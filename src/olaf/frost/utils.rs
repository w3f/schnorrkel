use alloc::{collections::BTreeSet, vec::Vec};
use curve25519_dalek::{
    traits::{Identity, VartimeMultiscalarMul},
    RistrettoPoint, Scalar,
};
use merlin::Transcript;

use crate::context::SigningTranscript;

use super::{
    data_structures::{
        BindingFactor, BindingFactorList, KeyPackage, SignatureShare, SigningNonces, SigningPackage,
    },
    errors::FROSTError,
    Identifier, VerifyingKey,
};

/// Compute the signature share for a signing operation.
pub(super) fn compute_signature_share(
    signer_nonces: &SigningNonces,
    binding_factor: BindingFactor,
    lambda_i: Scalar,
    key_package: &KeyPackage,
    challenge: Scalar,
) -> SignatureShare {
    let z_share: Scalar = signer_nonces.hiding.0
        + (signer_nonces.binding.0 * binding_factor.0)
        + (lambda_i * key_package.signing_share.key * challenge);

    SignatureShare { share: z_share }
}

/// Generates the group commitment which is published as part of the joint
/// Schnorr signature.
///
/// Implements [`compute_group_commitment`] from the spec.
///
/// [`compute_group_commitment`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-4.5.
pub(crate) fn compute_group_commitment(
    signing_package: &SigningPackage,
    binding_factor_list: &BindingFactorList,
) -> Result<GroupCommitment, FROSTError> {
    let identity = RistrettoPoint::identity();

    let mut group_commitment = RistrettoPoint::identity();

    // Number of signing participants we are iterating over.
    let signers = signing_package.signing_commitments.len();

    let mut binding_scalars = Vec::with_capacity(signers);

    let mut binding_elements = Vec::with_capacity(signers);

    for (commitment_identifier, commitment) in &signing_package.signing_commitments {
        // The following check prevents a party from accidentally revealing their share.
        // Note that the '&&' operator would be sufficient.
        if identity == commitment.binding.0 || identity == commitment.hiding.0 {
            return Err(FROSTError::IdentitySigningCommitment);
        }

        let binding_factor = binding_factor_list
            .get(&commitment_identifier)
            .ok_or(FROSTError::UnknownIdentifier)?;

        // Collect the binding commitments and their binding factors for one big
        // multiscalar multiplication at the end.
        binding_elements.push(commitment.binding.0);
        binding_scalars.push(binding_factor.0);

        group_commitment += commitment.hiding.0;
    }

    let accumulated_binding_commitment: RistrettoPoint =
        RistrettoPoint::vartime_multiscalar_mul(binding_scalars, binding_elements);

    group_commitment += accumulated_binding_commitment;

    Ok(GroupCommitment(group_commitment))
}

/// The product of all signers' individual commitments, published as part of the
/// final signature.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct GroupCommitment(pub(crate) RistrettoPoint);

/// Generates the lagrange coefficient for the i'th participant (for `signer_id`).
///
/// Implements [`derive_interpolating_value()`] from the spec.
///
/// [`derive_interpolating_value()`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-polynomials
pub(super) fn derive_interpolating_value(
    signer_id: &Identifier,
    signing_package: &SigningPackage,
) -> Result<Scalar, FROSTError> {
    compute_lagrange_coefficient(
        &signing_package.signing_commitments.keys().cloned().collect(),
        None,
        *signer_id,
    )
}

/// Generates a lagrange coefficient.
///
/// The Lagrange polynomial for a set of points (x_j, y_j) for 0 <= j <= k
/// is ∑_{i=0}^k y_i.ℓ_i(x), where ℓ_i(x) is the Lagrange basis polynomial:
///
/// ℓ_i(x) = ∏_{0≤j≤k; j≠i} (x - x_j) / (x_i - x_j).
///
/// This computes ℓ_j(x) for the set of points `xs` and for the j corresponding
/// to the given xj.
///
/// If `x` is None, it uses 0 for it (since Identifiers can't be 0).
pub(super) fn compute_lagrange_coefficient(
    x_set: &BTreeSet<Identifier>,
    x: Option<Identifier>,
    x_i: Identifier,
) -> Result<Scalar, FROSTError> {
    if x_set.is_empty() {
        return Err(FROSTError::IncorrectNumberOfIdentifiers);
    }
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;

    let mut x_i_found = false;

    for x_j in x_set.iter() {
        if x_i == *x_j {
            x_i_found = true;
            continue;
        }

        if let Some(x) = x {
            num *= Scalar::from(x) - Scalar::from(*x_j);
            den *= Scalar::from(x_i) - Scalar::from(*x_j);
        } else {
            // Both signs inverted just to avoid requiring Neg (-*xj)
            num *= Scalar::from(*x_j);
            den *= Scalar::from(*x_j) - Scalar::from(x_i);
        }
    }
    if !x_i_found {
        return Err(FROSTError::UnknownIdentifier);
    }

    let inverse = num * den.invert();

    if inverse == Scalar::ZERO {
        Err(FROSTError::DuplicatedIdentifier)
    } else {
        Ok(inverse)
    }
}

/// Generates the challenge as is required for Schnorr signatures.
pub(super) fn challenge(R: &RistrettoPoint, verifying_key: &VerifyingKey, msg: &[u8]) -> Scalar {
    let mut transcript = Transcript::new(b"challenge");

    transcript.commit_point(b"R", &R.compress());
    transcript.commit_point(b"verifying_key", verifying_key.as_compressed());
    transcript.append_message(b"message", msg);
    transcript.challenge_scalar(b"challenge")
}
