//! Internal types of the FROST protocol.

use alloc::{collections::BTreeSet, vec::Vec};
use curve25519_dalek::{
    traits::{Identity, VartimeMultiscalarMul},
    RistrettoPoint, Scalar,
};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;
use crate::{
    context::{SigningContext, SigningTranscript},
    olaf::{GroupPublicKey, Identifier, GENERATOR},
    SecretKey,
};
use super::errors::FROSTError;

/// A participant's signature share, which the coordinator will aggregate with all other signer's
/// shares into the joint signature.
pub struct SignatureShare {
    /// This participant's signature over the message.
    pub(super) share: Scalar,
}

pub(super) type Challenge = Scalar;

/// Generates the challenge as is required for Schnorr signatures.
pub(super) fn challenge(
    R: &RistrettoPoint,
    verifying_key: &GroupPublicKey,
    context: &[u8],
    msg: &[u8],
) -> Challenge {
    let mut transcript = SigningContext::new(context).bytes(msg);

    transcript.proto_name(b"Schnorr-sig");
    transcript.commit_point(b"sign:pk", verifying_key.0.as_compressed());
    transcript.commit_point(b"sign:R", &R.compress());
    transcript.challenge_scalar(b"sign:c")
}

/// The binding factor, also known as _rho_ (ρ), ensures each signature share is strongly bound to a signing set, specific set
/// of commitments, and a specific message.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct BindingFactor(pub(super) Scalar);

/// A list of binding factors and their associated identifiers.
#[derive(Clone, Debug)]
//pub(super) struct BindingFactorList(pub(super) Vec<BindingFactor>);
pub(super) struct BindingFactorList(pub(super) Vec<(u16, BindingFactor)>);

impl BindingFactorList {
    /// Create a new [`BindingFactorList`] from a map of identifiers to binding factors.
    pub(super) fn new(binding_factors: Vec<(u16, BindingFactor)>) -> Self {
        Self(binding_factors)
    }
}

/// A scalar that is a signing nonce.
#[derive(ZeroizeOnDrop)]
pub(super) struct Nonce(pub(super) Scalar);

impl Nonce {
    /// Generates a new uniformly random signing nonce by sourcing fresh randomness and combining
    /// with the secret signing share, to hedge against a bad RNG.
    ///
    /// Each participant generates signing nonces before performing a signing
    /// operation.
    ///
    /// An implementation of `nonce_generate(secret)` from the [spec].
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-nonce-generation
    pub(super) fn new<R>(secret: &SecretKey, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let mut random_bytes = [0; 32];
        rng.fill_bytes(&mut random_bytes[..]);

        Self::nonce_generate_from_random_bytes(secret, &random_bytes[..])
    }

    /// Generates a nonce from the given random bytes.
    /// This function allows testing and MUST NOT be made public.
    pub(super) fn nonce_generate_from_random_bytes(
        secret: &SecretKey,
        random_bytes: &[u8],
    ) -> Self {
        let mut transcript = Transcript::new(b"nonce_generate_from_random_bytes");

        transcript.append_message(b"random bytes", random_bytes);
        transcript.append_message(b"secret", secret.key.as_bytes());

        Self(transcript.challenge_scalar(b"nonce"))
    }
}

/// A group element that is a commitment to a signing nonce share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NonceCommitment(pub(super) RistrettoPoint);

impl From<Nonce> for NonceCommitment {
    fn from(nonce: Nonce) -> Self {
        From::from(&nonce)
    }
}

impl From<&Nonce> for NonceCommitment {
    fn from(nonce: &Nonce) -> Self {
        Self(GENERATOR * nonce.0)
    }
}

/// Comprised of hiding and binding nonces.
///
/// Note that [`SigningNonces`] must be used *only once* for a signing
/// operation; re-using nonces will result in leakage of a signer's long-lived
/// signing key.
#[derive(ZeroizeOnDrop)]
pub struct SigningNonces {
    pub(super) hiding: Nonce,
    pub(super) binding: Nonce,
    // The commitments to the nonces. This is precomputed to improve
    // sign() performance, since it needs to check if the commitments
    // to the participant's nonces are included in the commitments sent
    // by the Coordinator, and this prevents having to recompute them.
    #[zeroize(skip)]
    pub(super) commitments: SigningCommitments,
}

impl SigningNonces {
    /// Generates a new signing nonce.
    ///
    /// Each participant generates signing nonces before performing a signing
    /// operation.
    pub(super) fn new<R>(secret: &SecretKey, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let hiding = Nonce::new(secret, rng);
        let binding = Nonce::new(secret, rng);

        Self::from_nonces(hiding, binding)
    }

    /// Generates a new [`SigningNonces`] from a pair of [`Nonce`].
    ///
    /// # Security
    ///
    /// SigningNonces MUST NOT be repeated in different FROST signings.
    /// Thus, if you're using this method (because e.g. you're writing it
    /// to disk between rounds), be careful so that does not happen.
    pub(super) fn from_nonces(hiding: Nonce, binding: Nonce) -> Self {
        let hiding_commitment = (&hiding).into();
        let binding_commitment = (&binding).into();
        let commitments = SigningCommitments::new(hiding_commitment, binding_commitment);

        Self { hiding, binding, commitments }
    }
}

/// Published by each participant in the first round of the signing protocol.
///
/// This step can be batched if desired by the implementation. Each
/// SigningCommitment can be used for exactly *one* signature.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SigningCommitments {
    /// Commitment to the hiding [`Nonce`].
    pub(super) hiding: NonceCommitment,
    /// Commitment to the binding [`Nonce`].
    pub(super) binding: NonceCommitment,
    //pub(super) identifier: Identifier,
}

impl SigningCommitments {
    /// Create new SigningCommitments
    pub(super) fn new(hiding: NonceCommitment, binding: NonceCommitment) -> Self {
        Self { hiding, binding }
    }
}

impl From<&SigningNonces> for SigningCommitments {
    fn from(nonces: &SigningNonces) -> Self {
        nonces.commitments
    }
}

/// One signer's share of the group commitment, derived from their individual signing commitments
/// and the binding factor _rho_.
#[derive(Clone, Copy, PartialEq)]
pub(super) struct GroupCommitmentShare(pub(super) RistrettoPoint);

/// The product of all signers' individual commitments, published as part of the
/// final signature.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct GroupCommitment(pub(super) RistrettoPoint);

pub(super) fn compute_group_commitment(
    signing_commitments: &[SigningCommitments],
    binding_factor_list: &BindingFactorList,
) -> Result<GroupCommitment, FROSTError> {
    let identity = RistrettoPoint::identity();

    let mut group_commitment = RistrettoPoint::identity();

    // Number of signing participants we are iterating over.
    let signers = signing_commitments.len();

    let mut binding_scalars = Vec::with_capacity(signers);

    let mut binding_elements = Vec::with_capacity(signers);

    for (i, commitment) in signing_commitments.iter().enumerate() {
        // The following check prevents a party from accidentally revealing their share.
        // Note that the '&&' operator would be sufficient.
        if identity == commitment.binding.0 || identity == commitment.hiding.0 {
            return Err(FROSTError::IdentitySigningCommitment);
        }

        let binding_factor = &binding_factor_list.0[i];

        // Collect the binding commitments and their binding factors for one big
        // multiscalar multiplication at the end.
        binding_elements.push(commitment.binding.0);
        binding_scalars.push(binding_factor.1 .0);

        group_commitment += commitment.hiding.0;
    }

    let accumulated_binding_commitment: RistrettoPoint =
        RistrettoPoint::vartime_multiscalar_mul(binding_scalars, binding_elements);

    group_commitment += accumulated_binding_commitment;

    Ok(GroupCommitment(group_commitment))
}

pub(super) fn compute_binding_factor_list(
    signing_commitments: &[SigningCommitments],
    verifying_key: &GroupPublicKey,
    message: &[u8],
) -> BindingFactorList {
    let mut transcripts = binding_factor_transcripts(signing_commitments, verifying_key, message);

    BindingFactorList::new(
        transcripts
            .iter_mut()
            .map(|(identifier, transcript)| {
                let binding_factor = transcript.challenge_scalar(b"binding factor");

                (*identifier, BindingFactor(binding_factor))
            })
            .collect(),
    )
}

pub(super) fn derive_interpolating_value(
    signer_id: &Identifier,
    identifiers: BTreeSet<Identifier>,
) -> Result<Scalar, FROSTError> {
    compute_lagrange_coefficient(&identifiers, None, *signer_id)
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
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;

    for x_j in x_set.iter() {
        if x_i == *x_j {
            continue;
        }

        if let Some(x) = x {
            num *= x.0 - x_j.0;
            den *= x_i.0 - x_j.0;
        } else {
            // Both signs inverted just to avoid requiring Neg (-*xj)
            num *= x_j.0;
            den *= x_j.0 - x_i.0;
        }
    }

    //if !x_i_found {
    //return Err(FROSTError::UnknownIdentifier);
    //}

    let inverse = num * den.invert();

    Ok(inverse)
}

pub(super) fn binding_factor_transcripts(
    signing_commitments: &[SigningCommitments],
    verifying_key: &GroupPublicKey,
    message: &[u8],
) -> Vec<(u16, Transcript)> {
    let mut transcript = Transcript::new(b"binding_factor");

    transcript.commit_point(b"verifying_key", verifying_key.0.as_compressed());

    transcript.append_message(b"message", message);

    transcript.append_message(
        b"group_commitment",
        encode_group_commitments(signing_commitments)
            .challenge_scalar(b"encode_group_commitments")
            .as_bytes(),
    );

    signing_commitments
        .iter()
        .enumerate()
        .map(|(i, _)| {
            transcript.append_message(b"identifier", &i.to_le_bytes());
            (i as u16, transcript.clone())
        })
        .collect()
}

pub(super) fn encode_group_commitments(signing_commitments: &[SigningCommitments]) -> Transcript {
    let mut transcript = Transcript::new(b"encode_group_commitments");

    for item in signing_commitments {
        //transcript.append_message(b"identifier", item.identifier.0.as_bytes());
        transcript.commit_point(b"hiding", &item.hiding.0.compress());
        transcript.commit_point(b"binding", &item.binding.0.compress());
    }

    transcript
}
