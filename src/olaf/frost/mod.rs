//! Implementation of the FROST protocol (<https://eprint.iacr.org/2020/852>).

pub mod errors;
mod data_structures;
mod utils;
mod tests;

use alloc::{collections::BTreeMap, vec::Vec};
use curve25519_dalek::{traits::Identity, RistrettoPoint, Scalar};
use crate::{Keypair, PublicKey, Signature};
use self::{
    data_structures::{
        BindingFactor, BindingFactorList, KeyPackage, PublicKeyPackage, SignatureShare,
        SigningCommitments, SigningNonces, SigningPackage,
    },
    errors::FROSTError,
    utils::{
        challenge, compute_group_commitment, compute_signature_share, derive_interpolating_value,
    },
};

use super::{Identifier, GENERATOR};

pub(super) type VerifyingShare = PublicKey;
pub(super) type VerifyingKey = PublicKey;

impl Keypair {
    /// Done once by each participant, to generate _their_ nonces and commitments
    /// that are then used during signing.
    ///
    /// This is only needed if pre-processing is needed (for 1-round FROST). For
    /// regular 2-round FROST, use [`commit`].
    ///
    /// When performing signing using two rounds, num_nonces would equal 1, to
    /// perform the first round. Batching entails generating more than one
    /// nonce/commitment pair at a time.  Nonces should be stored in secret storage
    /// for later use, whereas the commitments are published.
    pub fn preprocess(&self, num_nonces: u8) -> (Vec<SigningNonces>, Vec<SigningCommitments>) {
        let mut rng = crate::getrandom_or_panic();

        let mut signing_nonces: Vec<SigningNonces> = Vec::with_capacity(num_nonces as usize);

        let mut signing_commitments: Vec<SigningCommitments> =
            Vec::with_capacity(num_nonces as usize);

        for _ in 0..num_nonces {
            let nonces = SigningNonces::new(&self.secret.key, &mut rng);
            signing_commitments.push(SigningCommitments::from(&nonces));
            signing_nonces.push(nonces);
        }

        (signing_nonces, signing_commitments)
    }

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Implements [`commit`] from the spec.
    ///
    /// Generates the signing nonces and commitments to be used in the signing
    /// operation.
    ///
    /// [`commit`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-round-one-commitment.
    pub fn commit(&self) -> (SigningNonces, SigningCommitments) {
        let (mut vec_signing_nonces, mut vec_signing_commitments) = self.preprocess(1);
        (
            vec_signing_nonces.pop().expect("must have 1 element"),
            vec_signing_commitments.pop().expect("must have 1 element"),
        )
    }

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Implements [`sign`] from the spec.
    ///
    /// Receives the message to be signed and a set of signing commitments and a set
    /// of randomizing commitments to be used in that signing operation, including
    /// that for this participant.
    ///
    /// Assumes the participant has already determined which nonce corresponds with
    /// the commitment that was assigned by the coordinator in the SigningPackage.
    ///
    /// [`sign`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-round-two-signature-share-g
    pub fn sign_frost(
        &self,
        signing_package: &SigningPackage,
        signer_nonces: &SigningNonces,
        verifying_key: VerifyingKey,
        identifier: Identifier,
        min_signers: u16,
    ) -> Result<SignatureShare, FROSTError> {
        let key_package = KeyPackage::new(
            identifier,
            self.secret.clone(),
            self.public,
            verifying_key,
            min_signers,
        );

        if signing_package.signing_commitments.len() < key_package.min_signers as usize {
            return Err(FROSTError::IncorrectNumberOfSigningCommitments);
        }

        // Validate the signer's commitment is present in the signing package
        let commitment = signing_package
            .signing_commitments
            .get(&key_package.identifier)
            .ok_or(FROSTError::MissingSigningCommitment)?;

        // Validate if the signer's commitment exists
        if &signer_nonces.commitments != commitment {
            return Err(FROSTError::IncorrectSigningCommitment);
        }

        // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
        // binding factor.
        let binding_factor_list: BindingFactorList = BindingFactorList::compute_binding_factor_list(
            signing_package,
            &key_package.verifying_key,
        );

        let binding_factor: BindingFactor = binding_factor_list
            .get(&key_package.identifier)
            .ok_or(FROSTError::UnknownIdentifier)?
            .clone();

        // Compute the group commitment from signing commitments produced in round one.
        let group_commitment = compute_group_commitment(signing_package, &binding_factor_list)?;

        // Compute Lagrange coefficient.
        let lambda_i = derive_interpolating_value(&key_package.identifier, signing_package)?;

        // Compute the per-message challenge.
        let challenge = challenge(
            &group_commitment.0,
            &key_package.verifying_key,
            signing_package.message.as_slice(),
        );

        // Compute the Schnorr signature share.
        let signature_share = compute_signature_share(
            signer_nonces,
            binding_factor,
            lambda_i,
            &key_package,
            challenge,
        );

        Ok(signature_share)
    }
}

/// Aggregates the signature shares to produce a final signature that
/// can be verified with the group public key.
///
/// `signature_shares` maps the identifier of each participant to the
/// [`round2::SignatureShare`] they sent. These identifiers must come from whatever mapping
/// the coordinator has between communication channels and participants, i.e.
/// they must have assurance that the [`round2::SignatureShare`] came from
/// the participant with that identifier.
///
/// This operation is performed by a coordinator that can communicate with all
/// the signing participants before publishing the final signature. The
/// coordinator can be one of the participants or a semi-trusted third party
/// (who is trusted to not perform denial of service attacks, but does not learn
/// any secret information). Note that because the coordinator is trusted to
/// report misbehaving parties in order to avoid publishing an invalid
/// signature, if the coordinator themselves is a signer and misbehaves, they
/// can avoid that step. However, at worst, this results in a denial of
/// service attack due to publishing an invalid signature.
pub fn aggregate(
    signing_package: &SigningPackage,
    signature_shares: &BTreeMap<Identifier, SignatureShare>,
    pubkeys: &PublicKeyPackage,
) -> Result<Signature, FROSTError> {
    // Check if signing_package.signing_commitments and signature_shares have
    // the same set of identifiers, and if they are all in pubkeys.verifying_shares.
    if signing_package.signing_commitments.len() != signature_shares.len() {
        return Err(FROSTError::UnknownIdentifier);
    }

    if !signing_package.signing_commitments.keys().all(|id| {
        #[cfg(feature = "cheater-detection")]
        return signature_shares.contains_key(id) && pubkeys.verifying_shares().contains_key(id);
        #[cfg(not(feature = "cheater-detection"))]
        return signature_shares.contains_key(id);
    }) {
        return Err(FROSTError::UnknownIdentifier);
    }

    // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
    // binding factor.
    let binding_factor_list: BindingFactorList =
        BindingFactorList::compute_binding_factor_list(signing_package, &pubkeys.verifying_key);

    // Compute the group commitment from signing commitments produced in round one.
    let group_commitment = compute_group_commitment(signing_package, &binding_factor_list)?;

    // The aggregation of the signature shares by summing them up, resulting in
    // a plain Schnorr signature.
    //
    // Implements [`aggregate`] from the spec.
    //
    // [`aggregate`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-5.3
    let mut s = Scalar::ZERO;

    for signature_share in signature_shares.values() {
        s += signature_share.share;
    }

    let signature = Signature { R: group_commitment.0.compress(), s };

    // Verify the aggregate signature
    let verification_result =
        verify_signature(&signing_package.message, &signature, &pubkeys.verifying_key);

    // Only if the verification of the aggregate signature failed; verify each share to find the cheater.
    // This approach is more efficient since we don't need to verify all shares
    // if the aggregate signature is valid (which should be the common case).
    #[cfg(feature = "cheater-detection")]
    if let Err(err) = verification_result {
        // Compute the per-message challenge.
        let challenge = challenge(
            &group_commitment.0,
            pubkeys.verifying_key(),
            signing_package.message().as_slice(),
        );

        // Verify the signature shares.
        for (signature_share_identifier, signature_share) in signature_shares {
            // Look up the public key for this signer, where `signer_pubkey` = _G.ScalarBaseMult(s[i])_,
            // and where s[i] is a secret share of the constant term of _f_, the secret polynomial.
            let signer_pubkey = pubkeys
                .verifying_shares
                .get(signature_share_identifier)
                .ok_or(FROSTError::UnknownIdentifier)?;

            // Compute Lagrange coefficient.
            let lambda_i = derive_interpolating_value(signature_share_identifier, signing_package)?;

            let binding_factor = binding_factor_list
                .get(signature_share_identifier)
                .ok_or(FROSTError::UnknownIdentifier)?;

            // Compute the commitment share.
            let R_share = signing_package
                .signing_commitment(signature_share_identifier)
                .ok_or(FROSTError::UnknownIdentifier)?
                .to_group_commitment_share(binding_factor);

            // Compute relation values to verify this signature share.
            signature_share.verify(
                *signature_share_identifier,
                &R_share,
                signer_pubkey,
                lambda_i,
                &challenge,
            )?;
        }

        // We should never reach here; but we return the verification error to be safe.
        return Err(err);
    }

    #[cfg(not(feature = "cheater-detection"))]
    verification_result?;

    Ok(signature)
}

// TODO: Integrate this into Keypair
/// Verify a purported `signature` with a pre-hashed [`Challenge`] made by the group public key.
pub(super) fn verify_signature(
    msg: &[u8],
    signature: &Signature,
    public_key: &VerifyingKey,
) -> Result<(), FROSTError> {
    let challenge = challenge(&signature.R.decompress().unwrap(), public_key, msg);

    // Verify check is h * ( - z * B + R  + c * A) == 0
    //                 h * ( z * B - c * A - R) == 0
    let zB = GENERATOR * signature.s;
    let cA = public_key.as_point() * challenge;
    let check = zB - cA - signature.R.decompress().unwrap();

    if check == RistrettoPoint::identity() {
        Ok(())
    } else {
        Err(FROSTError::InvalidSignature)
    }
}
