//! Implementation of the FROST protocol (<https://eprint.iacr.org/2020/852>).

pub mod errors;
mod data_structures;
mod utils;

use alloc::vec::Vec;
use crate::{Keypair, PublicKey};
use self::{
    data_structures::{
        BindingFactor, BindingFactorList, KeyPackage, SignatureShare, SigningCommitments,
        SigningNonces, SigningPackage,
    },
    errors::FROSTError,
    utils::{
        challenge, compute_group_commitment, compute_signature_share, derive_interpolating_value,
    },
};

pub(super) type VerifyingKey = PublicKey;
pub(super) type Identifier = u16;

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
