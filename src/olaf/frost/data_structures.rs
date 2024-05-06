use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use curve25519_dalek::{RistrettoPoint, Scalar};
use merlin::Transcript;
use getrandom_or_panic::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;
use crate::{
    context::SigningTranscript,
    olaf::{polynomials::PolynomialCommitment, sum_commitments, GENERATOR},
    PublicKey, SecretKey,
};

use super::{errors::FROSTError, Identifier, VerifyingKey, VerifyingShare};

/// A scalar that is a signing nonce.
#[derive(Clone, ZeroizeOnDrop)]
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
    pub fn new<R: CryptoRng + RngCore>(secret: &Scalar, rng: &mut R) -> Self {
        let mut random_bytes = [0; 32];
        rng.fill_bytes(&mut random_bytes[..]);

        Self::nonce_generate_from_random_bytes(secret, &random_bytes[..])
    }

    /// Generates a nonce from the given random bytes.
    /// This function allows testing and MUST NOT be made public.
    pub(super) fn nonce_generate_from_random_bytes(secret: &Scalar, random_bytes: &[u8]) -> Self {
        let mut transcript = Transcript::new(b"nonce_generate_from_random_bytes");

        transcript.append_message(b"random bytes", random_bytes);
        transcript.append_message(b"secret", secret.as_bytes());

        Self(transcript.challenge_scalar(b"nonce"))
    }
}

/// A group element that is a commitment to a signing nonce share.
#[derive(Copy, Clone, PartialEq, Eq)]
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
#[derive(Clone, ZeroizeOnDrop)]
pub(super) struct SigningNonces {
    /// The hiding [`Nonce`].
    pub(super) hiding: Nonce,
    /// The binding [`Nonce`].
    pub(super) binding: Nonce,
    /// The commitments to the nonces. This is precomputed to improve
    /// sign() performance, since it needs to check if the commitments
    /// to the participant's nonces are included in the commitments sent
    /// by the Coordinator, and this prevents having to recompute them.
    #[zeroize(skip)]
    pub(super) commitments: SigningCommitments,
}

impl SigningNonces {
    /// Generates a new signing nonce.
    ///
    /// Each participant generates signing nonces before performing a signing
    /// operation.
    pub(super) fn new<R: CryptoRng + RngCore>(secret: &Scalar, rng: &mut R) -> Self {
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
#[derive(Copy, Clone, PartialEq, Eq)]
pub(super) struct SigningCommitments {
    /// Commitment to the hiding [`Nonce`].
    pub(super) hiding: NonceCommitment,
    /// Commitment to the binding [`Nonce`].
    pub(super) binding: NonceCommitment,
}

impl SigningCommitments {
    /// Create new SigningCommitments
    pub(super) fn new(hiding: NonceCommitment, binding: NonceCommitment) -> Self {
        Self { hiding, binding }
    }

    /// Computes the [signature commitment share] from these round one signing commitments.
    ///
    /// [signature commitment share]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-signature-share-verificatio
    #[cfg(feature = "cheater-detection")]
    pub(super) fn to_group_commitment_share(
        self,
        binding_factor: &BindingFactor,
    ) -> GroupCommitmentShare {
        GroupCommitmentShare(self.hiding.0 + (self.binding.0 * binding_factor.0))
    }
}

impl From<&SigningNonces> for SigningCommitments {
    fn from(nonces: &SigningNonces) -> Self {
        nonces.commitments
    }
}

/// Generated by the coordinator of the signing operation and distributed to
/// each signing party.
#[derive(Clone)]
pub(super) struct SigningPackage {
    /// The set of commitments participants published in the first round of the
    /// protocol.
    pub(super) signing_commitments: BTreeMap<Identifier, SigningCommitments>,
    /// Message which each participant will sign.
    ///
    /// Each signer should perform protocol-specific verification on the
    /// message.
    pub(super) message: Vec<u8>,
}

impl SigningPackage {
    /// Create a new `SigningPackage`.
    ///
    /// The `signing_commitments` are sorted by participant `identifier`.
    pub(super) fn new(
        signing_commitments: BTreeMap<Identifier, SigningCommitments>,
        message: &[u8],
    ) -> SigningPackage {
        SigningPackage { signing_commitments, message: message.to_vec() }
    }

    /// Get a signing commitment by its participant identifier, or None if not found.
    pub(super) fn signing_commitment(&self, identifier: &Identifier) -> Option<SigningCommitments> {
        self.signing_commitments.get(identifier).copied()
    }

    /// Compute the transcripts to compute the per-signer binding factors.
    pub(super) fn binding_factor_transcripts(
        &self,
        verifying_key: &VerifyingKey,
    ) -> Vec<(Identifier, Transcript)> {
        let mut transcript = Transcript::new(b"binding_factor");

        transcript.commit_point(b"verifying_key", verifying_key.as_compressed());

        transcript.append_message(b"message", &self.message);

        transcript.append_message(
            b"group_commitment",
            encode_group_commitments(&self.signing_commitments)
                .challenge_scalar(b"encode_group_commitments")
                .as_bytes(),
        );

        self.signing_commitments
            .keys()
            .map(|identifier| {
                transcript.append_message(b"identifier", identifier.0.as_bytes());
                (*identifier, transcript.clone())
            })
            .collect()
    }
}

/// A participant's signature share, which the coordinator will aggregate with all other signer's
/// shares into the joint signature.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct SignatureShare {
    /// This participant's signature over the message.
    pub(super) share: Scalar,
}

impl SignatureShare {
    /// Tests if a signature share issued by a participant is valid before
    /// aggregating it into a final joint signature to publish.
    ///
    /// This is the final step of [`verify_signature_share`] from the spec.
    ///
    /// [`verify_signature_share`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-signature-share-verificatio
    #[cfg(feature = "cheater-detection")]
    pub(crate) fn verify(
        &self,
        identifier: Identifier,
        group_commitment_share: &round1::GroupCommitmentShare,
        verifying_share: &VerifyingShare,
        lambda_i: Scalar,
        challenge: &Challenge,
    ) -> Result<(), FROSTError> {
        if (GENERATOR * self.share)
            != (group_commitment_share.0 + (verifying_share * challenge * lambda_i))
        {
            return Err(FROSTError::InvalidSignatureShare { culprit: identifier });
        }

        Ok(())
    }
}

/// A FROST keypair, which is generated by the SimplPedPoP protocol.
#[derive(Clone, ZeroizeOnDrop)]
pub(super) struct KeyPackage {
    /// Denotes the participant identifier each secret share key package is owned by.
    #[zeroize(skip)]
    pub(super) identifier: Identifier,
    /// This participant's signing share. This is secret.
    pub(super) signing_share: SecretKey,
    /// This participant's public key.
    #[zeroize(skip)]
    pub(super) verifying_share: PublicKey,
    /// The public key that represents the entire group.
    #[zeroize(skip)]
    pub(super) verifying_key: PublicKey,
    pub(super) min_signers: u16,
}

impl KeyPackage {
    /// Create a new [`KeyPackage`] instance.
    pub(super) fn new(
        identifier: Identifier,
        signing_share: SecretKey,
        verifying_share: VerifyingKey,
        verifying_key: PublicKey,
        min_signers: u16,
    ) -> Self {
        Self { identifier, signing_share, verifying_share, verifying_key, min_signers }
    }
}

/// A list of binding factors and their associated identifiers.
#[derive(Clone)]
pub(super) struct BindingFactorList(BTreeMap<Identifier, BindingFactor>);

impl BindingFactorList {
    /// Create a new [`BindingFactorList`] from a map of identifiers to binding factors.
    pub fn new(binding_factors: BTreeMap<Identifier, BindingFactor>) -> Self {
        Self(binding_factors)
    }

    /// Get the [`BindingFactor`] for the given identifier, or None if not found.
    pub fn get(&self, key: &Identifier) -> Option<&BindingFactor> {
        self.0.get(key)
    }

    /// [`compute_binding_factors`] in the spec
    ///
    /// [`compute_binding_factors`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-4.4.
    pub(super) fn compute_binding_factor_list(
        signing_package: &SigningPackage,
        verifying_key: &VerifyingKey,
    ) -> BindingFactorList {
        let mut transcripts = signing_package.binding_factor_transcripts(verifying_key);

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
}

/// The binding factor, also known as _rho_ (ρ), ensures each signature share is strongly bound to a signing set, specific set
/// of commitments, and a specific message.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct BindingFactor(pub(super) Scalar);

/// One signer's share of the group commitment, derived from their individual signing commitments
/// and the binding factor _rho_.
#[derive(Clone, Copy, PartialEq)]
pub struct GroupCommitmentShare(pub(super) RistrettoPoint);

/// Encode the list of group signing commitments.
///
/// Implements [`encode_group_commitment_list()`] from the spec.
///
/// `signing_commitments` must contain the sorted map of participants
/// identifiers to the signing commitments they issued.
///
/// Returns a byte string containing the serialized representation of the
/// commitment list.
///
/// [`encode_group_commitment_list()`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-list-operations
pub(super) fn encode_group_commitments(
    signing_commitments: &BTreeMap<Identifier, SigningCommitments>,
) -> Transcript {
    //let mut bytes = vec![];
    let mut transcript = Transcript::new(b"encode_group_commitments");

    for (item_identifier, item) in signing_commitments {
        transcript.append_message(b"identifier", item_identifier.0.as_bytes());
        transcript.commit_point(b"hiding", &item.hiding.0.compress());
        transcript.commit_point(b"binding", &item.binding.0.compress());
    }

    transcript
}

/// Public data that contains all the signers' verifying shares as well as the
/// group verifying key.
///
/// Used for verification purposes before publishing a signature.
#[derive(Clone, Debug)]
pub struct PublicKeyPackage {
    /// The verifying shares for all participants. Used to validate signature
    /// shares they generate.
    pub(super) verifying_shares: BTreeMap<Identifier, VerifyingShare>,
    /// The joint public key for the entire group.
    pub(super) verifying_key: VerifyingKey,
}

impl PublicKeyPackage {
    /// Create a new [`PublicKeyPackage`] instance.
    pub(super) fn new(
        verifying_shares: BTreeMap<Identifier, VerifyingShare>,
        verifying_key: VerifyingKey,
    ) -> Self {
        Self { verifying_shares, verifying_key }
    }

    /// Computes the public key package given a list of participant identifiers
    /// and a [`VerifiableSecretSharingCommitment`]. This is useful in scenarios
    /// where the commitments are published somewhere and it's desirable to
    /// recreate the public key package from them.
    pub(super) fn from_commitment(
        identifiers: &BTreeSet<Identifier>,
        commitment: &mut PolynomialCommitment,
    ) -> Result<PublicKeyPackage, FROSTError> {
        let verifying_keys: BTreeMap<_, _> = identifiers
            .iter()
            .map(|id| (*id, PublicKey::from_point(commitment.evaluate(&id.0))))
            .collect();

        Ok(PublicKeyPackage::new(
            verifying_keys,
            VerifyingKey::from_point(*commitment.coefficients_commitments.first().unwrap()),
        ))
    }

    /// Computes the public key package given a map of participant identifiers
    /// and their [`VerifiableSecretSharingCommitment`] from a distributed key
    /// generation process. This is useful in scenarios where the commitments
    /// are published somewhere and it's desirable to recreate the public key
    /// package from them.
    pub(super) fn from_dkg_commitments(
        commitments: &BTreeMap<Identifier, PolynomialCommitment>,
    ) -> Result<PublicKeyPackage, FROSTError> {
        let identifiers: BTreeSet<_> = commitments.keys().copied().collect();
        let commitments: Vec<&PolynomialCommitment> = commitments.values().collect();
        let mut group_commitment =
            PolynomialCommitment::sum_polynomial_commitments(&commitments[..]);
        Self::from_commitment(&identifiers, &mut group_commitment)
    }
}
