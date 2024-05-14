//! Internal types of the FROST protocol.

use alloc::vec::Vec;
use curve25519_dalek::{
    traits::{Identity, VartimeMultiscalarMul},
    RistrettoPoint, Scalar,
};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;
use crate::{
    context::SigningTranscript,
    olaf::{GroupPublicKey, GENERATOR},
    SecretKey,
};
use super::errors::FROSTError;

/// A participant's signature share, which the coordinator will aggregate with all other signer's
/// shares into the joint signature.
pub struct SignatureShare {
    /// This participant's signature over the message.
    pub(super) share: Scalar,
}

/// The binding factor, also known as _rho_ (ρ), ensures each signature share is strongly bound to a signing set, specific set
/// of commitments, and a specific message.
pub(super) struct BindingFactor(pub(super) Scalar);

/// A list of binding factors and their associated identifiers.
pub(super) struct BindingFactorList(pub(super) Vec<(u16, BindingFactor)>);

impl BindingFactorList {
    /// Create a new [`BindingFactorList`] from a map of identifiers to binding factors.
    pub(super) fn new(binding_factors: Vec<(u16, BindingFactor)>) -> Self {
        Self(binding_factors)
    }

    pub(super) fn compute(
        signing_commitments: &[SigningCommitments],
        verifying_key: &GroupPublicKey,
        message: &[u8],
    ) -> BindingFactorList {
        let mut transcripts = BindingFactorList::binding_factor_transcripts(
            signing_commitments,
            verifying_key,
            message,
        );

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

    fn binding_factor_transcripts(
        signing_commitments: &[SigningCommitments],
        verifying_key: &GroupPublicKey,
        message: &[u8],
    ) -> Vec<(u16, Transcript)> {
        let mut transcript = Transcript::new(b"binding_factor");

        transcript.commit_point(b"verifying_key", verifying_key.0.as_compressed());

        transcript.append_message(b"message", message);

        transcript.append_message(
            b"group_commitment",
            BindingFactorList::encode_group_commitments(signing_commitments)
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

    fn encode_group_commitments(signing_commitments: &[SigningCommitments]) -> Transcript {
        let mut transcript = Transcript::new(b"encode_group_commitments");

        for item in signing_commitments {
            transcript.commit_point(b"hiding", &item.hiding.0.compress());
            transcript.commit_point(b"binding", &item.binding.0.compress());
        }

        transcript
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
    pub(super) hiding: NonceCommitment,
    pub(super) binding: NonceCommitment,
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

/// The product of all signers' individual commitments, published as part of the
/// final signature.
pub(super) struct GroupCommitment(pub(super) RistrettoPoint);

impl GroupCommitment {
    pub(super) fn compute(
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
}
