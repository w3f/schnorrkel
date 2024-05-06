use curve25519_dalek::{RistrettoPoint, Scalar};
use merlin::Transcript;
use getrandom_or_panic::RngCore;
use zeroize::ZeroizeOnDrop;

use crate::{context::SigningTranscript, olaf::GENERATOR};

/// A scalar that is a signing nonce.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct Nonce(pub(super) Scalar);

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
    pub fn new(secret: &Scalar) -> Self {
        let mut rng = crate::getrandom_or_panic();

        let mut random_bytes = [0; 32];
        rng.fill_bytes(&mut random_bytes[..]);

        Self::nonce_generate_from_random_bytes(secret, &random_bytes[..])
    }

    /// Generates a nonce from the given random bytes.
    /// This function allows testing and MUST NOT be made public.
    pub(crate) fn nonce_generate_from_random_bytes(secret: &Scalar, random_bytes: &[u8]) -> Self {
        let mut transcript = Transcript::new(b"nonce_generate_from_random_bytes");

        transcript.append_message(b"random bytes", random_bytes);
        transcript.append_message(b"secret", secret.as_bytes());

        Self(transcript.challenge_scalar(b"nonce"))
    }
}

/// A group element that is a commitment to a signing nonce share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NonceCommitment(pub(super) RistrettoPoint);

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
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct SigningNonces {
    /// The hiding [`Nonce`].
    pub(crate) hiding: Nonce,
    /// The binding [`Nonce`].
    pub(crate) binding: Nonce,
    /// The commitments to the nonces. This is precomputed to improve
    /// sign() performance, since it needs to check if the commitments
    /// to the participant's nonces are included in the commitments sent
    /// by the Coordinator, and this prevents having to recompute them.
    #[zeroize(skip)]
    pub(crate) commitments: SigningCommitments,
}

impl SigningNonces {
    /// Generates a new signing nonce.
    ///
    /// Each participant generates signing nonces before performing a signing
    /// operation.
    pub fn new(secret: &Scalar) -> Self {
        let hiding = Nonce::new(secret);
        let binding = Nonce::new(secret);

        Self::from_nonces(hiding, binding)
    }

    /// Generates a new [`SigningNonces`] from a pair of [`Nonce`].
    ///
    /// # Security
    ///
    /// SigningNonces MUST NOT be repeated in different FROST signings.
    /// Thus, if you're using this method (because e.g. you're writing it
    /// to disk between rounds), be careful so that does not happen.
    pub fn from_nonces(hiding: Nonce, binding: Nonce) -> Self {
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
    pub(crate) hiding: NonceCommitment,
    /// Commitment to the binding [`Nonce`].
    pub(crate) binding: NonceCommitment,
}

impl SigningCommitments {
    /// Create new SigningCommitments
    pub fn new(hiding: NonceCommitment, binding: NonceCommitment) -> Self {
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
