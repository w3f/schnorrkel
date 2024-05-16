//! Types of the FROST protocol.

use alloc::vec::Vec;
use curve25519_dalek::{
    ristretto::CompressedRistretto,
    traits::{Identity, VartimeMultiscalarMul},
    RistrettoPoint, Scalar,
};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;
use crate::{
    context::SigningTranscript,
    olaf::{
        simplpedpop::SPPOutputMessage, ThresholdPublicKey, VerifyingShare,
        COMPRESSED_RISTRETTO_LENGTH, GENERATOR, SCALAR_LENGTH,
    },
    scalar_from_canonical_bytes, SecretKey,
};
use super::errors::{FROSTError, FROSTResult};

/// A participant's signature share, which the coordinator will aggregate with all other signer's
/// shares into the joint signature.
#[derive(Clone)]
pub(super) struct SignatureShare {
    /// This participant's signature over the message.
    pub(super) share: Scalar,
}

impl SignatureShare {
    /// Serializes the `SignatureShare` into bytes.
    pub(super) fn to_bytes(&self) -> [u8; SCALAR_LENGTH] {
        self.share.to_bytes()
    }

    /// Deserializes the `SignatureShare` from bytes.
    pub(super) fn from_bytes(bytes: &[u8]) -> FROSTResult<SignatureShare> {
        let mut share_bytes = [0; SCALAR_LENGTH];
        share_bytes.copy_from_slice(&bytes[..SCALAR_LENGTH]);
        let share = scalar_from_canonical_bytes(share_bytes)
            .ok_or(FROSTError::SignatureShareDeserializationError)?;

        Ok(SignatureShare { share })
    }

    pub(super) fn verify(
        &self,
        group_commitment_share: &GroupCommitmentShare,
        verifying_share: &VerifyingShare,
        lambda_i: Scalar,
        challenge: &Scalar,
    ) -> FROSTResult<()> {
        if (GENERATOR * self.share)
            != (group_commitment_share.0 + (verifying_share.0.as_point() * challenge * lambda_i))
        {
            return Err(FROSTError::InvalidSignatureShare { culprit: *verifying_share });
        }

        Ok(())
    }
}

pub(super) struct GroupCommitmentShare(pub(super) RistrettoPoint);

/// The binding factor, also known as _rho_ (ρ), ensures each signature share is strongly bound to a signing set, specific set
/// of commitments, and a specific message.
#[derive(Clone)]
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
        verifying_key: &ThresholdPublicKey,
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
        verifying_key: &ThresholdPublicKey,
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
        let mut random_bytes = [0; SCALAR_LENGTH];
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

impl NonceCommitment {
    /// Serializes the `NonceCommitment` into bytes.
    pub(super) fn to_bytes(self) -> [u8; COMPRESSED_RISTRETTO_LENGTH] {
        self.0.compress().to_bytes()
    }

    /// Deserializes the `NonceCommitment` from bytes.
    pub(super) fn from_bytes(bytes: &[u8]) -> FROSTResult<NonceCommitment> {
        let compressed = CompressedRistretto::from_slice(&bytes[..COMPRESSED_RISTRETTO_LENGTH])
            .map_err(FROSTError::DeserializationError)?;

        let point = compressed.decompress().ok_or(FROSTError::InvalidNonceCommitment)?;

        Ok(NonceCommitment(point))
    }
}

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

    /// Serializes the `SigningCommitments` into bytes.
    pub(super) fn to_bytes(self) -> [u8; COMPRESSED_RISTRETTO_LENGTH * 2] {
        // TODO: Add tests
        let mut bytes = [0u8; COMPRESSED_RISTRETTO_LENGTH * 2];

        let hiding_bytes = self.hiding.to_bytes();
        let binding_bytes = self.binding.to_bytes();

        bytes[..COMPRESSED_RISTRETTO_LENGTH].copy_from_slice(&hiding_bytes);
        bytes[COMPRESSED_RISTRETTO_LENGTH..].copy_from_slice(&binding_bytes);

        bytes
    }

    /// Deserializes the `SigningCommitments` from bytes.
    pub(super) fn from_bytes(bytes: &[u8]) -> FROSTResult<SigningCommitments> {
        let hiding = NonceCommitment::from_bytes(&bytes[..COMPRESSED_RISTRETTO_LENGTH])?;
        let binding = NonceCommitment::from_bytes(&bytes[COMPRESSED_RISTRETTO_LENGTH..])?;

        Ok(SigningCommitments { hiding, binding })
    }

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

/// The signing package that each signer produces in the signing round of the FROST protocol and sends to the
/// coordinator, which aggregates them into the final threshold signature.
pub struct SigningPackage {
    pub(super) message: Vec<u8>,
    pub(super) context: Vec<u8>,
    pub(super) signing_commitments: Vec<SigningCommitments>,
    pub(super) signature_share: SignatureShare,
    pub(super) spp_output_message: SPPOutputMessage,
}

impl SigningPackage {
    /// Serializes SigningPackage into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend((self.message.len() as u32).to_le_bytes());
        bytes.extend(&self.message);

        bytes.extend((self.context.len() as u32).to_le_bytes());
        bytes.extend(&self.context);

        bytes.extend((self.signing_commitments.len() as u32).to_le_bytes());
        for commitment in &self.signing_commitments {
            bytes.extend(commitment.to_bytes());
        }

        bytes.extend(self.signature_share.to_bytes());

        bytes.extend(self.spp_output_message.to_bytes());

        bytes
    }

    /// Deserializes SigningPackage from bytes.
    pub fn from_bytes(bytes: &[u8]) -> FROSTResult<Self> {
        let mut cursor = 0;

        let message_len =
            u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        let message = bytes[cursor..cursor + message_len].to_vec();
        cursor += message_len;

        let context_len =
            u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        let context = bytes[cursor..cursor + context_len].to_vec();
        cursor += context_len;

        let signing_commitments_len =
            u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        let mut signing_commitments = Vec::with_capacity(signing_commitments_len);
        for _ in 0..signing_commitments_len {
            let commitment_bytes = &bytes[cursor..cursor + 64]; // Assuming each SigningCommitment is 64 bytes
            cursor += 64;
            signing_commitments.push(SigningCommitments::from_bytes(commitment_bytes)?);
        }

        let share_bytes = &bytes[cursor..cursor + SCALAR_LENGTH];
        cursor += SCALAR_LENGTH;
        let signature_share = SignatureShare::from_bytes(share_bytes)?;

        let spp_output_message = SPPOutputMessage::from_bytes(&bytes[cursor..])
            .map_err(FROSTError::SPPOutputMessageDeserializationError)?;

        Ok(SigningPackage {
            message,
            context,
            signing_commitments,
            signature_share,
            spp_output_message,
        })
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

#[cfg(test)]
mod tests {
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use merlin::Transcript;
    use rand_core::OsRng;
    use crate::{
        olaf::{
            simplpedpop::{Parameters, SPPOutput, SPPOutputMessage},
            Identifier, ThresholdPublicKey, VerifyingShare, GENERATOR,
        },
        Keypair, PublicKey,
    };

    use super::{NonceCommitment, SignatureShare, SigningCommitments, SigningPackage};

    #[test]
    fn test_signing_package_serialization() {
        let mut rng = OsRng;
        let group_public_key = RistrettoPoint::random(&mut rng);
        let verifying_keys = vec![
            (
                Identifier(Scalar::random(&mut rng)),
                VerifyingShare(PublicKey::from_point(RistrettoPoint::random(&mut rng))),
            ),
            (
                Identifier(Scalar::random(&mut rng)),
                VerifyingShare(PublicKey::from_point(RistrettoPoint::random(&mut rng))),
            ),
            (
                Identifier(Scalar::random(&mut rng)),
                VerifyingShare(PublicKey::from_point(RistrettoPoint::random(&mut rng))),
            ),
        ];
        let parameters = Parameters::generate(2, 2);

        let spp_output = SPPOutput {
            parameters,
            threshold_public_key: ThresholdPublicKey(PublicKey::from_point(group_public_key)),
            verifying_keys,
        };

        let keypair = Keypair::generate();
        let signature = keypair.sign(Transcript::new(b"test"));

        let spp_output_message = SPPOutputMessage {
            signer: VerifyingShare(keypair.public),
            spp_output: spp_output.clone(),
            signature,
        };

        let signing_commitments = vec![
            SigningCommitments {
                hiding: NonceCommitment(Scalar::random(&mut rng) * GENERATOR),
                binding: NonceCommitment(Scalar::random(&mut rng) * GENERATOR),
            },
            SigningCommitments {
                hiding: NonceCommitment(Scalar::random(&mut rng) * GENERATOR),
                binding: NonceCommitment(Scalar::random(&mut rng) * GENERATOR),
            },
        ];

        let message = b"message".to_vec();
        let context = b"context".to_vec();
        let signature_share = SignatureShare { share: Scalar::random(&mut rng) };

        let signing_package = SigningPackage {
            message: message.clone(),
            context: context.clone(),
            signing_commitments: signing_commitments.clone(),
            signature_share: signature_share.clone(),
            spp_output_message: spp_output_message.clone(),
        };

        let signing_package_bytes = signing_package.to_bytes();
        let deserialized_signing_package =
            SigningPackage::from_bytes(&signing_package_bytes).unwrap();

        assert!(deserialized_signing_package.message == message);
        assert!(deserialized_signing_package.context == context);
        assert!(deserialized_signing_package.signing_commitments == signing_commitments);
        assert!(deserialized_signing_package.signature_share.share == signature_share.share);
        assert!(deserialized_signing_package.spp_output_message.spp_output == spp_output);
    }
}
