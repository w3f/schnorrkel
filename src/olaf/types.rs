//! SimplPedPoP types.

use core::iter;
use alloc::vec::Vec;
use curve25519_dalek::{ristretto::CompressedRistretto, traits::Identity, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;
use crate::{
    context::SigningTranscript, scalar_from_canonical_bytes, PublicKey, Signature,
    PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use super::{
    errors::{DKGError, DKGResult},
    GroupPublicKey, Identifier, VerifyingShare, GENERATOR, MINIMUM_THRESHOLD,
};
use aead::KeyInit;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Nonce};

pub(super) const COMPRESSED_RISTRETTO_LENGTH: usize = 32;
pub(super) const VEC_LENGTH: usize = 2;
pub(super) const ENCRYPTION_NONCE_LENGTH: usize = 12;
pub(super) const RECIPIENTS_HASH_LENGTH: usize = 16;
pub(super) const CHACHA20POLY1305_LENGTH: usize = 64;
pub(super) const CHACHA20POLY1305_KEY_LENGTH: usize = 32;
pub(super) const SCALAR_LENGTH: usize = 32;

/// The parameters of a given execution of the SimplPedPoP protocol.
#[derive(PartialEq, Eq)]
pub struct Parameters {
    pub(super) participants: u16,
    pub(super) threshold: u16,
}

impl Parameters {
    /// Create new parameters.
    pub fn generate(participants: u16, threshold: u16) -> Parameters {
        Parameters { participants, threshold }
    }

    pub(super) fn validate(&self) -> Result<(), DKGError> {
        if self.threshold < MINIMUM_THRESHOLD {
            return Err(DKGError::InsufficientThreshold);
        }

        if self.participants < MINIMUM_THRESHOLD {
            return Err(DKGError::InvalidNumberOfParticipants);
        }

        if self.threshold > self.participants {
            return Err(DKGError::ExcessiveThreshold);
        }

        Ok(())
    }

    pub(super) fn commit<T: SigningTranscript>(&self, t: &mut T) {
        t.commit_bytes(b"threshold", &self.threshold.to_le_bytes());
        t.commit_bytes(b"participants", &self.participants.to_le_bytes());
    }
}

#[derive(ZeroizeOnDrop)]
pub(super) struct SecretShare(pub(super) Scalar);

impl SecretShare {
    pub(super) fn encrypt(
        &self,
        key: &[u8; CHACHA20POLY1305_KEY_LENGTH],
        nonce: &[u8; ENCRYPTION_NONCE_LENGTH],
    ) -> DKGResult<EncryptedSecretShare> {
        let cipher = ChaCha20Poly1305::new(&(*key).into());

        let nonce = Nonce::from_slice(&nonce[..]);

        let ciphertext: Vec<u8> = cipher
            .encrypt(nonce, &self.0.to_bytes()[..])
            .map_err(DKGError::EncryptionError)?;

        Ok(EncryptedSecretShare(ciphertext))
    }
}

#[derive(Clone)]
pub struct EncryptedSecretShare(pub(super) Vec<u8>);

impl EncryptedSecretShare {
    pub(super) fn decrypt(
        &self,
        key: &[u8; CHACHA20POLY1305_KEY_LENGTH],
        nonce: &[u8; ENCRYPTION_NONCE_LENGTH],
    ) -> DKGResult<SecretShare> {
        let cipher = ChaCha20Poly1305::new(&(*key).into());

        let nonce = Nonce::from_slice(&nonce[..]);

        let plaintext = cipher.decrypt(nonce, &self.0[..]).map_err(DKGError::DecryptionError)?;

        let mut bytes = [0; 32];
        bytes.copy_from_slice(&plaintext);

        Ok(SecretShare(Scalar::from_bytes_mod_order(bytes)))
    }
}

/// The secret polynomial of a participant chosen at randoma nd used to generate the secret shares of all the participants (including itself).
#[derive(ZeroizeOnDrop)]
pub(super) struct SecretPolynomial {
    pub(super) coefficients: Vec<Scalar>,
}

impl SecretPolynomial {
    pub(super) fn generate<R: RngCore + CryptoRng>(degree: usize, rng: &mut R) -> Self {
        let mut coefficients = Vec::with_capacity(degree);

        let mut first = Scalar::random(rng);
        while first == Scalar::ZERO {
            first = Scalar::random(rng);
        }

        coefficients.push(first);
        coefficients.extend(iter::repeat_with(|| Scalar::random(rng)).take(degree - 1));

        SecretPolynomial { coefficients }
    }

    pub(super) fn evaluate(&self, x: &Scalar) -> Scalar {
        let mut value =
            *self.coefficients.last().expect("coefficients must have at least one element");

        for coeff in self.coefficients.iter().rev().skip(1) {
            value = value * x + coeff;
        }

        value
    }
}

/// The polynomial commitment of a participant, used to verify the secret shares without revealing the polynomial.
pub struct PolynomialCommitment {
    pub(super) coefficients_commitments: Vec<RistrettoPoint>,
}

impl PolynomialCommitment {
    pub(super) fn commit(secret_polynomial: &SecretPolynomial) -> Self {
        let coefficients_commitments = secret_polynomial
            .coefficients
            .iter()
            .map(|coefficient| GENERATOR * coefficient)
            .collect();

        Self { coefficients_commitments }
    }

    pub(super) fn evaluate(&self, identifier: &Scalar) -> RistrettoPoint {
        let i = identifier;

        let (_, result) = self
            .coefficients_commitments
            .iter()
            .fold((Scalar::ONE, RistrettoPoint::identity()), |(i_to_the_k, sum_so_far), comm_k| {
                (i * i_to_the_k, sum_so_far + comm_k * i_to_the_k)
            });

        result
    }

    pub(super) fn sum_polynomial_commitments(
        polynomials_commitments: &[&PolynomialCommitment],
    ) -> PolynomialCommitment {
        let max_length = polynomials_commitments
            .iter()
            .map(|c| c.coefficients_commitments.len())
            .max()
            .unwrap_or(0);

        let mut total_commitment = vec![RistrettoPoint::identity(); max_length];

        for polynomial_commitment in polynomials_commitments {
            for (i, coeff_commitment) in
                polynomial_commitment.coefficients_commitments.iter().enumerate()
            {
                total_commitment[i] += coeff_commitment;
            }
        }

        PolynomialCommitment { coefficients_commitments: total_commitment }
    }
}

/// AllMessage packs together messages for all participants.
///
/// We'd save bandwidth by having separate messages for each
/// participant, but typical thresholds lie between 1/2 and 2/3,
/// so this doubles or tripples bandwidth usage.
pub struct AllMessage {
    pub(super) content: MessageContent,
    pub(super) signature: Signature,
}

impl AllMessage {
    /// Creates a new message.
    pub fn new(content: MessageContent, signature: Signature) -> Self {
        Self { content, signature }
    }
    /// Serialize AllMessage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.content.to_bytes());
        bytes.extend(self.signature.to_bytes());

        bytes
    }

    /// Deserialize AllMessage from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<AllMessage, DKGError> {
        let mut cursor = 0;

        let content = MessageContent::from_bytes(&bytes[cursor..])?;
        cursor += content.to_bytes().len();

        let signature = Signature::from_bytes(&bytes[cursor..cursor + SIGNATURE_LENGTH])
            .map_err(DKGError::InvalidSignature)?;

        Ok(AllMessage { content, signature })
    }
}

/// The contents of the message destined to all participants.
pub struct MessageContent {
    pub(super) sender: PublicKey,
    pub(super) encryption_nonce: [u8; ENCRYPTION_NONCE_LENGTH],
    pub(super) parameters: Parameters,
    pub(super) recipients_hash: [u8; RECIPIENTS_HASH_LENGTH],
    pub(super) polynomial_commitment: PolynomialCommitment,
    pub(super) encrypted_secret_shares: Vec<EncryptedSecretShare>,
}

impl MessageContent {
    /// Creates the content of the message.
    pub fn new(
        sender: PublicKey,
        encryption_nonce: [u8; ENCRYPTION_NONCE_LENGTH],
        parameters: Parameters,
        recipients_hash: [u8; RECIPIENTS_HASH_LENGTH],
        polynomial_commitment: PolynomialCommitment,
        encrypted_secret_shares: Vec<EncryptedSecretShare>,
    ) -> Self {
        Self {
            sender,
            encryption_nonce,
            parameters,
            recipients_hash,
            polynomial_commitment,
            encrypted_secret_shares,
        }
    }
    /// Serialize MessageContent
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.sender.to_bytes());
        bytes.extend(&self.encryption_nonce);
        bytes.extend(self.parameters.participants.to_le_bytes());
        bytes.extend(self.parameters.threshold.to_le_bytes());
        bytes.extend(&self.recipients_hash);

        for point in &self.polynomial_commitment.coefficients_commitments {
            bytes.extend(point.compress().to_bytes());
        }

        for ciphertext in &self.encrypted_secret_shares {
            bytes.extend(ciphertext.0.clone());
        }

        bytes
    }

    /// Deserialize MessageContent from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<MessageContent, DKGError> {
        let mut cursor = 0;

        let sender = PublicKey::from_bytes(&bytes[cursor..cursor + PUBLIC_KEY_LENGTH])
            .map_err(DKGError::InvalidPublicKey)?;
        cursor += PUBLIC_KEY_LENGTH;

        let encryption_nonce: [u8; ENCRYPTION_NONCE_LENGTH] = bytes
            [cursor..cursor + ENCRYPTION_NONCE_LENGTH]
            .try_into()
            .map_err(DKGError::DeserializationError)?;
        cursor += ENCRYPTION_NONCE_LENGTH;

        let participants = u16::from_le_bytes(
            bytes[cursor..cursor + VEC_LENGTH]
                .try_into()
                .map_err(DKGError::DeserializationError)?,
        );
        cursor += VEC_LENGTH;
        let threshold = u16::from_le_bytes(
            bytes[cursor..cursor + VEC_LENGTH]
                .try_into()
                .map_err(DKGError::DeserializationError)?,
        );
        cursor += VEC_LENGTH;

        let recipients_hash: [u8; RECIPIENTS_HASH_LENGTH] = bytes
            [cursor..cursor + RECIPIENTS_HASH_LENGTH]
            .try_into()
            .map_err(DKGError::DeserializationError)?;
        cursor += RECIPIENTS_HASH_LENGTH;

        let mut coefficients_commitments = Vec::with_capacity(participants as usize);

        for _ in 0..participants {
            let point = CompressedRistretto::from_slice(
                &bytes[cursor..cursor + COMPRESSED_RISTRETTO_LENGTH],
            )
            .map_err(DKGError::DeserializationError)?;

            coefficients_commitments
                .push(point.decompress().ok_or(DKGError::InvaliCoefficientCommitment)?);

            cursor += COMPRESSED_RISTRETTO_LENGTH;
        }

        let polynomial_commitment = PolynomialCommitment { coefficients_commitments };

        let mut encrypted_secret_shares = Vec::new();

        for _ in 0..participants {
            let ciphertext = bytes[cursor..cursor + CHACHA20POLY1305_LENGTH].to_vec();
            encrypted_secret_shares.push(EncryptedSecretShare(ciphertext));
            cursor += CHACHA20POLY1305_LENGTH;
        }

        Ok(MessageContent {
            sender,
            encryption_nonce,
            parameters: Parameters { participants, threshold },
            recipients_hash,
            polynomial_commitment,
            encrypted_secret_shares,
        })
    }
}

/// The signed output of the SimplPedPoP protocol.
pub struct DKGOutputMessage {
    pub(super) sender: PublicKey,
    pub(super) dkg_output: DKGOutput,
    pub(super) signature: Signature,
}

impl DKGOutputMessage {
    /// Creates a signed SimplPedPoP output.
    pub fn new(sender: PublicKey, content: DKGOutput, signature: Signature) -> Self {
        Self { sender, dkg_output: content, signature }
    }

    /// Serializes the DKGOutputMessage into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let pk_bytes = self.sender.to_bytes();
        bytes.extend(pk_bytes);

        let content_bytes = self.dkg_output.to_bytes();
        bytes.extend(content_bytes);

        let signature_bytes = self.signature.to_bytes();
        bytes.extend(signature_bytes);

        bytes
    }

    /// Deserializes the DKGOutputMessage from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DKGError> {
        let mut cursor = 0;

        let pk_bytes = &bytes[..PUBLIC_KEY_LENGTH];
        let sender = PublicKey::from_bytes(pk_bytes).map_err(DKGError::InvalidPublicKey)?;
        cursor += PUBLIC_KEY_LENGTH;

        let content_bytes = &bytes[cursor..bytes.len() - SIGNATURE_LENGTH];
        let dkg_output = DKGOutput::from_bytes(content_bytes)?;

        cursor = bytes.len() - SIGNATURE_LENGTH;
        let signature = Signature::from_bytes(&bytes[cursor..cursor + SIGNATURE_LENGTH])
            .map_err(DKGError::InvalidSignature)?;

        Ok(DKGOutputMessage { sender, dkg_output, signature })
    }
}

/// The content of the signed output of the SimplPedPoP protocol.
pub struct DKGOutput {
    pub(super) group_public_key: GroupPublicKey,
    pub(super) verifying_keys: Vec<(Identifier, VerifyingShare)>,
}

impl DKGOutput {
    /// Creates the content of the SimplPedPoP output.
    pub fn new(
        group_public_key: GroupPublicKey,
        verifying_keys: Vec<(Identifier, VerifyingShare)>,
    ) -> Self {
        Self { group_public_key, verifying_keys }
    }
    /// Serializes the DKGOutput into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let compressed_public_key = self.group_public_key.0.as_compressed();
        bytes.extend(compressed_public_key.to_bytes().iter());

        let key_count = self.verifying_keys.len() as u16;
        bytes.extend(key_count.to_le_bytes());

        for (id, key) in &self.verifying_keys {
            bytes.extend(id.0.to_bytes());
            bytes.extend(key.0.to_bytes());
        }

        bytes
    }

    /// Deserializes the DKGOutput from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DKGError> {
        let mut cursor = 0;

        let public_key_bytes = &bytes[cursor..cursor + PUBLIC_KEY_LENGTH];
        cursor += PUBLIC_KEY_LENGTH;

        let compressed_public_key = CompressedRistretto::from_slice(public_key_bytes)
            .map_err(DKGError::DeserializationError)?;

        let group_public_key =
            compressed_public_key.decompress().ok_or(DKGError::InvalidGroupPublicKey)?;

        cursor += VEC_LENGTH;

        let mut verifying_keys = Vec::new();

        while cursor < bytes.len() {
            let mut identifier_bytes = [0; SCALAR_LENGTH];
            identifier_bytes.copy_from_slice(&bytes[cursor..cursor + SCALAR_LENGTH]);
            let identifier =
                scalar_from_canonical_bytes(identifier_bytes).ok_or(DKGError::InvalidIdentifier)?;
            cursor += SCALAR_LENGTH;

            let key_bytes = &bytes[cursor..cursor + PUBLIC_KEY_LENGTH];
            cursor += PUBLIC_KEY_LENGTH;
            let key = PublicKey::from_bytes(key_bytes).map_err(DKGError::InvalidPublicKey)?;
            verifying_keys.push((Identifier(identifier), VerifyingShare(key)));
        }

        Ok(DKGOutput {
            group_public_key: GroupPublicKey(PublicKey::from_point(group_public_key)),
            verifying_keys,
        })
    }
}

#[cfg(test)]
mod tests {
    use merlin::Transcript;
    use rand_core::OsRng;
    use crate::Keypair;
    use super::*;

    #[test]
    fn test_serialize_deserialize_all_message() {
        let sender = Keypair::generate();
        let encryption_nonce = [1u8; ENCRYPTION_NONCE_LENGTH];
        let parameters = Parameters { participants: 2, threshold: 1 };
        let recipients_hash = [2u8; RECIPIENTS_HASH_LENGTH];
        let coefficients_commitments =
            vec![RistrettoPoint::random(&mut OsRng), RistrettoPoint::random(&mut OsRng)];
        let polynomial_commitment = PolynomialCommitment { coefficients_commitments };
        let encrypted_secret_shares = vec![
            EncryptedSecretShare(vec![1; CHACHA20POLY1305_LENGTH]),
            EncryptedSecretShare(vec![1; CHACHA20POLY1305_LENGTH]),
        ];
        let signature = sender.sign(Transcript::new(b"sig"));

        let message_content = MessageContent::new(
            sender.public,
            encryption_nonce,
            parameters,
            recipients_hash,
            polynomial_commitment,
            encrypted_secret_shares,
        );

        let message = AllMessage::new(message_content, signature);

        let bytes = message.to_bytes();

        let deserialized_message = AllMessage::from_bytes(&bytes).expect("Failed to deserialize");

        assert_eq!(message.content.sender, deserialized_message.content.sender);

        assert_eq!(message.content.encryption_nonce, deserialized_message.content.encryption_nonce);

        assert_eq!(
            message.content.parameters.participants,
            deserialized_message.content.parameters.participants
        );

        assert_eq!(
            message.content.parameters.threshold,
            deserialized_message.content.parameters.threshold
        );

        assert_eq!(message.content.recipients_hash, deserialized_message.content.recipients_hash);

        assert!(message
            .content
            .polynomial_commitment
            .coefficients_commitments
            .iter()
            .zip(
                deserialized_message
                    .content
                    .polynomial_commitment
                    .coefficients_commitments
                    .iter()
            )
            .all(|(a, b)| a.compress() == b.compress()));

        assert!(message
            .content
            .encrypted_secret_shares
            .iter()
            .zip(deserialized_message.content.encrypted_secret_shares.iter())
            .all(|(a, b)| a.0 == b.0));

        assert_eq!(message.signature, deserialized_message.signature);
    }

    #[test]
    fn test_dkg_output_serialization() {
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

        let dkg_output = DKGOutput {
            group_public_key: GroupPublicKey(PublicKey::from_point(group_public_key)),
            verifying_keys,
        };

        let keypair = Keypair::generate();
        let signature = keypair.sign(Transcript::new(b"test"));

        let dkg_output = DKGOutputMessage { sender: keypair.public, dkg_output, signature };

        let bytes = dkg_output.to_bytes();

        let deserialized_dkg_output =
            DKGOutputMessage::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(
            deserialized_dkg_output.dkg_output.group_public_key.0.as_compressed(),
            dkg_output.dkg_output.group_public_key.0.as_compressed(),
            "Group public keys do not match"
        );

        assert_eq!(
            deserialized_dkg_output.dkg_output.verifying_keys.len(),
            dkg_output.dkg_output.verifying_keys.len(),
            "Verifying keys counts do not match"
        );

        assert!(
            deserialized_dkg_output
                .dkg_output
                .verifying_keys
                .iter()
                .zip(dkg_output.dkg_output.verifying_keys.iter())
                .all(|((a, b), (c, d))| a.0 == c.0 && b.0 == d.0),
            "Verifying keys do not match"
        );

        assert_eq!(
            deserialized_dkg_output.signature, dkg_output.signature,
            "Signatures do not match"
        );
    }

    #[test]
    fn test_encryption_decryption() {
        let mut rng = OsRng;
        let ephemeral_key = Keypair::generate();
        let recipient = Keypair::generate();
        let encryption_nonce = [1; ENCRYPTION_NONCE_LENGTH];
        let key_exchange = ephemeral_key.secret.key * recipient.public.as_point();
        let secret_share = SecretShare(Scalar::random(&mut rng));
        let mut transcript = Transcript::new(b"encryption");
        transcript.commit_point(b"key", &key_exchange.compress());
        let mut key_bytes = [0; CHACHA20POLY1305_KEY_LENGTH];
        transcript.challenge_bytes(b"key", &mut key_bytes);

        let encrypted_share = secret_share.encrypt(&key_bytes, &encryption_nonce).unwrap();

        encrypted_share.decrypt(&key_bytes, &encryption_nonce).unwrap();
    }
}
