//! Types of the SimplPedPoP protocol.

#![allow(clippy::too_many_arguments)]

use core::iter;
use alloc::vec::Vec;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;
use aead::KeyInit;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Nonce};
use curve25519_dalek::{ristretto::CompressedRistretto, traits::Identity, RistrettoPoint, Scalar};
use crate::{
    context::SigningTranscript,
    olaf::{
        Identifier, ThresholdPublicKey, VerifyingShare, COMPRESSED_RISTRETTO_LENGTH, GENERATOR,
        MINIMUM_THRESHOLD, SCALAR_LENGTH,
    },
    scalar_from_canonical_bytes, PublicKey, Signature, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use super::errors::{SPPError, SPPResult};

pub(super) const U16_LENGTH: usize = 2;
pub(super) const ENCRYPTION_NONCE_LENGTH: usize = 12;
pub(super) const RECIPIENTS_HASH_LENGTH: usize = 16;
pub(super) const CHACHA20POLY1305_LENGTH: usize = 48;
pub(super) const CHACHA20POLY1305_KEY_LENGTH: usize = 32;
pub(super) const VEC_LENGTH: usize = 2;

#[derive(ZeroizeOnDrop)]
pub(super) struct SecretShare(pub(super) Scalar);

impl SecretShare {
    pub(super) fn encrypt(
        &self,
        key: &[u8; CHACHA20POLY1305_KEY_LENGTH],
        nonce: &[u8; ENCRYPTION_NONCE_LENGTH],
    ) -> SPPResult<EncryptedSecretShare> {
        let cipher = ChaCha20Poly1305::new(&(*key).into());

        let nonce = Nonce::from_slice(&nonce[..]);

        let ciphertext: Vec<u8> = cipher
            .encrypt(nonce, &self.0.to_bytes()[..])
            .map_err(SPPError::EncryptionError)?;

        Ok(EncryptedSecretShare(ciphertext))
    }

    pub(super) fn decrypt(
        encrypted_secret_share: &EncryptedSecretShare,
        key: &[u8; CHACHA20POLY1305_KEY_LENGTH],
        nonce: &[u8; ENCRYPTION_NONCE_LENGTH],
    ) -> SPPResult<SecretShare> {
        let cipher = ChaCha20Poly1305::new(&(*key).into());

        let nonce = Nonce::from_slice(&nonce[..]);

        let plaintext = cipher
            .decrypt(nonce, &encrypted_secret_share.0[..])
            .map_err(SPPError::DecryptionError)?;

        let mut bytes = [0; SCALAR_LENGTH];
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
        let mut coefficients = Vec::with_capacity(degree + 1);

        let mut first = Scalar::random(rng);
        while first == Scalar::ZERO {
            first = Scalar::random(rng);
        }

        coefficients.push(first);
        coefficients.extend(iter::repeat_with(|| Scalar::random(rng)).take(degree));

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

    pub(super) fn commit(&self) -> PolynomialCommitment {
        let coefficients_commitments =
            self.coefficients.iter().map(|coefficient| GENERATOR * coefficient).collect();

        PolynomialCommitment { coefficients_commitments }
    }
}

/// The parameters of a given execution of the SimplPedPoP protocol.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Parameters {
    pub(crate) participants: u16,
    pub(crate) threshold: u16,
}

impl Parameters {
    pub(crate) fn generate(participants: u16, threshold: u16) -> Parameters {
        Parameters { participants, threshold }
    }

    pub(super) fn validate(&self) -> Result<(), SPPError> {
        if self.threshold < MINIMUM_THRESHOLD {
            return Err(SPPError::InsufficientThreshold);
        }

        if self.participants < MINIMUM_THRESHOLD {
            return Err(SPPError::InvalidNumberOfParticipants);
        }

        if self.threshold > self.participants {
            return Err(SPPError::ExcessiveThreshold);
        }

        Ok(())
    }

    pub(super) fn commit<T: SigningTranscript>(&self, t: &mut T) {
        t.commit_bytes(b"threshold", &self.threshold.to_le_bytes());
        t.commit_bytes(b"participants", &self.participants.to_le_bytes());
    }

    pub(super) fn to_bytes(&self) -> [u8; U16_LENGTH * 2] {
        let mut bytes = [0u8; U16_LENGTH * 2];
        bytes[0..U16_LENGTH].copy_from_slice(&self.participants.to_le_bytes());
        bytes[U16_LENGTH..U16_LENGTH * 2].copy_from_slice(&self.threshold.to_le_bytes());
        bytes
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> SPPResult<Parameters> {
        if bytes.len() != U16_LENGTH * 2 {
            return Err(SPPError::InvalidParameters);
        }

        let participants = u16::from_le_bytes([bytes[0], bytes[1]]);
        let threshold = u16::from_le_bytes([bytes[2], bytes[3]]);

        Ok(Parameters { participants, threshold })
    }
}

/// The polynomial commitment of a participant, used to verify the secret shares without revealing the polynomial.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PolynomialCommitment {
    pub(super) coefficients_commitments: Vec<RistrettoPoint>,
}

impl PolynomialCommitment {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EncryptedSecretShare(pub(super) Vec<u8>);

/// AllMessage packs together messages for all participants.
///
/// We'd save bandwidth by having separate messages for each
/// participant, but typical thresholds lie between 1/2 and 2/3,
/// so this doubles or tripples bandwidth usage.
#[derive(Debug, PartialEq, Eq)]
pub struct AllMessage {
    pub(super) content: MessageContent,
    pub(super) signature: Signature,
    pub(super) proof_of_possession: Signature,
}

impl AllMessage {
    /// Creates a new message.
    pub(crate) fn new(
        content: MessageContent,
        signature: Signature,
        proof_of_possession: Signature,
    ) -> Self {
        Self { content, signature, proof_of_possession }
    }
    /// Serialize AllMessage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.content.to_bytes());
        bytes.extend(self.signature.to_bytes());
        bytes.extend(self.proof_of_possession.to_bytes());

        bytes
    }

    /// Deserialize AllMessage from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<AllMessage, SPPError> {
        let mut cursor = 0;

        let content = MessageContent::from_bytes(&bytes[cursor..])?;
        cursor += content.to_bytes().len();

        let signature = Signature::from_bytes(&bytes[cursor..cursor + SIGNATURE_LENGTH])
            .map_err(SPPError::ErrorDeserializingSignature)?;
        cursor += SIGNATURE_LENGTH;

        let proof_of_possession = Signature::from_bytes(&bytes[cursor..cursor + SIGNATURE_LENGTH])
            .map_err(SPPError::ErrorDeserializingProofOfPossession)?;

        Ok(AllMessage { content, signature, proof_of_possession })
    }
}

/// The contents of the message destined to all participants.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MessageContent {
    pub(super) sender: PublicKey,
    pub(super) encryption_nonce: [u8; ENCRYPTION_NONCE_LENGTH],
    pub(super) parameters: Parameters,
    pub(super) recipients_hash: [u8; RECIPIENTS_HASH_LENGTH],
    pub(super) polynomial_commitment: PolynomialCommitment,
    pub(super) encrypted_secret_shares: Vec<EncryptedSecretShare>,
    pub(super) ephemeral_key: PublicKey,
}

impl MessageContent {
    /// Creates the content of the message.
    pub(super) fn new(
        sender: PublicKey,
        encryption_nonce: [u8; ENCRYPTION_NONCE_LENGTH],
        parameters: Parameters,
        recipients_hash: [u8; RECIPIENTS_HASH_LENGTH],
        polynomial_commitment: PolynomialCommitment,
        encrypted_secret_shares: Vec<EncryptedSecretShare>,
        ephemeral_key: PublicKey,
    ) -> Self {
        Self {
            sender,
            encryption_nonce,
            parameters,
            recipients_hash,
            polynomial_commitment,
            encrypted_secret_shares,
            ephemeral_key,
        }
    }

    /// Serialize MessageContent into bytes.
    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.sender.to_bytes());
        bytes.extend(&self.encryption_nonce);
        bytes.extend(self.parameters.to_bytes());
        bytes.extend(&self.recipients_hash);

        for point in &self.polynomial_commitment.coefficients_commitments {
            bytes.extend(point.compress().to_bytes());
        }

        for ciphertext in &self.encrypted_secret_shares {
            bytes.extend(ciphertext.0.clone());
        }

        bytes.extend(&self.ephemeral_key.to_bytes());

        bytes
    }

    /// Deserialize MessageContent from bytes.
    pub(super) fn from_bytes(bytes: &[u8]) -> Result<MessageContent, SPPError> {
        let mut cursor = 0;

        let sender = PublicKey::from_bytes(&bytes[cursor..cursor + PUBLIC_KEY_LENGTH])
            .map_err(SPPError::InvalidPublicKey)?;
        cursor += PUBLIC_KEY_LENGTH;

        let encryption_nonce: [u8; ENCRYPTION_NONCE_LENGTH] = bytes
            [cursor..cursor + ENCRYPTION_NONCE_LENGTH]
            .try_into()
            .map_err(SPPError::DeserializationError)?;
        cursor += ENCRYPTION_NONCE_LENGTH;

        let parameters = Parameters::from_bytes(&bytes[cursor..cursor + U16_LENGTH * 2])?;
        cursor += U16_LENGTH * 2;

        let participants = parameters.participants;

        let recipients_hash: [u8; RECIPIENTS_HASH_LENGTH] = bytes
            [cursor..cursor + RECIPIENTS_HASH_LENGTH]
            .try_into()
            .map_err(SPPError::DeserializationError)?;
        cursor += RECIPIENTS_HASH_LENGTH;

        let mut coefficients_commitments = Vec::with_capacity(participants as usize);

        for _ in 0..parameters.threshold {
            let point = CompressedRistretto::from_slice(
                &bytes[cursor..cursor + COMPRESSED_RISTRETTO_LENGTH],
            )
            .map_err(SPPError::DeserializationError)?;

            coefficients_commitments
                .push(point.decompress().ok_or(SPPError::InvalidCoefficientCommitment)?);

            cursor += COMPRESSED_RISTRETTO_LENGTH;
        }

        let polynomial_commitment = PolynomialCommitment { coefficients_commitments };

        let mut encrypted_secret_shares = Vec::new();

        for _ in 0..participants {
            let ciphertext = bytes[cursor..cursor + CHACHA20POLY1305_LENGTH].to_vec();
            encrypted_secret_shares.push(EncryptedSecretShare(ciphertext));
            cursor += CHACHA20POLY1305_LENGTH;
        }

        let ephemeral_key = PublicKey::from_bytes(&bytes[cursor..cursor + PUBLIC_KEY_LENGTH])
            .map_err(SPPError::InvalidPublicKey)?;

        Ok(MessageContent {
            sender,
            encryption_nonce,
            parameters,
            recipients_hash,
            polynomial_commitment,
            encrypted_secret_shares,
            ephemeral_key,
        })
    }
}

/// The signed output of the SimplPedPoP protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SPPOutputMessage {
    pub(crate) signer: VerifyingShare,
    pub(crate) spp_output: SPPOutput,
    pub(crate) signature: Signature,
}

impl SPPOutputMessage {
    pub(crate) fn new(signer: VerifyingShare, content: SPPOutput, signature: Signature) -> Self {
        Self { signer, signature, spp_output: content }
    }

    /// Serializes the SPPOutputMessage into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let pk_bytes = self.signer.0.to_bytes();
        bytes.extend(pk_bytes);

        let content_bytes = self.spp_output.to_bytes();
        bytes.extend(content_bytes);

        let signature_bytes = self.signature.to_bytes();
        bytes.extend(signature_bytes);

        bytes
    }

    /// Deserializes the SPPOutputMessage from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SPPError> {
        let mut cursor = 0;

        let pk_bytes = &bytes[..PUBLIC_KEY_LENGTH];
        let signer =
            VerifyingShare(PublicKey::from_bytes(pk_bytes).map_err(SPPError::InvalidPublicKey)?);
        cursor += PUBLIC_KEY_LENGTH;

        let content_bytes = &bytes[cursor..bytes.len() - SIGNATURE_LENGTH];
        let spp_output = SPPOutput::from_bytes(content_bytes)?;

        cursor = bytes.len() - SIGNATURE_LENGTH;
        let signature = Signature::from_bytes(&bytes[cursor..cursor + SIGNATURE_LENGTH])
            .map_err(SPPError::ErrorDeserializingSignature)?;

        Ok(SPPOutputMessage { signer, spp_output, signature })
    }

    /// Returns the output of the SimplPedPoP protocol.
    pub fn spp_output(&self) -> SPPOutput {
        self.spp_output.clone()
    }

    /// Verifies the signature of the message.
    pub fn verify_signature(&self) -> SPPResult<()> {
        let mut spp_output_transcript = Transcript::new(b"spp output");
        spp_output_transcript.append_message(b"message", &self.spp_output.to_bytes());

        self.signer
            .0
            .verify(spp_output_transcript, &self.signature)
            .map_err(SPPError::InvalidSignature)
    }
}

/// The content of the signed output of the SimplPedPoP protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SPPOutput {
    pub(crate) parameters: Parameters,
    pub(crate) threshold_public_key: ThresholdPublicKey,
    pub(crate) verifying_keys: Vec<(Identifier, VerifyingShare)>,
}

impl SPPOutput {
    pub(crate) fn new(
        parameters: &Parameters,
        threshold_public_key: ThresholdPublicKey,
        verifying_keys: Vec<(Identifier, VerifyingShare)>,
    ) -> Self {
        let parameters = Parameters::generate(parameters.participants, parameters.threshold);

        Self { threshold_public_key, verifying_keys, parameters }
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.parameters.to_bytes());

        let compressed_public_key = self.threshold_public_key.0.as_compressed();
        bytes.extend(compressed_public_key.to_bytes().iter());

        let key_count = self.verifying_keys.len() as u16;
        bytes.extend(key_count.to_le_bytes());

        for (id, key) in &self.verifying_keys {
            bytes.extend(id.0.to_bytes());
            bytes.extend(key.0.to_bytes());
        }

        bytes
    }

    /// Deserializes the SPPOutput from bytes.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, SPPError> {
        let mut cursor = 0;

        let parameters = Parameters::from_bytes(&bytes[cursor..cursor + U16_LENGTH * 2])?;
        cursor += U16_LENGTH * 2;

        let public_key_bytes = &bytes[cursor..cursor + PUBLIC_KEY_LENGTH];
        cursor += PUBLIC_KEY_LENGTH;

        let compressed_public_key = CompressedRistretto::from_slice(public_key_bytes)
            .map_err(SPPError::DeserializationError)?;

        let threshold_public_key =
            compressed_public_key.decompress().ok_or(SPPError::InvalidThresholdPublicKey)?;

        let mut verifying_keys = Vec::new();

        cursor += VEC_LENGTH;

        while cursor < bytes.len() {
            let mut identifier_bytes = [0; SCALAR_LENGTH];
            identifier_bytes.copy_from_slice(&bytes[cursor..cursor + SCALAR_LENGTH]);
            let identifier =
                scalar_from_canonical_bytes(identifier_bytes).ok_or(SPPError::InvalidIdentifier)?;
            cursor += SCALAR_LENGTH;

            let key_bytes = &bytes[cursor..cursor + PUBLIC_KEY_LENGTH];
            cursor += PUBLIC_KEY_LENGTH;
            let key = PublicKey::from_bytes(key_bytes).map_err(SPPError::InvalidPublicKey)?;
            verifying_keys.push((Identifier(identifier), VerifyingShare(key)));
        }

        Ok(SPPOutput {
            threshold_public_key: ThresholdPublicKey(PublicKey::from_point(threshold_public_key)),
            verifying_keys,
            parameters,
        })
    }

    /// Returns the threshold public key.
    pub fn threshold_public_key(&self) -> ThresholdPublicKey {
        self.threshold_public_key
    }
}

#[cfg(test)]
mod tests {
    use merlin::Transcript;
    use rand_core::OsRng;
    use crate::{context::SigningTranscript, olaf::test_utils::generate_parameters, Keypair};
    use super::*;
    use curve25519_dalek::RistrettoPoint;

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

        SecretShare::decrypt(&encrypted_share, &key_bytes, &encryption_nonce).unwrap();
    }

    #[test]
    fn test_generate_polynomial_commitment_valid() {
        let degree = 3;

        let polynomial = SecretPolynomial::generate(degree, &mut OsRng);

        let polynomial_commitment = polynomial.commit();

        assert_eq!(polynomial.coefficients.len(), degree as usize + 1);

        assert_eq!(polynomial_commitment.coefficients_commitments.len(), degree as usize + 1);
    }

    #[test]
    fn test_evaluate_polynomial() {
        let coefficients: Vec<Scalar> =
            vec![Scalar::from(3u64), Scalar::from(2u64), Scalar::from(1u64)]; // Polynomial x^2 + 2x + 3

        let polynomial = SecretPolynomial { coefficients };

        let value = Scalar::from(5u64); // x = 5

        let result = polynomial.evaluate(&value);

        assert_eq!(result, Scalar::from(38u64)); // 5^2 + 2*5 + 3
    }

    #[test]
    fn test_serialize_deserialize_all_message() {
        let parameters = generate_parameters();

        let keypairs: Vec<Keypair> =
            (0..parameters.participants).map(|_| Keypair::generate()).collect();
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public).collect();

        let message: AllMessage = keypairs[0]
            .simplpedpop_contribute_all(parameters.threshold as u16, public_keys.clone())
            .unwrap();

        let bytes = message.to_bytes();

        let deserialized_message = AllMessage::from_bytes(&bytes).expect("Failed to deserialize");

        assert_eq!(message, deserialized_message);
    }

    #[test]
    fn test_spp_output_message_serialization() {
        let parameters = generate_parameters();
        let participants = parameters.participants as usize;
        let threshold = parameters.threshold as usize;

        let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public).collect();

        let mut all_messages = Vec::new();
        for i in 0..participants {
            let message: AllMessage = keypairs[i]
                .simplpedpop_contribute_all(threshold as u16, public_keys.clone())
                .unwrap();
            all_messages.push(message);
        }

        let spp_output = keypairs[0].simplpedpop_recipient_all(&all_messages).unwrap();

        let bytes = spp_output.0.to_bytes();

        let deserialized_spp_output_message =
            SPPOutputMessage::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(deserialized_spp_output_message, spp_output.0);
    }

    #[test]
    fn test_spp_output_message_verification() {
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
        let mut transcript = Transcript::new(b"spp output");
        transcript.append_message(b"message", &spp_output.to_bytes());
        let signature = keypair.sign(transcript);

        let spp_output_message =
            SPPOutputMessage { signer: VerifyingShare(keypair.public), spp_output, signature };

        spp_output_message.verify_signature().unwrap()
    }

    #[test]
    fn test_sum_secret_polynomial_commitments() {
        let polynomial_commitment1 = PolynomialCommitment {
            coefficients_commitments: vec![
                GENERATOR * Scalar::from(1u64), // Constant
                GENERATOR * Scalar::from(2u64), // Linear
                GENERATOR * Scalar::from(3u64), // Quadratic
            ],
        };

        let polynomial_commitment2 = PolynomialCommitment {
            coefficients_commitments: vec![
                GENERATOR * Scalar::from(4u64), // Constant
                GENERATOR * Scalar::from(5u64), // Linear
                GENERATOR * Scalar::from(6u64), // Quadratic
            ],
        };

        let summed_polynomial_commitments = PolynomialCommitment::sum_polynomial_commitments(&[
            &polynomial_commitment1,
            &polynomial_commitment2,
        ]);

        let expected_coefficients_commitments = vec![
            GENERATOR * Scalar::from(5u64), // 1 + 4 = 5
            GENERATOR * Scalar::from(7u64), // 2 + 5 = 7
            GENERATOR * Scalar::from(9u64), // 3 + 6 = 9
        ];

        assert_eq!(
            summed_polynomial_commitments.coefficients_commitments,
            expected_coefficients_commitments,
            "Coefficient commitments do not match"
        );
    }

    #[test]
    fn test_evaluate_polynomial_commitment() {
        // f(x) = 3 + 2x + x^2
        let constant_coefficient_commitment = Scalar::from(3u64) * GENERATOR;
        let linear_commitment = Scalar::from(2u64) * GENERATOR;
        let quadratic_commitment = Scalar::from(1u64) * GENERATOR;

        // Note the order and inclusion of the constant term
        let coefficients_commitments =
            vec![constant_coefficient_commitment, linear_commitment, quadratic_commitment];

        let polynomial_commitment = PolynomialCommitment { coefficients_commitments };

        let value = Scalar::from(2u64);

        // f(2) = 11
        let expected = Scalar::from(11u64) * GENERATOR;

        let result = polynomial_commitment.evaluate(&value);

        assert_eq!(result, expected, "The evaluated commitment does not match the expected result");
    }

    #[test]
    fn test_parameters_serialization() {
        let params = Parameters::generate(3, 2);
        let bytes = params.to_bytes();
        let result = Parameters::from_bytes(&bytes).unwrap();

        assert_eq!(params.participants, result.participants);
        assert_eq!(params.threshold, result.threshold);
    }
}
