//! SimplPedPoP data structures.

#![allow(clippy::too_many_arguments)]

use alloc::vec::Vec;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint};
use crate::{context::SigningTranscript, PublicKey, Signature, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use super::{errors::DKGError, MINIMUM_THRESHOLD};

pub(crate) const COMPRESSED_RISTRETTO_LENGTH: usize = 32;
pub(crate) const U16_LENGTH: usize = 2;
pub(crate) const ENCRYPTION_NONCE_LENGTH: usize = 12;
pub(crate) const RECIPIENTS_HASH_LENGTH: usize = 16;
pub(crate) const CHACHA20POLY1305_LENGTH: usize = 64;

/// The parameters of a given execution of the SimplPedPoP protocol.
#[derive(Clone, PartialEq, Eq)]
pub struct Parameters {
    pub(crate) participants: u16,
    pub(crate) threshold: u16,
}

impl Parameters {
    /// Create new parameters.
    pub fn generate(participants: u16, threshold: u16) -> Parameters {
        Parameters { participants, threshold }
    }

    pub(crate) fn validate(&self) -> Result<(), DKGError> {
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

    pub(crate) fn commit<T: SigningTranscript>(&self, t: &mut T) {
        t.commit_bytes(b"threshold", &self.threshold.to_le_bytes());
        t.commit_bytes(b"participants", &self.participants.to_le_bytes());
    }
}

/// AllMessage packs together messages for all participants.
///
/// We'd save bandwidth by having separate messages for each
/// participant, but typical thresholds lie between 1/2 and 2/3,
/// so this doubles or tripples bandwidth usage.
pub struct AllMessage {
    pub(crate) content: MessageContent,
    pub(crate) signature: Signature,
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
    pub(crate) sender: PublicKey,
    pub(crate) encryption_nonce: [u8; ENCRYPTION_NONCE_LENGTH],
    pub(crate) parameters: Parameters,
    pub(crate) recipients_hash: [u8; RECIPIENTS_HASH_LENGTH],
    pub(crate) point_polynomial: Vec<RistrettoPoint>,
    pub(crate) ciphertexts: Vec<Vec<u8>>,
    pub(crate) ephemeral_key: PublicKey,
    pub(crate) proof_of_possession: Signature,
}

impl MessageContent {
    /// Creates the content of the message.
    pub fn new(
        sender: PublicKey,
        encryption_nonce: [u8; ENCRYPTION_NONCE_LENGTH],
        parameters: Parameters,
        recipients_hash: [u8; RECIPIENTS_HASH_LENGTH],
        point_polynomial: Vec<RistrettoPoint>,
        ciphertexts: Vec<Vec<u8>>,
        ephemeral_key: PublicKey,
        proof_of_possession: Signature,
    ) -> Self {
        Self {
            sender,
            encryption_nonce,
            parameters,
            recipients_hash,
            point_polynomial,
            ciphertexts,
            ephemeral_key,
            proof_of_possession,
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

        for point in &self.point_polynomial {
            bytes.extend(point.compress().to_bytes());
        }

        for ciphertext in &self.ciphertexts {
            bytes.extend(ciphertext);
        }

        bytes.extend(&self.ephemeral_key.to_bytes());
        bytes.extend(&self.proof_of_possession.to_bytes());

        bytes
    }

    /// Deserialize MessageContent from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<MessageContent, DKGError> {
        let mut cursor = 0;

        // Deserialize PublicKey
        let sender = PublicKey::from_bytes(&bytes[cursor..cursor + PUBLIC_KEY_LENGTH])
            .map_err(DKGError::InvalidPublicKey)?;
        cursor += PUBLIC_KEY_LENGTH;

        // Deserialize encryption_nonce
        let encryption_nonce: [u8; ENCRYPTION_NONCE_LENGTH] = bytes
            [cursor..cursor + ENCRYPTION_NONCE_LENGTH]
            .try_into()
            .map_err(DKGError::DeserializationError)?;
        cursor += ENCRYPTION_NONCE_LENGTH;

        // Deserialize Parameters
        let participants = u16::from_le_bytes(
            bytes[cursor..cursor + U16_LENGTH]
                .try_into()
                .map_err(DKGError::DeserializationError)?,
        );
        cursor += U16_LENGTH;
        let threshold = u16::from_le_bytes(
            bytes[cursor..cursor + U16_LENGTH]
                .try_into()
                .map_err(DKGError::DeserializationError)?,
        );
        cursor += U16_LENGTH;

        let recipients_hash: [u8; RECIPIENTS_HASH_LENGTH] = bytes
            [cursor..cursor + RECIPIENTS_HASH_LENGTH]
            .try_into()
            .map_err(DKGError::DeserializationError)?;
        cursor += RECIPIENTS_HASH_LENGTH;

        let mut point_polynomial = Vec::with_capacity(participants as usize);
        for _ in 0..participants {
            let point = CompressedRistretto::from_slice(
                &bytes[cursor..cursor + COMPRESSED_RISTRETTO_LENGTH],
            )
            .map_err(DKGError::DeserializationError)?;
            point_polynomial.push(point.decompress().ok_or(DKGError::InvalidRistrettoPoint)?);
            cursor += COMPRESSED_RISTRETTO_LENGTH;
        }

        let mut ciphertexts = Vec::new();
        for _ in 0..participants {
            let ciphertext = bytes[cursor..cursor + CHACHA20POLY1305_LENGTH].to_vec();
            ciphertexts.push(ciphertext);
            cursor += CHACHA20POLY1305_LENGTH;
        }

        let ephemeral_key = PublicKey::from_bytes(&bytes[cursor..cursor + PUBLIC_KEY_LENGTH])
            .map_err(DKGError::InvalidPublicKey)?;
        cursor += PUBLIC_KEY_LENGTH;

        let proof_of_possession = Signature::from_bytes(&bytes[cursor..cursor + SIGNATURE_LENGTH])
            .map_err(DKGError::InvalidSignature)?;

        Ok(MessageContent {
            sender,
            encryption_nonce,
            parameters: Parameters { participants, threshold },
            recipients_hash,
            point_polynomial,
            ciphertexts,
            ephemeral_key,
            proof_of_possession,
        })
    }
}

/// The signed output of the SimplPedPoP protocol.
pub struct DKGOutput {
    pub(crate) sender: PublicKey,
    pub(crate) content: DKGOutputContent,
    pub(crate) signature: Signature,
}

impl DKGOutput {
    /// Creates a signed SimplPedPoP output.
    pub fn new(sender: PublicKey, content: DKGOutputContent, signature: Signature) -> Self {
        Self { sender, content, signature }
    }

    /// Serializes the DKGOutput into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let pk_bytes = self.sender.to_bytes();
        bytes.extend(pk_bytes);

        let content_bytes = self.content.to_bytes();
        bytes.extend(content_bytes);

        let signature_bytes = self.signature.to_bytes();
        bytes.extend(signature_bytes);

        bytes
    }

    /// Deserializes the DKGOutput from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DKGError> {
        let mut cursor = 0;

        let pk_bytes = &bytes[..PUBLIC_KEY_LENGTH];
        let sender = PublicKey::from_bytes(pk_bytes).map_err(DKGError::InvalidPublicKey)?;
        cursor += PUBLIC_KEY_LENGTH;

        let content_bytes = &bytes[cursor..bytes.len() - SIGNATURE_LENGTH];
        let content = DKGOutputContent::from_bytes(content_bytes)?;

        cursor = bytes.len() - SIGNATURE_LENGTH;
        let signature = Signature::from_bytes(&bytes[cursor..cursor + SIGNATURE_LENGTH])
            .map_err(DKGError::InvalidSignature)?;

        Ok(DKGOutput { sender, content, signature })
    }
}

/// The content of the signed output of the SimplPedPoP protocol.
#[derive(Debug)]
pub struct DKGOutputContent {
    pub(crate) group_public_key: PublicKey,
    pub(crate) verifying_keys: Vec<RistrettoPoint>,
}

impl DKGOutputContent {
    /// Creates the content of the SimplPedPoP output.
    pub fn new(group_public_key: PublicKey, verifying_keys: Vec<RistrettoPoint>) -> Self {
        Self { group_public_key, verifying_keys }
    }
    /// Serializes the DKGOutputContent into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize the group public key
        let compressed_public_key = self.group_public_key.as_compressed(); // Assuming PublicKey can be compressed directly
        bytes.extend(compressed_public_key.to_bytes().iter());

        // Serialize the number of verifying keys
        let key_count = self.verifying_keys.len() as u16;
        bytes.extend(key_count.to_le_bytes());

        // Serialize each verifying key
        for key in &self.verifying_keys {
            let compressed_key = key.compress();
            bytes.extend(compressed_key.to_bytes());
        }

        bytes
    }
}

impl DKGOutputContent {
    /// Deserializes the DKGOutputContent from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<DKGOutputContent, DKGError> {
        let mut cursor = 0;

        // Deserialize the group public key
        let public_key_bytes = &bytes[cursor..cursor + PUBLIC_KEY_LENGTH]; // Ristretto points are 32 bytes when compressed
        cursor += PUBLIC_KEY_LENGTH;
        let compressed_public_key = CompressedRistretto::from_slice(public_key_bytes)
            .map_err(DKGError::DeserializationError)?;
        let group_public_key =
            compressed_public_key.decompress().ok_or(DKGError::InvalidRistrettoPoint)?;

        // Deserialize the number of verifying keys
        let key_count_bytes = &bytes[cursor..cursor + U16_LENGTH];
        cursor += U16_LENGTH;
        let key_count =
            u16::from_le_bytes(key_count_bytes.try_into().map_err(DKGError::DeserializationError)?);

        // Deserialize each verifying key
        let mut verifying_keys = Vec::with_capacity(key_count as usize);
        for _ in 0..key_count {
            let key_bytes = &bytes[cursor..cursor + COMPRESSED_RISTRETTO_LENGTH];
            cursor += COMPRESSED_RISTRETTO_LENGTH;
            let compressed_key = CompressedRistretto::from_slice(key_bytes)
                .map_err(DKGError::DeserializationError)?;
            let key = compressed_key.decompress().ok_or(DKGError::InvalidRistrettoPoint)?;
            verifying_keys.push(key);
        }

        Ok(DKGOutputContent {
            group_public_key: PublicKey::from_point(group_public_key),
            verifying_keys,
        })
    }
}
