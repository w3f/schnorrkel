//! Errors of the Olaf protocol.

use core::array::TryFromSliceError;
use crate::SignatureError;

/// A result for the SimplPedPoP protocol.
pub type DKGResult<T> = Result<T, DKGError>;

/// An error ocurred during the execution of the SimplPedPoP protocol.
#[derive(Debug)]
pub enum DKGError {
    /// Threshold cannot be greater than the number of participants.
    ExcessiveThreshold,
    /// Threshold must be at least 2.
    InsufficientThreshold,
    /// Number of participants is invalid.
    InvalidNumberOfParticipants,
    /// Invalid public key.
    InvalidPublicKey(SignatureError),
    /// Invalid group public key.
    InvalidGroupPublicKey,
    /// Invalid signature.
    InvalidSignature(SignatureError),
    /// Invalid coefficient commitment of the polynomial commitment.
    InvalidCoefficientCommitment,
    /// Invalid identifier.
    InvalidIdentifier,
    /// Invalid secret share.
    InvalidSecretShare,
    /// Deserialization Error.
    DeserializationError(TryFromSliceError),
    /// The parameters of all messages must be equal.
    DifferentParameters,
    /// The recipients hash of all messages must be equal.
    DifferentRecipientsHash,
    /// The number of messages should be 2 at least, which the minimum number of participants.
    InvalidNumberOfMessages,
    /// The number of coefficient commitments of the polynomial commitment must be equal to the threshold - 1.
    IncorrectNumberOfCoefficientCommitments,
    /// The number of encrypted shares per message must be equal to the number of participants.
    IncorrectNumberOfEncryptedShares,
    /// Decryption error when decrypting an encrypted secret share.
    DecryptionError(chacha20poly1305::Error),
    /// Encryption error when encrypting the secret share.
    EncryptionError(chacha20poly1305::Error),
    /// Invalid Proof of Possession.
    InvalidProofOfPossession(SignatureError),
}
