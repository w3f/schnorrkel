//! Errors of the Olaf protocol.

use core::array::TryFromSliceError;
use crate::SignatureError;

/// A result for the SimplPedPoP protocol.
pub type DKGResult<T> = Result<T, DKGError>;

/// An error ocurred during the execution of the SimplPedPoP protocol.
#[derive(Debug, Clone)]
pub enum DKGError {
    /// Invalid Proof of Possession.
    InvalidProofOfPossession(SignatureError),
    /// Threshold cannot be greater than the number of participants.
    ExcessiveThreshold,
    /// Threshold must be at least 2.
    InsufficientThreshold,
    /// Number of participants is invalid.
    InvalidNumberOfParticipants,
    /// Invalid PublicKey.
    InvalidPublicKey(SignatureError),
    /// Invalid Signature.
    InvalidSignature(SignatureError),
    /// Invalid Scalar.
    InvalidScalar,
    /// Invalid Ristretto Point.
    InvalidRistrettoPoint,
    /// Deserialization Error.
    DeserializationError(TryFromSliceError),
    /// Incorrect number secret shares.
    IncorrectNumberOfValidSecretShares {
        /// The expected value.
        expected: usize,
        /// The actual value.
        actual: usize,
    },
    /// The parameters of all messages should be equal.
    DifferentParameters,
    /// The recipients hash of all messages should be equal.
    DifferentRecipientsHash,
    /// The number of messages should be 2 at least, which the minimum number of participants.
    InvalidNumberOfMessages,
    /// The number of messages should be equal to the number of participants.
    IncorrectNumberOfMessages,
    /// The number of commitments per message should be equal to the number of participants - 1.
    IncorrectNumberOfCommitments,
    /// The number of encrypted shares per message should be equal to the number of participants.
    IncorrectNumberOfEncryptedShares,
    /// The verifying key is invalid.
    InvalidVerifyingKey,
    /// Decryption error when decrypting an encrypted secret share.
    DecryptionError(chacha20poly1305::Error),
    /// Encryption error when encrypting the secret share.
    EncryptionError(chacha20poly1305::Error),
}
