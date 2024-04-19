//! Errors of the Olaf protocol.

use super::identifier::Identifier;
use crate::SignatureError;
use thiserror::Error;

/// A result for the SimplPedPoP protocol.
pub type DKGResult<T> = Result<T, DKGError>;

/// Errors that can occur during the SimplPedPoP protocol.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum DKGError {
    /// Occurs when a proof of possession is invalid. Typically involves signature verification failure.
    #[error("Invalid proof of possession: {0}")]
    InvalidProofOfPossession(SignatureError),

    /// Error when a certificate does not meet the required validation criteria, usually involving cryptographic signature issues.
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(SignatureError),

    /// Raised when the specified threshold exceeds the number of participants in the protocol.
    #[error("Threshold cannot be greater than the number of participants")]
    ExcessiveThreshold,

    /// This error is raised if the threshold for a cryptographic operation is set below the minimum required limit, which is 2.
    #[error("Threshold must be at least 2")]
    InsufficientThreshold,

    /// Indicates an error when the number of participants specified for the DKG process is not valid.
    #[error("Number of participants is invalid")]
    InvalidNumberOfParticipants,

    /// Error when the verification of a secret share fails for a specific identifier.
    #[error("Secret share verification failed for identifier {0}")]
    InvalidSecretShare(Identifier),

    /// Indicates a problem with the secrecy component of a protocol, such as incorrect or tampered secret data.
    #[error("Invalid secret")]
    InvalidSecret,

    /// Error when an unknown identifier is detected in round 1 of the public messages.
    #[error("Unknown identifier in round 1 public messages: {0}")]
    UnknownIdentifierRound1PublicMessages(Identifier),

    /// Similar to the round 1 error, but for unknown identifiers found in the public messages of round 2.
    #[error("Unknown identifier in round 2 public messages: {0}")]
    UnknownIdentifierRound2PublicMessages(Identifier),

    /// Error for unknown identifiers in private messages of round 2, typically indicating a data mismatch or synchronization issue.
    #[error("Unknown identifier in round 2 private messages")]
    UnknownIdentifierRound2PrivateMessages,

    /// Raised when an identifier is set to a zero scalar, which is not permissible in cryptographic operations.
    #[error("Identifier cannot be a zero scalar")]
    InvalidIdentifier,

    /// Indicates a discrepancy in the number of identifiers expected versus received.
    #[error("Incorrect number of identifiers: expected {expected}, actual {actual}")]
    IncorrectNumberOfIdentifiers {
        /// The number of identifiers that were expected to be processed or received.
        expected: usize,
        /// The actual number of identifiers that were processed or received.
        actual: usize,
    },

    /// Indicates a discrepancy in the number of private messages expected versus received.
    #[error("Incorrect number of private messages: expected {expected}, actual {actual}")]
    IncorrectNumberOfPrivateMessages {
        /// The expected number of private messages according to protocol requirements.
        expected: usize,
        /// The actual number of private messages received or processed.
        actual: usize,
    },

    /// Indicates a discrepancy in the number of round 1 public messages expected versus received.
    #[error("Incorrect number of round 1 public messages: expected {expected}, actual {actual}")]
    IncorrectNumberOfRound1PublicMessages {
        /// The expected number of public messages in round 1 based on the protocol setup.
        expected: usize,
        /// The actual count of public messages received in round 1.
        actual: usize,
    },

    /// Indicates a discrepancy in the number of round 2 public messages expected versus received.
    #[error("Incorrect number of round 2 public messages: expected {expected}, actual {actual}")]
    IncorrectNumberOfRound2PublicMessages {
        /// The expected number of public messages in round 2 as defined by the protocol.
        expected: usize,
        /// The actual count of public messages received in round 2.
        actual: usize,
    },

    /// Indicates a discrepancy in the number of round 2 private messages expected versus received.
    #[error("Incorrect number of round 2 private messages: expected {expected}, actual {actual}")]
    IncorrectNumberOfRound2PrivateMessages {
        /// The number of private messages that were expected in round 2 of the protocol.
        expected: usize,
        /// The actual number of private messages that were received in round 2.
        actual: usize,
    },

    /// Error occurring during the decryption of an encrypted secret share.
    #[error("Decryption error when decrypting an encrypted secret share: {0}")]
    DecryptionError(chacha20poly1305::Error),

    /// Error occurring during the encryption of a secret share.
    #[error("Encryption error when encrypting the secret share: {0}")]
    EncryptionError(chacha20poly1305::Error),

    /// Indicates a discrepancy in the number of coefficient commitments in the secret polynomial expected versus actual.
    #[error("Incorrect number of coefficient commitments: expected {expected}, actual {actual}")]
    InvalidSecretPolynomialCommitment {
        /// /// The expected number of coefficients in the secret polynomial.
        expected: usize,
        /// The actual number of coefficients in the secret polynomial.
        actual: usize,
    },
}

/// A result for the FROST protocol.
pub type FROSTResult<T> = Result<T, FROSTError>;

/// Errors that can occur during the FROST protocol.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum FROSTError {
    /// Signature share verification failed.
    #[error("Signature share verification failed for signer {culprit}")]
    InvalidSignatureShare {
        /// The identifier of the signer whose share validation failed.
        culprit: Identifier,
    },
    /// Incorrect number of signing commitments.
    #[error("Incorrect number of signing commitments")]
    IncorrectNumberOfSigningCommitments,
    /// The participant's signing commitment is missing from the Signing Package
    #[error("The participant's signing commitment is missing from the Signing Package")]
    MissingSigningCommitment,
    /// The participant's signing commitment is incorrect
    #[error("The participant's signing commitment is incorrect")]
    IncorrectSigningCommitment,
    /// This identifier does not belong to a participant in the signing process.
    #[error("Unknown identifier")]
    UnknownIdentifier,
    /// Commitment equals the identity
    #[error("Commitment equals the identity")]
    IdentitySigningCommitment,
    /// Incorrect number of identifiers.
    #[error("Incorrect number of identifiers")]
    IncorrectNumberOfIdentifiers,
    /// Signature verification failed.
    #[error("Signature verification failed: {0}")]
    InvalidSignature(SignatureError),
    /// This identifier is duplicated.
    #[error("This identifier is duplicated")]
    DuplicatedIdentifier,
}
