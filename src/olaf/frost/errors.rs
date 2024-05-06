//! Errors of the FROST protocol.

/// A result for the FROST protocol.
pub type FROSTResult<T> = Result<T, FROSTError>;

/// An error ocurred during the execution of the FROST protocol
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FROSTError {
    /// Incorrect number of signing commitments.
    IncorrectNumberOfSigningCommitments,
    /// The participant's signing commitment is missing from the Signing Package
    MissingSigningCommitment,
    /// The participant's signing commitment is incorrect
    IncorrectSigningCommitment,
    /// This identifier does not belong to a participant in the signing process.
    UnknownIdentifier,
    /// Commitment equals the identity
    IdentitySigningCommitment,
    /// Incorrect number of identifiers.
    IncorrectNumberOfIdentifiers,
    /// Signature verification failed.
    InvalidSignature,
    /// This identifier is duplicated.
    DuplicatedIdentifier,
}
