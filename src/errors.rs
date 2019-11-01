// -*- mode: rust; -*-
//
// This file is part of schnorrkel.
// Copyright (c) 2019 Isis Lovecruft and Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>
// - Jeff Burdges <jeff@web3.foundation>

//! ### Errors which may occur when parsing keys and/or signatures to or from wire formats.

// rustc seems to think the typenames in match statements (e.g. in
// Display) should be snake cased, for some reason.
#![allow(non_snake_case)]

use core::fmt;
use core::fmt::Display;


/// `Result` specilized to this crate for convenience.
pub type SignatureResult<T> = Result<T, SignatureError>;

/// Three-round trip multi-signature stage identifies used in error reporting
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MultiSignatureStage {
    /// Initial commitment phase of a multi-signature
    Commitment,
    /// Reveal phase of a multi-signature
    Reveal,
    /// Actual cosigning phase of a multi-signature
    Cosignature,
}

impl Display for MultiSignatureStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::MultiSignatureStage::*;
        match *self {
            Commitment => write!(f, "commitment"),
            Reveal => write!(f, "reveal"),
            Cosignature => write!(f, "cosignature"),
        }
    }
}

/// Errors which may occur while processing signatures and keypairs.
///
/// All these errors represent a failed signature when they occur in
/// the context of verifying a sitgnature, including in deserializaing
/// for verification.  We expose the distinction among them primarily
/// for debugging purposes.
///
/// This error may arise due to:
///
/// * Being given bytes with a length different to what was expected.
///
/// * A problem decompressing `r`, a curve point, in the `Signature`, or the
///   curve point for a `PublicKey`.
///
/// * A problem with the format of `s`, a scalar, in the `Signature`.  This
///   is only raised if the high-bit of the scalar was set.  (Scalars must
///   only be constructed from 255-bit integers.)
///
/// * Multi-signature protocol errors
//
// * Failure of a signature to satisfy the verification equation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SignatureError {
    /// A signature verification equation failed.
    ///
    /// We emphasise that all variants represent a failed signature,
    /// not only this one.
    EquationFalse,
    /// Invalid point provided, usually to `verify` methods.
    PointDecompressionError,
    /// Invalid scalar provided, usually to `Signature::from_bytes`.
    ScalarFormatError,
    /// An error in the length of bytes handed to a constructor.
    ///
    /// To use this, pass a string specifying the `name` of the type
    /// which is returning the error, and the `length` in bytes which
    /// its constructor expects.
    BytesLengthError {
        /// Identifies the type returning the error
        name: &'static str,
        /// Describes the type returning the error
        description: &'static str,
        /// Length expected by the constructor in bytes
        length: usize
    },
    /// Signature not marked as schnorrkel, maybe try ed25519 instead.
    NotMarkedSchnorrkel,
    /// There is no record of the preceeding multi-signautre protocol
    /// stage for the specified public key.
    MuSigAbsent {
        /// Identifies the multi-signature protocol stage during which
        /// the error occured.
        musig_stage: MultiSignatureStage,
    },
    /// For this public key, there are either conflicting records for
    /// the preceeding multi-signautre protocol stage or else duplicate
    /// duplicate records for the current stage.
    MuSigInconsistent {
        /// Identifies the multi-signature protocol stage during which
        /// the error occured.
        musig_stage: MultiSignatureStage,
        /// Set true if the stage was reached correctly once but this
        /// duplicate disagrees.
        duplicate: bool,
    },

    // /// Reveal did not match commitment
    // InvalidReveal,
// other multisig errors
// AbsentCommitment
// InvalidCommitment
}

/*
impl SignatureError {
    #[inline(always)]
    fn equation(b: bool) -> SignatureResult<()> {
        if b { Ok(()) } else { Err(SignatureError::EquationFalse) }
    }
}
*/

impl Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::SignatureError::*;
        match *self {
            EquationFalse =>
                write!(f, "Verification equation failed"),
            PointDecompressionError =>
                write!(f, "Cannot decompress Ristretto point"),
            ScalarFormatError =>
                write!(f, "Cannot use scalar with high-bit set"),
            BytesLengthError { name, length, .. } =>
                write!(f, "{} must be {} bytes in length", name, length),
            NotMarkedSchnorrkel => 
                write!(f, "Signature bytes not marked as a schnorrkel signature"),
            MuSigAbsent { musig_stage, } =>
                write!(f, "Absent {} violated multi-signature protocol", musig_stage),
            MuSigInconsistent { musig_stage, duplicate, } =>
                if duplicate {
                    write!(f, "Inconsistent duplicate {} in multi-signature", musig_stage)
                } else {
                    write!(f, "Inconsistent {} violated multi-signature protocol", musig_stage)
                },
        }
    }
}

#[cfg(feature = "failure")]
impl ::failure::Fail for SignatureError {}

/// Convert `SignatureError` into `::serde::de::Error` aka `SerdeError`
///
/// We should do this with `From` but right now the orphan rules prohibit
/// `impl From<SignatureError> for E where E: ::serde::de::Error`.
#[cfg(feature = "serde")]
pub fn serde_error_from_signature_error<E>(err: SignatureError) -> E
where E: ::serde::de::Error
{
    use self::SignatureError::*;
    match err {
        PointDecompressionError
            => E::custom("Ristretto point decompression failed"),
        ScalarFormatError
            => E::custom("improper scalar has high-bit set"),  // TODO ed25519 v high 3 bits?
        BytesLengthError{ description, length, .. }
            => E::invalid_length(length, &description),
        NotMarkedSchnorrkel
            => E::custom("Signature bytes not marked as a schnorrkel signature"),
        _ => panic!("Non-serialisation error encountered by serde!"),
    }
}

