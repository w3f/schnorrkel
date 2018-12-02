// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017 Isis Lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>

//! Errors which may occur when parsing keys and/or signatures to or from wire formats.

// rustc seems to think the typenames in match statements (e.g. in
// Display) should be snake cased, for some reason.
#![allow(non_snake_case)]

use core::fmt;
use core::fmt::Display;

/// Errors which may occur while processing signatures and keypairs.
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
/// * Failure of a signature to satisfy the verification equation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SignatureError {
	/// Invalid point provided, usually to `verify` methods.
    PointDecompressionError,
	/// Invalid scalar provided, usually to `Signature::from_bytes`.
    ScalarFormatError,
    /// An error in the length of bytes handed to a constructor.
    ///
    /// To use this, pass a string specifying the `name` of the type which is
    /// returning the error, and the `length` in bytes which its constructor
    /// expects.
    BytesLengthError{
		/// Identifies the type returning the error
		name: &'static str,
		/// Length expected by the constructor in bytes
		length: usize 
	},
    /// The verification equation wasn't satisfied
    VerifyError,
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SignatureError::PointDecompressionError
                => write!(f, "Cannot decompress Edwards point"),
            SignatureError::ScalarFormatError
                => write!(f, "Cannot use scalar with high-bit set"),
            SignatureError::BytesLengthError{ name: n, length: l}
                => write!(f, "{} must be {} bytes in length", n, l),
            SignatureError::VerifyError
                => write!(f, "Verification equation was not satisfied"),
        }
    }
}

impl ::failure::Fail for SignatureError {}

#[cfg(feature = "serde")]
impl<E> From<SignatureError> for E where E: ::serde::de::Error {
	fn from(err: SignatureError) -> E {
		match err {
            SignatureError::PointDecompressionError
                => E::custom("Ristretto point decompression failed"),
            SignatureError::ScalarFormatError
                => E::custom("improper scalar has high-bit set"),  // TODO ed25519 v high 3 bits?
            SignatureError::BytesLengthError{ name: n, length: l}
                => E::invalid_length(bytes.len(), &self),
            SignatureError::VerifyError
                => panic!("Verification attempted in deserialisation!"),
		}
	}
}

