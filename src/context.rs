// -*- mode: rust; -*-
//
// This file is part of schnorr-dalek.
// Copyright (c) 2017-2018 Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - jeffrey Burdges <jeff@web3.foundation>

//! Schnorr signature contexts and configuration, adaptable
//! to most Schnorr signature schemes.

use curve25519_dalek::digest::{Input};  // ExtendableOutput,XofReader
use curve25519_dalek::digest::generic_array::typenum::U64;

// trait DigestXOF = Input + ExtendableOutput + Clone + Default;

use super::*;

/// A Schnorr signing context specifies both
///  randomization and/or derandomization defenses, as well as
///  hash functions used, and their initial state,
///  due to hashing a context string.
pub trait SigningContext {
	/// Hash digest type used in signing and nonce creation
	type D: Input + Default + Clone;

	/// Initial hash state for creating a public coin, itself created
	/// by hashing a context string.
	/// 
	/// In signing and verifying, we must extend this `Digest` to 
	/// produce the public coin by `input`ing first the nonce point,
	/// then the public key, and finally the message hash.
	// the standrd Schnorr ordering
	fn context_digest(&self) -> Self::D;

	/// Initial hash state for creating a nonce, itself created by
	/// extending a `context_digest` with randomness.
	///
	/// In signing and verifying, we must extend this `Digest` to produce
	/// the nonce by `input`ing the secret nonce seed and message hash,
	/// like in a derandomized scheme like ed25519. 
	///
	/// We advise againsrt fully derandomized schemes because actual
	/// randomness is appear important in cases like multi-signatures.
	/// As an example, there is a security proof for the 3-RTT MuSig
	/// scheme, but if randomness were not used then one could lower
	/// its security to the original 2-RTT MuSig version, which
	/// lacks any security proof.
	/// 
	/// We do however feel derandomization techniques provide valuble
	/// protections even against attacks on our randomness source, and
	/// test vectors require a derandomized version.
	fn nonce_rng(&self) -> Self::D {
		use rand::{RngCore,thread_rng};
		let mut r = [0u8; 32];
		thread_rng().fill_bytes(&mut r);
		self.context_digest().chain(&r) /* .chain(&secret_nonce_seed).chain(&message) */
	}
}

/// Initialize a context hash from a byte string.
pub fn context<D>(context : Option<&'static [u8]>) -> Context<D>
where D: Input + Default + Clone,
{
    let context: &[u8] = context.unwrap_or(b""); // By default, the context is an empty string.
    debug_assert!(context.len() <= 255, "The context must not be longer than 255 bytes.");
	Context( D::default().chain(&[context.len() as u8]).chain(context) )
	// let mut c = Context(D::default());
	// if let Some(context) = context { c.more(context); }
	// c
}

/// A typical Schnorr signing context with both
/// randomized and derandomized defenses
#[derive(Debug,Clone)]
pub struct Context<D>(D)
where D: Input + Default + Clone;

/*
impl<D> Context<D>
where D: Input + Default + Clone
{
	/// Extend the initial context hash 
	pub fn more(&mut self, bytes: &[u8]) {
		for c in bytes.chunks(255) {
			self.0.input(&[c.len() as u8]);
			self.0.input(c);
		}
	}
}
*/

impl<D> SigningContext for Context<D>
where D: Input + Default + Clone,
{
	type D=D;
	fn context_digest(&self) -> D {  self.0.clone() /*.chain(&[0u8]) */  }
}
