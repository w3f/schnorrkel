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

// use rand::prelude::*;  // {RngCore,thread_rng};

use core::borrow::{Borrow,BorrowMut};

use rand::prelude::*;

use merlin::{Transcript};

use curve25519_dalek::digest::{FixedOutput,ExtendableOutput,XofReader}; // Input
use curve25519_dalek::digest::generic_array::typenum::U32;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use super::*;

/// Schnorr signing transcript
/// 
/// We envision signatures being on messages, but if a signature occurs
/// inside a larger protocol then the signature scheme's internal 
/// transcript may exist before or persist after signing.
/// 
/// In this trait, we provide an interface for Schnorr signature-like
/// constructions that is compatable with `merlin::Transcript`, but
/// abstract enough to support normal hash functions as well.
///
/// We also abstract over owned and borrowed `merlin::Transcript`s,
/// so that simple use cases do not suffer from our support for. 
pub trait SigningTranscript {
    /// Extend transcript with some bytes, shadowed by `merlin::Transcript`.
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8]);

    /// Extend transcript with a protocol name
    fn proto_name(&mut self, label: &'static [u8]) {
        self.commit_bytes(b"proto-name", label);
    }

    /// Extend the transcript with a compressed Ristretto point
    fn commit_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.commit_bytes(label, point.as_bytes());
    }

    /*
    fn commit_sorted_points<P,S>(&mut self, label: &'static [u8], set: &mut [P])
	where P: Borrow<CompressedRistretto>,
          // S: BorrowMut<[P]>,
	{
		// let set = set.borrow_mut();
		set.sort_unstable_by(
			|a,b| a.borrow().as_bytes()
			 .cmp(b.borrow().as_bytes())
		);
		for p in set.iter() {
	    	self.commit_point(label,p.borrow());
		}
    }
	*/

    /// Produce some challenge bytes, shadowed by `merlin::Transcript`.
    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]);

    /// Produce the public challenge scalar `e`.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0; 64];
        self.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }

    /// Produce a secret witness scalar `k`, aka nonce, from the protocol
	/// transcript and any "nonce seeds" kept with the secret keys.
    fn witness_scalar(&self, nonce_seed: &[u8], extra_nonce_seed: Option<&[u8]>) -> Scalar;

    /// Produce secret witness bytes from the protocol transcript
	/// and any "nonce seeds" kept with the secret keys.
    fn witness_bytes(&self, dest: &mut [u8], nonce_seed: &[u8], extra_nonce_seed: Option<&[u8]>);
}

impl<T> SigningTranscript for T
where T: Borrow<Transcript>+BorrowMut<Transcript>  // Transcript, &mut Transcript
{
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8]) {
        Transcript::commit_bytes(self.borrow_mut(), label, bytes);
    }

    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        Transcript::challenge_bytes(self.borrow_mut(), label, dest);
    }

    fn witness_scalar(&self, nonce_seed: &[u8], extra_nonce_seed: Option<&[u8]>) -> Scalar
	{
        let mut br = self.borrow().build_rng()
            .commit_witness_bytes(b"", nonce_seed);
		if let Some(w) = extra_nonce_seed {
			br = br.commit_witness_bytes(b"", w);
		}
		let mut r = br.finalize(&mut thread_rng());
		Scalar::random(&mut r)
    }

    fn witness_bytes(&self, dest: &mut [u8], nonce_seed: &[u8], extra_nonce_seed: Option<&[u8]>)
	{
        let mut br = self.borrow().build_rng()
            .commit_witness_bytes(b"", nonce_seed);
		if let Some(w) = extra_nonce_seed {
			br = br.commit_witness_bytes(b"", w);
		}
		let mut r = br.finalize(&mut thread_rng());
		r.fill_bytes(dest)
    }
}

/// Schnorr signing context
///
/// We expect users to seperate `SigningContext`s for each role that
/// signature play in their protocol.  These `SigningContext`s may be
/// global `lazy_static!`s.
///
/// To sign a message, apply the appropriate inherent method to create
/// a signature transcript.
#[derive(Clone)] // Debug
pub struct SigningContext(Transcript);

/// Initialize a signing context from a static byte string that
/// identifies the signature's role in the larger protocol.
pub fn signing_context(context : &'static [u8]) -> SigningContext {
    SigningContext::new(context)
}

impl SigningContext {
	/// Initialize a signing context from a static byte string that
	/// identifies the signature's role in the larger protocol.
	pub fn new(context : &'static [u8]) -> SigningContext {
        SigningContext(Transcript::new(context))
	}

    /// Initalize an owned signing transcript on a message provided as a byte array
	pub fn bytes(&self, bytes: &[u8]) -> Transcript {
        let mut t = self.0.clone();
        t.commit_bytes(b"sign-bytes", bytes);
        t
	}

    /// Initalize an owned signing transcript on a message provided as a hash function with extensible output
	pub fn xof<D: ExtendableOutput>(&self, h: D) -> Transcript {
	    let mut prehash = [0u8; 32];
	    h.xof_result().read(&mut prehash);		
		let mut t = self.0.clone();
		t.commit_bytes(b"sign-XoF", &prehash);
		t
	}

    /// Initalize an owned signing transcript on a message provided as a hash function with 256 bit output
	pub fn hash256<D: FixedOutput<OutputSize=U32>>(&self, h: D) -> Transcript {
	    let mut prehash = [0u8; 32];
		prehash.copy_from_slice(h.fixed_result().as_slice());
		let mut t = self.0.clone();
		t.commit_bytes(b"sign-256", &prehash);
		t
	}
}

