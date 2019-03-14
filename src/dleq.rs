// -*- mode: rust; -*-
//
// This file is part of schnorrkel.
// Copyright (c) 2019 Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! Implementation of a Verifiable Random Function (VRF) using
//! Ristretto points and Schnorr DLEQ proofs.
//!
//! We model the VRF on "Making NSEC5 Practical for DNSSEC" by
//! Dimitrios Papadopoulos, Duane Wessels, Shumon Huque, Moni Naor,
//! Jan Včelák, Leonid Rezyin, andd Sharon Goldberg
//! https://eprint.iacr.org/2017/099.pdf
//! We note the V(X)EdDSA signature scheme by Trevor Perrin at
//! https://www.signal.org/docs/specifications/xeddsa/#vxeddsa
//! is equivalent to the NSEC5 construction.
//!
//! We support individual signers batch numerous VRF outputs as
//! described in the DLEQ Proofs and Batching the proofs sections of
//! "Privacy Pass - The Math" by Alex Davidson.
//! https://blog.cloudflare.com/privacy-pass-the-math/#dleqproofs
//! and "Privacy Pass: Bypassing Internet Challenges Anonymously"
//! by Alex Davidson, Ian Goldberg, Nick Sullivan, George Tankersley,
//! and Filippo Valsorda.
//! https://www.petsymposium.org/2018/files/papers/issue3/popets-2018-0026.pdf
//!
//! As noted there, our batching technique's soundness appeals to
//! Theorem 3.17 on page 74 of Ryqan Henry's PhD thesis 
//! "Efficient Zero-KnowledgeProofs and Applications"
//! https://uwspace.uwaterloo.ca/bitstream/handle/10012/8621/Henry_Ryan.pdf
//! See also the attack on Peng and Bao’s batch proof protocol in 
//! "Batch Proofs of Partial Knowledge" by Ryan Henry and Ian Goldberg
//! https://www.cypherpunks.ca/~iang/pubs/batchzkp-acns.pdf
//!
//! We might reasonably ask if the VRF signer's public key should
//! really be hashed when creating the scalars in `merge_vrf`. 
//! After all, there is no similar requirement when the values being
//! hashed are BLS public keys in 
//! https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html
//! In fact, we expect the public key could be dropped both in
//! Privacy Pass' case, due to using randomness in the messages,
//! and in the VRF case, provided the message depends upon shared
//! randomness created after the public key.  Yet, there are VRF
//! applications outside these two cases, and DLEQ proof applications
//! where the points are not even hashes.  At minimum, we expect
//! hashing the public key prevents malicious signers from choosing
//! their key to cancel out the blionding of a particular point,
//! which might become important in a verifiable shuffle or other
//! anonymity applications.  In any case, there is no cost to
//! hashing the public key for VRF applications.
//! TODO: Explain better!
//!
//! We do not currently implement verifier side batching analogous
//! to batched verification of Schnorr signatures because doing so
//! requires including an extra curve point, which enlarges the
//! VRF proofs.


use core::borrow::{Borrow,BorrowMut};

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, boxed::Box};
#[cfg(feature = "std")]
use std::{vec::Vec, boxed::Box};

use rand::prelude::*; // ThreadRng,thread_rng
use rand_chacha::ChaChaRng;

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{CompressedRistretto,RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;

use merlin::Transcript;

use super::*;
use crate::context::SigningTranscript;
use crate::points::RistrettoBoth;
// use crate::errors::SignatureError;


/// VRF input or output, possibly unverified
///
/// Internally, we keep both `RistrettoPoint` and `CompressedRistretto`
/// forms using `RistrettoBoth`.
///
/// We'd actually love to statically distinguish here between inputs
/// and outputs, as well as whether outputs were verified, but doing
/// so would disrupt our general purpose DLEQ proof mechanism, so
/// users must be responcible for this themselves.  We do however
/// consume by value in actual output methods, and do not implement
/// `Copy`, as a reminder that VRF outputs should only be used once
/// and should be checked before usage.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VRFPut(RistrettoBoth);

/// Hash a transcript to a point for use in VRF output 
pub fn vrf_hash<T: SigningTranscript>(mut t: T) -> VRFPut {
    let mut b = [0u8; 64];
    t.challenge_bytes(b"VRFHash",&mut b);
    VRFPut(RistrettoBoth::from_point(RistrettoPoint::from_uniform_bytes(&b)))
}

impl VRFPut {
    /// Raw bytes output from the VRF
    pub fn into_output_bytes(self) -> [u8; 32] { self.0.into_compressed().0 }

    /// VRF output converted into any `SeedableRng` with a 32 byte seed.
    pub fn into_rng<R: SeedableRng<Seed=[u8; 32]>>(self) -> R {
        R::from_seed(self.into_output_bytes())
    }

    /// VRF output converted into a `ChaChaRng`, which provides
    /// multiple output streams via `ChaChaRng::set_stream`.
    pub fn into_chacharng(self) -> ChaChaRng {
        self.into_rng::<ChaChaRng>()
    }

    /// VRF output converted into Merlin's Keccek based `Rng`.
    ///
    /// We think this might be marginally slower than `ChaChaRng`
    /// when considerable output is required, but it should reduce
    /// the final linked binary size slightly, and improves domain
    /// seperation. 
    pub fn into_merlin_rng(self, context: &'static [u8]) -> merlin::TranscriptRng {
        // Very insecure hack except for our commit_witness_bytes below
        struct ZeroFakeRng;
        impl ::rand::RngCore for ZeroFakeRng {
            fn next_u32(&mut self) -> u32 { panic!() }
            fn next_u64(&mut self) -> u64 { panic!() }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                for i in dest.iter_mut() { *i = 0; }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
        impl ::rand::CryptoRng for ZeroFakeRng {}

        ::merlin::Transcript::new(context).build_rng()
          .commit_witness_bytes(b"", &self.0.as_compressed().0)
          .finalize(&mut ZeroFakeRng)
    }
}

// TODO: serde_boilerplate!(VRFPut);


/// VRF inout and output pair
pub struct VRFInOut {
    /// VRF input point
	pub input: VRFPut,
    /// VRF output point
	pub output: VRFPut,
}

impl VRFInOut {
    fn commit<T: SigningTranscript>(&self, mut t: T) {
        t.commit_point(b"input", self.input.0.as_compressed());
        t.commit_point(b"output", self.output.0.as_compressed());
    }
}

fn challenge_scalar_128<T: SigningTranscript>(mut t: T) -> Scalar {
    let mut s = [0u8; 16];
    t.challenge_bytes(b"",&mut s);
    Scalar::from(u128::from_le_bytes(s))
}

impl PublicKey {
    /// Merge VRF input and output pairs from the same signer,
    /// using constant time arithmatic.
    ///
    /// There is sadly no constant time 128 bit multiplication in dalek,
    /// making this variant somewhat slower than necessary.  It should 
    /// only impact signers in niche senarios however, so this slower
    /// variant should normally be unecessary.  
    ///
	/// TODO: Add constant time 128 bit batched multiplication to dalek.
    /// TODO: Is rand_chacha's `gen::<u128>()` standardizable enough to
    /// prefer it over merlin for the output?  
    pub fn vrfs_merge<I,B>(&self, ps: &[B]) -> VRFInOut
    where B: Borrow<VRFInOut>,
    {
        let mut t = ::merlin::Transcript::new(b"MergeVRFs");
        t.commit_point(b"pk", self.as_compressed());
        for p in ps.iter() {
            p.borrow().commit(&mut t);
        }

        let mut input = ps[0].borrow().input.0.as_point().clone();
        let mut output = ps[0].borrow().output.0.as_point().clone();
        for p in ps.iter().skip(1).map(|p| p.borrow()) {
            let mut t0 = t.clone();
            p.commit(&mut t0);
            let z = challenge_scalar_128(t0);
            input += &z * p.input.0.as_point();
            output += &z * p.output.0.as_point();
        }

        VRFInOut {
            input: VRFPut(RistrettoBoth::from_point(input)),
            output: VRFPut(RistrettoBoth::from_point(output)),
        }
    }

    /// Merge VRF input and output pairs from the same signer,
    /// using variable time arithmatic
    ///
    /// You should use this variant when verifying VRF proofs batched
    /// by the singer.  You could usually use this variant even when
    /// producing proofs, provided the set being signed is not secret.
    pub fn vrfs_merge_vartime<I,B>(&self, ps: &[B]) -> VRFInOut
    where B: Borrow<VRFInOut>,
    {
        let mut t = ::merlin::Transcript::new(b"MergeVRFs");
        t.commit_point(b"pk", self.as_compressed());
        for p in ps.iter() {
            p.borrow().commit(&mut t);
        }

        let zs: Vec<Scalar> = ps.iter().skip(1).map(|p| {
            let mut t0 = t.clone();
            p.borrow().commit(&mut t0);
            challenge_scalar_128(t0)
        }).collect();
		let one = Scalar::one();
		let zf = || ::core::iter::once(&one).chain(zs.iter());

        VRFInOut {
            input: VRFPut(RistrettoBoth::from_point(
                RistrettoPoint::vartime_multiscalar_mul(zf(), ps.iter().map(|p| p.borrow().input.0.as_point()))
            )),
            output: VRFPut(RistrettoBoth::from_point(
                RistrettoPoint::vartime_multiscalar_mul(zf(), ps.iter().map(|p| p.borrow().output.0.as_point()))
            )),
        }
    }
}









/// Short proof of correctness for associated VRF output,
/// for which no batched verfication works.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VRFProof {
    /// Challenge
    c: Scalar,
    /// Schnorr proof
    s: Scalar,
}

// TODO: serde_boilerplate!(VRFProof);


/// Longer proof of correctness for associated VRF output,
/// which supports batching.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(non_snake_case)]
pub struct VRFProofBatchable {
    /// Challenge
    c: Scalar,
    /// Schnorr proof
    s: Scalar,
    /// Additional R value that permits batching
    R: CompressedRistretto,
}

impl VRFProofBatchable {
    /// Return the shorten `VRFProof` for not batched situations
    pub fn shorten(self) -> VRFProof {
        let VRFProofBatchable {c, s, .. } = self;
        VRFProof {c, s, }
    }
}

// TODO: serde_boilerplate!(VRFProofBatchable);


impl Keypair {
    /// Produce DLEQ proof.
    ///
    /// We mutate `points` by multipling every point by `self.secret`
    /// and produce a proof that this multiplication was done correctly.
    #[allow(non_snake_case)]
    pub fn proove_dleqs<T,B>(&self, mut t: T, points: &mut [B]) -> VRFProofBatchable
    where T: SigningTranscript+Clone,
          B: BorrowMut<VRFPut>,
    {
        t.proto_name(b"DLEQProof");
        // t.commit_point(b"g",constants::RISTRETTO_BASEPOINT_TABLE.basepoint().compress());
        for h in points.iter_mut().map(|h| h.borrow_mut()) {
            t.commit_point(b"h", h.0.as_compressed());
        }

        t.commit_point(b"pk",self.public.as_compressed());

        // We compute R after adding pk and all h.
        let r = t.witness_scalar(&[&self.secret.nonce]);
        let R = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();
        t.commit_point(b"R=g^r",&R);

        for p in points.iter_mut().map(|p| p.borrow_mut()) {
            t.commit_point(b"h^r", & (&r * p.0.as_point()).compress() );            
        }

        // We add h^x last to save an allocation. 
        for p in points.iter_mut().map(|p| p.borrow_mut()) {
            let p0 = RistrettoBoth::from_point(&self.secret.key * p.0.as_point());
            p.0 = p0;
            t.commit_point(b"h^pk", p.0.as_compressed());           
        }

        let c = t.challenge_scalar(b"");  // context, message, A/public_key, R=rG
        let s = &r - &(&c * &self.secret.key);
        VRFProofBatchable { c, s, R, }
    }

    /// Run VRF on one single input transcript, producing the outpus and correspodning short proof.
    pub fn vrf<T: SigningTranscript>(&self, t: T) -> (VRFPut,VRFProofBatchable) {
        let mut h = vrf_hash(t);
        let t0 = Transcript::new(b"VRF");  // We have context in t and another hear breaks batching 
        let proof = self.proove_dleqs(t0, &mut [&mut h]);
        (h, proof)
    }

    /// Run VRF on several input transcripts, producing their outputs and a common short proof.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn vrfs<T,I>(&self, ts: I) -> (Box<[VRFPut]>,VRFProofBatchable)
    where T: SigningTranscript,
          I: IntoIterator<Item=T>,
    {
        let mut hs = ts.into_iter().map(|t| vrf_hash(t)).collect::<Vec<VRFPut>>();
        let t0 = Transcript::new(b"VRF");
        let proof = self.proove_dleqs(t0, hs.as_mut_slice());
        (hs.into_boxed_slice(), proof)
    }
}






impl PublicKey {
    /// Verify DLEQ proof that `points_out` consists of all points in
    /// `points_in` raised to the same private exponent as `self`.
    ///
    /// We also return an enlarged `VRFProofBatchable` instead of true
    /// so that verifiers can forward batchable proofs.
    ///
    /// In principle, one might provide "blindly verifiable" VRFs that
    /// avoid requiring `self` here, but naively such constructions
    /// risk the same flaws as DLEQ based blind signatures, and this
    /// version exploits the slightly faster basepoint arithmatic.
    #[allow(non_snake_case)]
    pub fn verify_dleqs<T,B>(&self, mut t: T, points_in: &[B], points_out: &[B], proof: &VRFProof)
     -> Option<VRFProofBatchable>
    where T: SigningTranscript,
          B: Borrow<VRFPut>,
    {
        assert_eq!(points_in.len(), points_out.len());

        t.proto_name(b"DLEQProof");
        // t.commit_point(b"g",constants::RISTRETTO_BASEPOINT_TABLE.basepoint().compress());
        for h in points_in.iter() {
            t.commit_point(b"h", h.borrow().0.as_compressed());
        }

        t.commit_point(b"pk",self.as_compressed());

        // We recompute R aka u from the proof
        // let R = (&proof.c * self.as_point()) + (&proof.s * &constants::RISTRETTO_BASEPOINT_TABLE);
        let R = RistrettoPoint::vartime_double_scalar_mul_basepoint(&proof.c, self.as_point(), &proof.s).compress();
        t.commit_point(b"R=g^r",&R);

        // We also recompute h^r aka u using the proof
        use curve25519_dalek::traits::VartimeMultiscalarMul;
        for (h,hpk) in points_in.iter().zip(points_out) {
            let f = |x: &B| *(x.borrow().0.as_point());
            // let hr = (&proof.c * hpk.borrow().0.as_point()) + (&proof.s * h.borrow().0.as_point());
            let hr = RistrettoPoint::vartime_multiscalar_mul(
                &[proof.c, proof.s],
                &[f(hpk), f(h)]
            );
            t.commit_point(b"h^r", & hr.compress() );           
        }

        // We add h^x last to save an allocation in proove_dleqs. 
        for p in points_out.iter() {
            t.commit_point(b"h^pk", p.borrow().0.as_compressed());          
        }

        // We need not check that h^pk lies on the curve because Ristretto ensures this.
        let VRFProof { c, s, } = *proof;
        if c == t.challenge_scalar(b"") {
            Some(VRFProofBatchable { c, s, R, })
        } else { None }
    }

    /// Verify VRF proof for one single input transcript and correspodning output.
    pub fn vrf_verify<T: SigningTranscript>(&self, t: T, out: &VRFPut, proof: &VRFProof)
     -> Option<VRFProofBatchable> {
        let h = vrf_hash(t);
        let t0 = Transcript::new(b"VRF");  // We have context in t and another hear breaks batching 
        self.verify_dleqs(t0, &[&h], &[out], proof)
    }

    /// Verify a common VRF short proof for several input transcripts and correspodning outputs.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn vrfs_verify<T,I>(&self, ts: I, out: &[VRFPut], proof: &VRFProof)
     -> Option<VRFProofBatchable>
    where T: SigningTranscript,
          I: IntoIterator<Item=T>,
    {
        let mut hs = ts.into_iter().map(|t| vrf_hash(t)).collect::<Vec<VRFPut>>();
        let t0 = Transcript::new(b"VRF");  // We have context in t and another hear breaks batching 
        self.verify_dleqs(t0, hs.as_mut_slice(), out, proof)
    }
}


#[cfg(test)]
mod tests {
    use std::vec::Vec;
    use rand::prelude::*;
    use super::*;

    #[test]
    fn vrf_single() {
        // let mut csprng = ChaChaRng::from_seed([0u8; 32]);
        let keypair1 = Keypair::generate(&mut thread_rng());

        let ctx = signing_context(b"yo!");
		let msg = b"meow";
		let (out1,proof1) = keypair1.vrf(ctx.bytes(msg));
		let proof1too = keypair1.public.vrf_verify(ctx.bytes(msg), &out1, & proof1.clone().shorten())
            .expect("Correct VRF verification failed!");
        assert!( proof1 == proof1too, "VRF verification yielded incorrect batchable proof" );
		assert_eq!( keypair1.vrf(ctx.bytes(msg)).0, out1, "Rerunning VRF gave different output");
		assert!( keypair1.public.vrf_verify(ctx.bytes(b"not meow"), &out1, & proof1.clone().shorten()).is_none(), 
            "VRF verification with incorrect message passed!");

        let keypair2 = Keypair::generate(&mut thread_rng());
		assert!( keypair2.public.vrf_verify(ctx.bytes(msg), &out1, & proof1.clone().shorten()).is_none(), 
            "VRF verification with incorrect signer passed!");
        let (out2,_proof2) = keypair2.vrf(ctx.bytes(msg));

        // Verified key exchange, aaka sequential two party VRF.
        let t0 = Transcript::new(b"VRF");
		let mut out21 = out1.clone();
        let proof21 = keypair2.proove_dleqs(t0.clone(), &mut [&mut out21]);
		let mut out12 = out2.clone();
        let proof12 = keypair1.proove_dleqs(t0.clone(), &mut [&mut out12]);
        assert!( out12 == out21, "Sequential two-party VRF failed" );
        assert!( keypair1.public.verify_dleqs(t0.clone(), &[&out2], &[&out12], & proof12.shorten()).is_some() );
        assert!( keypair2.public.verify_dleqs(t0.clone(), &[&out1], &[&out21], & proof21.shorten()).is_some() );
    }

    #[test]
    fn vrfs_multi() {
        let keypairs: Vec<Keypair> = (0..4).map(|_| Keypair::generate(&mut thread_rng())).collect();

        let ctx = signing_context(b"yo!");
        let messages: [&[u8; 4]; 2] = [b"meow",b"woof"];
        let ts = || messages.iter().map(|m| ctx.bytes(*m));

        let outs_n_proofs = keypairs.iter().map(|k| {
            k.vrfs(ts())
        }).collect::<Vec<(Box<[VRFPut]>,VRFProofBatchable)>>();

        for (k,(os,p)) in keypairs.iter().zip(&outs_n_proofs) {
            let p0 = k.public.vrfs_verify(ts(), &os, & p.clone().shorten())
                .expect("Valid VRF output verification failed!");
            assert_eq!(p0, *p, "Returning batchable proof failed!");
        }
        for (k,(os,p)) in keypairs.iter().zip(&outs_n_proofs) {
            let mut os = os.clone();
            os.reverse();
            assert!(k.public.vrfs_verify(ts(), &os, & p.clone().shorten()).is_none(),
                "Incorrect VRF output verification passed!");
        }
        for (k,(os,p)) in keypairs.iter().rev().zip(&outs_n_proofs) {
            assert!(k.public.vrfs_verify(ts(), &os, & p.clone().shorten()).is_none(),
                "VRF output verification by a different signer passed!");
        }

		/*
        let kex_n_proofs = keypairs.iter().rev().zip(&outs_n_proofs).map(|(k,(os,_p))| {
            let mut os: Box<[VRFPut]>  = os.clone();
            let t0 = Transcript::new(b"VRF");
            let proof = k.proove_dleqs(t0,&mut os);
            (os, proof)
        }).collect::<Vec<(Box<[VRFPut]>,VRFProofBatchable)>>();
        assert_eq!(kex_n_proofs[0], kex_n_proofs[1], "Key exchange verification failed!");
		*/
    }
}

