// -*- mode: rust; -*-
//
// This file is part of schnorrkel.
// Copyright (c) 2019 Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - jeffrey Burdges <jeff@web3.foundation>

//! Implementation for Ristretto Schnorr signatures of
//! "Simple Schnorr Multi-Signatures with Applications to Bitcoin" by
//! Gregory Maxwell, Andrew Poelstra, Yannick Seurin, and Pieter Wuille
//! https://eprint.iacr.org/2018/068
//!
//! We observe the security arguments from the
//! [original 2-round version](https://eprint.iacr.org/2018/068/20180118:124757)
//! were found lacking in
//! "On the Provable Security of Two-Round Multi-Signatures" by
//! Manu Drijvers, Kasra Edalatnejad, Bryan Ford, and Gregory Neven
//! https://eprint.iacr.org/2018/417
//! ([slides](https://rwc.iacr.org/2019/slides/neven.pdf))
//! so we implement only the
//! [3-round version](https://eprint.iacr.org/2018/068/20180520:191909).
//!
//! Appendix A of the [MuSig paper](https://eprint.iacr.org/2018/068)
//! discusses Interactive Aggregate Signatures (IAS) in which cosigners'
//! messages differ.  Appendix A.3 gives a secure scheme that correctly
//! binds signers to their messages.  See
//! https://github.com/w3f/schnorrkel/issues/5#issuecomment-477912319

// See also https://github.com/lovesh/signature-schemes/issues/2


use core::borrow::{Borrow};  // BorrowMut

#[cfg(feature = "alloc")]
use alloc::{collections::btree_map::{BTreeMap, Entry}};
#[cfg(feature = "std")]
use std::{collections::btree_map::{BTreeMap, Entry}};

use merlin::Transcript;

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{CompressedRistretto,RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

use super::*;
use crate::context::SigningTranscript;
use crate::errors::MultiSignatureStage;


// === Agagregate public keys for multi-signatures === //

/// Compute a transcript from which we may compute public key weightings.
///
/// Incorrect weightings shall occur if the iterator provided does not
/// run in the same sorted ordering as `BTreeMap::iter`/`keys`/etc.
/// We avoided a context: &'static [u8] here and in callers becuase they
/// seem irreevant to the security arguments in the MuSig paper.
#[inline(always)]
fn commit_public_keys<'a,I>(keys: I) -> Transcript
where I: Iterator<Item=&'a PublicKey>
{
    let mut t = Transcript::new(b"MuSig-aggregate-public_key");
    for pk in keys {
        t.commit_point(b"pk-set", pk.as_compressed() );
    }
    t
}

/// Computes the weighting from the transcript returnned by
/// `commit_public_keys` and a public key.
///
/// We cannot verify that the public key was ever entered into the
/// transcript, so user facing callers should check this.
fn compute_weighting(mut t: Transcript, pk: &PublicKey) -> Scalar {
    t.commit_point(b"pk-choice", pk.as_compressed() );
    t.challenge_scalar(b"")
}

/// Any data structure used for aggregating public keys.
///
/// Internally, these must usually iterate over the public keys being
/// aggregated in lexicographic order, so any `BTreeMap<PublicKey,V>`
/// works.  Alternative designs sound plausible when working with some
/// blockchain scheme.
pub trait AggregatePublicKey {
    /// Return delinearization weighting for one of many public keys being aggregated.
    fn weighting(&self, choice: &PublicKey) -> Option<Scalar>;

    /// Returns aggregated public key.
    fn public_key(&self) -> PublicKey;
}

impl<K,V> AggregatePublicKey for BTreeMap<K,V>
where K: Borrow<PublicKey>+Ord
{
    fn weighting(&self, choice: &PublicKey) -> Option<Scalar> {
        if ! self.contains_key(choice) {  return None;  }
        let t0 = commit_public_keys( self.keys().map(|pk| pk.borrow()) );
        Some(compute_weighting(t0, choice))
    }

    fn public_key(&self) -> PublicKey {
        let t0 = commit_public_keys( self.keys().map(|pk| pk.borrow()) );
        let point = self.keys().map(|pk| {
            let pk = pk.borrow();
            compute_weighting(t0.clone(), pk) * pk.as_point()
        }).sum();
        PublicKey::from_point(point)
    }
}

/// Aggregation helper for public keys kept in slices
pub struct AggregatePublicKeySlice<'a,K>(&'a [K])
where K: Borrow<PublicKey>;

/// Aggregate public keys stored in a mutable slice
pub fn aggregate_public_key_from_slice<'a>(public_keys: &'a mut [PublicKey])
 -> Option<AggregatePublicKeySlice<'a,PublicKey>>
{
    if public_keys.len() == 1 { return None; }
    public_keys.sort_unstable();
    if public_keys.windows(2).any(|x| x[0]==x[1]) { return None; }
    Some(AggregatePublicKeySlice(public_keys))
}

/// Aggregate public keys stored in a mutable slice
pub fn aggregate_public_key_from_refs_slice<'a>(public_keys: &'a mut [&'a PublicKey])
 -> Option<AggregatePublicKeySlice<'a,&'a PublicKey>>
{
    if public_keys.len() == 1 { return None; }
    public_keys.sort_unstable();
    if public_keys.windows(2).any(|x| x[0]==x[1]) { return None; }
    Some(AggregatePublicKeySlice(public_keys))
}

/// Aggregate public keys stored in a sorted slice
pub fn aggregate_public_key_from_sorted_slice<'a,K>(public_keys: &'a mut [K])
 -> Option<AggregatePublicKeySlice<'a,K>>
where K: Borrow<PublicKey>+PartialOrd<K>
{
    if public_keys.len() == 1 { return None; }
    if public_keys.windows(2).any(|x| x[0] >= x[1]) { return None; }
    Some(AggregatePublicKeySlice(public_keys))
}

impl<'a,K> AggregatePublicKey for AggregatePublicKeySlice<'a,K>
where K: Borrow<PublicKey>+PartialEq<K>
{
    fn weighting(&self, choice: &PublicKey) -> Option<Scalar> {
        if self.0.iter().any(|pk| pk.borrow() == choice) {  return None;  }
        let t0 = commit_public_keys( self.0.iter().map(|pk| pk.borrow()) );
        Some(compute_weighting(t0, choice))
    }

    fn public_key(&self) -> PublicKey {
        let t0 = commit_public_keys( self.0.iter().map(|pk| pk.borrow()) );
        let point = self.0.iter().map(|pk| {
            let pk = pk.borrow();
            compute_weighting(t0.clone(), pk) * pk.as_point()
        } ).sum();
        PublicKey::from_point(point)
    }
}


// === Multi-signature protocol === //

const COMMITMENT_SIZE : usize = 16;

/// Commitments to `R_i` values shared between cosigners during signing
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct Commitment(pub [u8; COMMITMENT_SIZE]);

impl Commitment {
    #[allow(non_snake_case)]
    fn for_R(R: &CompressedRistretto) -> Commitment {
        let mut t = Transcript::new(b"MuSig-commitment");
        t.commit_point(b"no",R);
        let mut commit = [0u8; COMMITMENT_SIZE];
        t.challenge_bytes(b"",&mut commit[..]);
        Commitment(commit)
    }
}
// TODO: serde_boilerplate!(Commitment);


#[allow(non_snake_case)]
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
enum CoR {
    Commit(Commitment),              // H(R_i)
    Reveal { R: RistrettoPoint },    // R_i
    Cosigned { s: Scalar },          // s_i extracted from Cosignature type
    Collect { R: RistrettoPoint, s: Scalar },
}

impl CoR {
    /*
    #[allow(non_snake_case)]
    fn get_R(&self) -> Option<&RistrettoPoint> {
        match self {
            CoR::Commit(_) => None,
            CoR::Reveal { R } => Some(R),
            CoR::Cosigned { .. } => None,  // panic! ???
            CoR::Collect { R, .. } => Some(R),
        }
    }

    fn get_s(&self) -> Option<&RistrettoPoint> {
        match self {
            CoR::Commit(_) => None,
            CoR::Reveal { .. } => None,
            CoR::Cosigned { s } => Some(s),
            CoR::Collect { s, .. } => Some(s),
        }
    }
    */

    #[allow(non_snake_case)]
    fn set_revealed(&mut self, R: CompressedRistretto) -> SignatureResult<()> {
        let commitment = Commitment::for_R(&R);
        let R = R.decompress().ok_or(SignatureError::PointDecompressionError) ?;
        match self.clone() {  // TODO: Remove .clone() here with #![feature(nll)]
            CoR::Collect { .. } => panic!("Internal error, set_reveal during collection phase."),
            CoR::Cosigned { .. } => panic!("Internal error, cosigning during reveal phase."),
            CoR::Commit(c_old) =>
                if c_old==commitment {  // TODO: Restore *c_old here with #![feature(nll)]
                    *self = CoR::Reveal { R };
                    Ok(())
                } else {
                    let musig_stage = MultiSignatureStage::Commitment;
                    Err(SignatureError::MuSigInconsistent { musig_stage, duplicate: false, })
                },
            CoR::Reveal { R: R_old } =>
                if R_old == R { Ok(()) } else {  // TODO: Restore *R_old here with #![feature(nll)]
                    let musig_stage = MultiSignatureStage::Reveal;
                    Err(SignatureError::MuSigInconsistent { musig_stage, duplicate: true, })
                },  // Should we have a general duplicate reveal error for this case?
        }
    }

    #[allow(non_snake_case)]
    fn set_cosigned(&mut self, s: Scalar) -> SignatureResult<()> {
        match self {
            CoR::Collect { .. } => panic!("Internal error, set_cosigned during collection phase."),
            CoR::Commit(_) => {
                    let musig_stage = MultiSignatureStage::Reveal;
                    Err(SignatureError::MuSigAbsent { musig_stage, })
                },
            CoR::Reveal { .. } => {
                    *self = CoR::Cosigned { s };
                    Ok(())
                },
            CoR::Cosigned { s: s_old } =>
                if *s_old==s { Ok(()) } else {
                    let musig_stage = MultiSignatureStage::Cosignature;
                    Err(SignatureError::MuSigInconsistent { musig_stage, duplicate: true, })
                },
        }
    }
}


/// Schnorr multi-signature (MuSig) container generic over its session types
#[allow(non_snake_case)]
pub struct MuSig<T: SigningTranscript,S> {
    t: T,
    Rs: BTreeMap<PublicKey,CoR>,
    stage: S
}

impl<T: SigningTranscript,S> MuSig<T,S> {
    /// Iterates over public keys.
    ///
    /// If `require_reveal=true` then we count only public key that revealed their `R` values.
    pub fn public_keys(&self, require_reveal: bool) -> impl Iterator<Item=&PublicKey> {
        self.Rs.iter().filter_map( move |(pk,cor)| match cor {
            CoR::Commit(_) => if require_reveal { None } else { Some(pk) },
            CoR::Reveal { .. } => Some(pk),
            CoR::Cosigned { .. } => Some(pk),
            CoR::Collect { .. } => Some(pk),
        } )
    }

    /// Aggregate public key
    ///
    /// If `require_reveal=true` then we count only public key that revealed their `R` values.
    fn compute_public_key(&self, require_reveal: bool) -> PublicKey {
        let t0 = commit_public_keys(self.public_keys(require_reveal));
        let point = self.public_keys(require_reveal).map( |pk|
            compute_weighting(t0.clone(), pk) * pk.as_point()
        ).sum();
        PublicKey::from_point(point)
    }

    /// Aggregate public key given currently revealed `R` values
    pub fn public_key(&self) -> PublicKey
        {  self.compute_public_key(true)  }

	/// Aggregate public key expected if all currently committed nodes fully participate
    pub fn expected_public_key(&self) -> PublicKey
        {  self.compute_public_key(false)  }

    /// Sums revealed `R` values.
    ///
    /// Only compatable with `compute_public_key` when calling it with `require_reveal=true`
    #[allow(non_snake_case)]
    fn compute_R(&self) -> CompressedRistretto {
        let R: RistrettoPoint = self.Rs.iter().filter_map( |(_pk,cor)| match cor {
            CoR::Commit(_) => None,
            CoR::Reveal { R } => Some(R),
            CoR::Cosigned { .. } => panic!("Internal error, compute_R called during cosigning phase."),
            CoR::Collect { R, .. } => Some(R),
        } ).sum();
        R.compress()
    }
}


/// Initial cosigning stages during which transcript modification
/// remains possible but not advisable.
pub trait TranscriptStages {}
impl<K> TranscriptStages for CommitStage<K> where K: Borrow<Keypair> {}
impl<K> TranscriptStages for RevealStage<K> where K: Borrow<Keypair> {}
impl<T,S> MuSig<T,S> 
where T: SigningTranscript, S: TranscriptStages
{
    /// We permit extending the transcript whenever you like, so
    /// that say the message may be agreed upon in parallel to the
	/// commitments.  We advise against doing so however, as this
    /// requires absolute faith in your random number generator,
	/// usually `rand::thread_rng()`.
    pub fn transcript(&mut self) -> &mut T { &mut self.t }
}

impl Keypair {
    /// Initialize a multi-signature aka cosignature protocol run.
    ///
    /// We borrow the keypair here to discurage keeping too many
    /// copies of the private key, but the `MuSig::new` method
    /// can create an owned version, or use `Rc` or `Arc`.
    #[allow(non_snake_case)]
    pub fn musig<'k,T>(&'k self, t: T) -> MuSig<T,CommitStage<&'k Keypair>>
    where T: SigningTranscript {
        MuSig::new(self,t)
    }
}

/// Commitment stage for cosigner's `R` values
#[allow(non_snake_case)]
pub struct CommitStage<K: Borrow<Keypair>> {
    keypair: K,
    r_me: Scalar,
    R_me: CompressedRistretto,
}

impl<K,T> MuSig<T,CommitStage<K>>
where K: Borrow<Keypair>, T: SigningTranscript
{
    /// Initialize a multi-signature aka cosignature protocol run.
    ///
    /// We encurage borrowing the `Keypair` to minimize copies of
    /// the private key, so we provide the `Keypair::musig` method
    /// for the `K = &'k Keypair` case.  You could use `Rc` or `Arc`
    /// with this `MuSig::new` method, or even pass in an owned copy.
    #[allow(non_snake_case)]
    pub fn new(keypair: K, t: T) -> MuSig<T,CommitStage<K>> {
        let r_me = t.witness_scalar(&[&keypair.borrow().secret.nonce]);
          // context, message, nonce, but not &self.public.compressed
        let R_me = &r_me * &constants::RISTRETTO_BASEPOINT_TABLE;

        let mut Rs = BTreeMap::new();
        Rs.insert(keypair.borrow().public, CoR::Reveal { R: R_me.clone() });

        let stage = CommitStage { keypair, r_me, R_me: R_me.compress() };
        MuSig { t, Rs, stage, }
    }

    /// Our commitment to our `R` to send to all other cosigners
    pub fn our_commitment(&self) -> Commitment {
        Commitment::for_R(&self.stage.R_me)
    }

    /// Add a new cosigner's public key and associated `R` bypassing our commitmewnt phase.
    pub fn add_their_commitment(&mut self, them: PublicKey, theirs: Commitment)
     -> SignatureResult<()>
    {
        let theirs = CoR::Commit(theirs);
        match self.Rs.entry(them) {
            Entry::Vacant(v) => { v.insert(theirs); () },
            Entry::Occupied(o) =>
                if o.get() != &theirs {
                    let musig_stage = MultiSignatureStage::Commitment;
                    return Err(SignatureError::MuSigInconsistent { musig_stage, duplicate: true, });
                },
        }
        Ok(())
    }

    /// Commit to reveal phase transition.
    #[allow(non_snake_case)]
    pub fn reveal_stage(self) -> MuSig<T,RevealStage<K>> {
        let MuSig { t, Rs, stage: CommitStage { keypair, r_me, R_me, }, } = self;
        MuSig { t, Rs, stage: RevealStage { keypair, r_me, R_me, }, }
    }
}

/// Reveal stage for cosigner's `R` values
#[allow(non_snake_case)]
pub struct RevealStage<K: Borrow<Keypair>> {
    keypair: K,
    r_me: Scalar,
    R_me: CompressedRistretto,
}

/// Revealed `R_i` values shared between cosigners during signing
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct Reveal(pub [u8; 32]);
// TODO: serde_boilerplate!(Reveal);


impl<K,T> MuSig<T,RevealStage<K>> 
where K: Borrow<Keypair>, T: SigningTranscript
{
    /// Reveal our `R` contribution to send to all other cosigners
    pub fn our_reveal(&self) -> Reveal {
        Reveal(self.stage.R_me.to_bytes())
    }

    // TODO: Permit `add_their_reveal` and `add_trusted` in `CommitStage`
    // using const generics, const fn, and replacing the `*Stage` types
    // with some enum.

    /// Include a revealed `R` value from a previously committed cosigner
    pub fn add_their_reveal(&mut self, them: PublicKey, theirs: Reveal)
     -> SignatureResult<()>
    {
        match self.Rs.entry(them) {
            Entry::Vacant(_) => {
                    let musig_stage = MultiSignatureStage::Commitment;
                    Err(SignatureError::MuSigAbsent { musig_stage, })
                },
            Entry::Occupied(mut o) => o.get_mut().set_revealed(CompressedRistretto(theirs.0))
        }
    }

    /// Add a new cosigner's public key and associated `R` bypassing our
    /// commitmewnt phase.
    ///
    /// Avoid using this due to the attack described in
    /// "On the Provable Security of Two-Round Multi-Signatures" by
    /// Manu Drijvers, Kasra Edalatnejad, Bryan Ford, and Gregory Neven
    /// https://eprint.iacr.org/2018/417
    /// Avoid using this for public keys held by networked devices
    /// in particular.
    ///
    /// There are however limited scenarios in which using this appears
    /// secure, primarily if the trusted device is (a) air gapped,
    /// (b) stateful, and (c) infrequently used, via some constrained
    /// channel like manually scanning QR code.  Almost all hardware
    /// wallets designs fail (b), but non-hardware wallets fail (a),
    /// with the middle ground being only something like Pairty Signer.
    /// Also, any public keys controlled by an organization likely
    /// fail (c) too, making this only useful for individuals.
    #[allow(non_snake_case)]
    pub fn add_trusted(&mut self, them: PublicKey, theirs: Reveal)
     -> SignatureResult<()>
    {
        let R = CompressedRistretto(theirs.0).decompress()
            .ok_or(SignatureError::PointDecompressionError) ?;
        let theirs = CoR::Reveal { R };
        match self.Rs.entry(them) {
            Entry::Vacant(v) => { v.insert(theirs); () },
            Entry::Occupied(o) =>
                if o.get() != &theirs {
                    let musig_stage = MultiSignatureStage::Reveal;
                    return Err(SignatureError::MuSigInconsistent { musig_stage, duplicate: true, });
                },
        }
        Ok(())
    }

    /// Reveal to cosign phase transition.
    #[allow(non_snake_case)]
    pub fn cosign_stage(mut self) -> MuSig<T,CosignStage> {
        self.t.proto_name(b"Schnorr-sig");

        let pk = self.public_key().as_compressed().clone();
        self.t.commit_point(b"pk",&pk);

        let R = self.compute_R();
        self.t.commit_point(b"no",&R);

        let t0 = commit_public_keys(self.public_keys(true));
        let a_me = compute_weighting(t0, &self.stage.keypair.borrow().public);
        let c = self.t.challenge_scalar(b"");  // context, message, A/public_key, R=rG
        let s_me = &(&c * &a_me * &self.stage.keypair.borrow().secret.key) + &self.stage.r_me;

        // TODO: Check assembler to see if this improves anything 
        // TODO: Replace with Zeroize but ClearOnDrop does not work with std
        #[cfg(any(feature = "std"))]
        ::clear_on_drop::clear::Clear::clear(&mut self.stage.r_me);

        let MuSig { t, mut Rs, stage: RevealStage { .. }, } = self;
        *(Rs.get_mut(&self.stage.keypair.borrow().public).expect("Rs known to contain this public; qed")) = CoR::Cosigned { s: s_me.clone() };
        MuSig { t, Rs, stage: CosignStage { R, s_me }, }
    }
}

/// Final cosigning stage  colelction
#[allow(non_snake_case)]
pub struct CosignStage {
    /// Collective `R` value
    R: CompressedRistretto,
    /// Our `s` contribution
    s_me: Scalar,
}

/// Cosignatures shared between cosigners during signing
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct Cosignature(pub [u8; 32]);

impl<T: SigningTranscript> MuSig<T,CosignStage> {
    /// Reveals our signature contribution
    pub fn our_cosignature(&self) -> Cosignature {
        Cosignature(self.stage.s_me.to_bytes())
    }

    /// Include a cosignature from another cosigner
    pub fn add_their_cosignature(&mut self, them: PublicKey, theirs: Cosignature)
     -> SignatureResult<()>
    {
        let theirs = Scalar::from_canonical_bytes(theirs.0)
            .ok_or(SignatureError::ScalarFormatError) ?;
        match self.Rs.entry(them) {
            Entry::Vacant(_) => {
                    let musig_stage = MultiSignatureStage::Reveal;
                    Err(SignatureError::MuSigAbsent { musig_stage, })
                },
            Entry::Occupied(mut o) => o.get_mut().set_cosigned(theirs)
        }
    }

    /// Interate over the cosigners who successfully revaled and
    /// later cosigned.
    pub fn cosigned(&self) -> impl Iterator<Item=&PublicKey> {
        self.Rs.iter().filter_map( |(pk,cor)| match cor {
            CoR::Commit(_) => None,
            CoR::Reveal { .. } => None,
            CoR::Cosigned { .. } => Some(pk),
            CoR::Collect { .. } => panic!("Collect found in Cosign phase.")
        } )
    }

    /// Interate over the possible cosigners who successfully committed
    /// and revaled, but actually cosigned.
    pub fn uncosigned(&self) -> impl Iterator<Item=&PublicKey> {
        self.Rs.iter().filter_map( |(pk,cor)| match cor {
            CoR::Commit(_) => None,
            CoR::Reveal { .. } => Some(pk),
            CoR::Cosigned { .. } => None,
            CoR::Collect { .. } => panic!("Collect found in Cosign phase."),
        } )
    }

    /// Actually computes the cosignature
    #[allow(non_snake_case)]
    pub fn sign(&self) -> Option<Signature> {
        // if self.uncosigned().all(|_| false) { return None; }  // TODO:  why does this fail?
        if self.uncosigned().last().is_some() { return None; }
        let s: Scalar = self.Rs.iter()
            .filter_map( |(_pk,cor)| match cor {
                CoR::Commit(_) => None,
                CoR::Reveal { .. } => panic!("Internal error, MuSig<T,CosignStage>::uncosigned broken."),
                CoR::Cosigned { s, .. } => Some(s),
                CoR::Collect { .. } => panic!("Collect found in Cosign phase."),
            } ).sum();
        Some(Signature { s, R: self.stage.R, })
    }
}


/// Initialize a collector of cosignatures who does not themselves cosign.
#[allow(non_snake_case)]
pub fn collect_cosignatures<T: SigningTranscript>(mut t: T) -> MuSig<T,CollectStage> {
    t.proto_name(b"Schnorr-sig");
    MuSig { t, Rs: BTreeMap::new(), stage: CollectStage, }
}

/// Initial stage for cosignature collectors who do not themselves cosign.
pub struct CollectStage;

impl<T: SigningTranscript> MuSig<T,CollectStage> {
    /// Adds revealed `R` and cosignature into a cosignature collector
    #[allow(non_snake_case)]
    pub fn add(&mut self, them: PublicKey, their_reveal: Reveal, their_cosignature: Cosignature)
     -> SignatureResult<()>
    {
        let R = CompressedRistretto(their_reveal.0).decompress()
            .ok_or(SignatureError::PointDecompressionError) ?;
        let s = Scalar::from_canonical_bytes(their_cosignature.0)
            .ok_or(SignatureError::ScalarFormatError) ?;
        let cor = CoR::Collect { R, s };

        match self.Rs.entry(them) {
            Entry::Vacant(v) => { v.insert(cor); () },
            Entry::Occupied(o) =>
                if o.get() != &cor {
                    let musig_stage = MultiSignatureStage::Reveal;
                    return Err(SignatureError::MuSigInconsistent { musig_stage, duplicate: true, });
                },
        }
        Ok(())
    }

    /// Actually computes the collected cosignature.
    #[allow(non_snake_case)]
    pub fn signature(&self) -> Signature {
        let R = self.compute_R();
        let s: Scalar = self.Rs.iter()
            .map( |(_pk,cor)| match cor {
                CoR::Collect { s, .. } => s,
                _ => panic!("Reached CollectStage from another stage"),
            } ).sum();
        Signature { s, R, }
    }
}


#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;
    #[cfg(feature = "std")]
    use std::vec::Vec;

    use rand::prelude::*;
    use super::*;

    #[test]
    fn aggregation_btreeemap_vs_slice() {
        let mut csprng = thread_rng();
        let mut vec: Vec<PublicKey> = (0..16).map(|_| SecretKey::generate(&mut csprng).to_public()).collect();
        let btm: BTreeMap<PublicKey,()> = vec.iter().map( |x| (x.clone(),()) ).collect();
        debug_assert_eq!(
            btm.public_key(),
            aggregate_public_key_from_slice(vec.as_mut_slice()).unwrap().public_key()
        );
        // NLL aggregate_public_key_from_sorted_slice
    }

    #[test]
    fn multi_signature() {
        let mut csprng = thread_rng();
        let keypairs: Vec<Keypair> = (0..16).map(|_| Keypair::generate(&mut csprng)).collect();

        let t = signing_context(b"multi-sig").bytes(b"We are legion!");
        let mut commits: Vec<_> = keypairs.iter().map( |k| k.musig(t.clone()) ).collect();
        for i in 0..commits.len() {
        let r = commits[i].our_commitment();
            for j in commits.iter_mut() {
                assert!( j.add_their_commitment(keypairs[i].public.clone(),r)
                    .is_ok() != (r == j.our_commitment()) );
            }
        }

        let mut reveal_msgs: Vec<Reveal> = Vec::with_capacity(commits.len());
        let mut reveals: Vec<_> = commits.drain(..).map( |c| c.reveal_stage() ).collect();
        for i in 0..reveals.len() {
            let r = reveals[i].our_reveal();
            for j in reveals.iter_mut() {
                j.add_their_reveal(keypairs[i].public.clone(),r).unwrap();
            }
            reveal_msgs.push(r);
        }
        let pk = reveals[0].public_key();

        let mut cosign_msgs: Vec<Cosignature> = Vec::with_capacity(reveals.len());
        let mut cosigns: Vec<_> = reveals.drain(..).map( |c| { assert_eq!(pk, c.public_key()); c.cosign_stage() } ).collect();
        for i in 0..cosigns.len() {
            assert_eq!(pk, cosigns[i].public_key());
            let r = cosigns[i].our_cosignature();
            for j in cosigns.iter_mut() {
                j.add_their_cosignature(keypairs[i].public.clone(),r).unwrap();
            }
            cosign_msgs.push(r);
            assert_eq!(pk, cosigns[i].public_key());
        }

        // let signature = cosigns[0].sign().unwrap();
        let mut c = collect_cosignatures(t.clone());
        for i in 0..cosigns.len() {
            c.add(keypairs[i].public.clone(),reveal_msgs[i].clone(),cosign_msgs[i].clone()).unwrap();
        }
        let signature = c.signature();

        assert!( pk.verify(t,&signature).is_ok() );
        for i in 0..cosigns.len() {
            assert_eq!(pk, cosigns[i].public_key());
            assert_eq!(signature, cosigns[i].sign().unwrap());
        }
    }
}
