// -*- mode: rust; -*-
//
// This file is part of schnorr-dalek.
// Copyright (c) 2017-2018 Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - jeffrey Burdges <jeff@web3.foundation>

//! Implementation of "hierarchical deterministic" key derivation for
//! Schnorr signatures compatable with the Ristretto representation of
//! ed25519.

// use curve25519_dalek::digest::generic_array::typenum::U64;
// use curve25519_dalek::digest::Digest;

use curve25519_dalek::constants;
use curve25519_dalek::scalar::Scalar;

// TODO use clear_on_drop::clear::Clear;

use sha3::Shake256;
use sha3::digest::{Input,ExtendableOutput,XofReader};
// use tiny_keccak::{Keccak,XofReader};

use super::ristretto::*;

/// Length in bytes of our chain codes.
///
/// In fact, only 16 bytes sounds safe, but this never appears on chain,
/// so no downsides to using 32 bytes.
pub const CHAIN_CODE_LENGTH: usize = 32;

/// We cannot assume the original public key is secret and additional
/// inputs might have low entropy, like `i` in BIP32.  As in BIP32,
/// chain codes fill this gap by being a high entropy secret shared
/// between public and private key holders.  These are produced by
/// key derivations and can be incorporated into subsequence key
/// derivations.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ChainCode(pub [u8; CHAIN_CODE_LENGTH]);

/// Key types that support "hierarchical deterministic" key derivation
pub trait Derrivation : Sized {
    /// Derive key with subkey identified by a byte array
    /// presented as a hash, and a chain code.
	///
	/// At present, your only valid type paramater choice might be
	/// `sha3::Shake256`, which we explain further in `lib.rs` by the
	///  `extern crate sha3;` line.  There remain sitautions where
	/// passing the hash will prove more conenienbt than managing
	/// strings however.
	fn derived_key_prehashed<D>(&self, cc: ChainCode, h: D) -> (Self, ChainCode)
	where D: Input + ExtendableOutput + Default + Clone;

    /// Derive key with subkey identified by a byte array
    /// and a chain code.  We do not include a context here
	/// becuase the chain code could serve this purpose.
	/// We support only Shake256 here for simplicity, and
	/// the reasons discussed in `lib.rs`, and 
	/// https://github.com/rust-lang/rust/issues/36887
    fn derived_key<B: AsRef<[u8]>>(&self, cc: ChainCode, i: B) -> (Self, ChainCode) {
		self.derived_key_prehashed(cc, Shake256::default().chain(i))
	}
}

impl PublicKey {
	/// Derive a mutating scalar and new chain code from a public key and chain code.
	///
    /// If `i` is the "index", `c` is the chain code, and `pk` the public key,
    /// then we compute `Shake256(i ++ c ++ pk)` and define our mutating scalar
	/// to be the 512 bits of output reduced mod l, and define the next chain
	/// code to be next 256 bits. 
    fn derive_scalar_and_chaincode<D>(&self, cc: ChainCode, h: D) -> (Scalar, ChainCode)
	where D: Input + ExtendableOutput + Default + Clone
    {
		let pk = self.to_ed25519_public_key_bytes();

		let mut r = h.chain(&cc.0).chain(&pk).xof_result();

        // We need not clamp in a Schnorr group.  We shall even use 64 bytes
		// from XOF to produce a scalar that reduces mod l marginally more
		// uniformly, so now we just scan the key a second time to define
		// the chain code. 
        let mut scalar = [0u8; 64];
		r.read(&mut scalar);

        let mut chaincode = [0u8; 32];
		r.read(&mut chaincode);

        (Scalar::from_bytes_mod_order_wide(&scalar), ChainCode(chaincode))
    }
}

impl Keypair {
    /// Derive a secret key and new chain code from a key pair and chain code.
    ///
    /// We expect the trait methods of `Keypair as Derrivation` to be
    /// more useful since signing anything requires the public key too.
    pub fn derive_secret_key<D>(&self, cc: ChainCode, h: D) -> (SecretKey, ChainCode)
	where D: Input + ExtendableOutput + Default + Clone
    {
        let (scalar, chaincode) = self.public.derive_scalar_and_chaincode(cc, h.clone());

        let mut nonce = [0u8; 32];
        // We can define the nonce however we like here since it only protects
        // the signature from bad random number generators.  It need not be
        // specified by any spcification or standard.  It must however be
		// independent from the mutating scalar and new chain code.
		//
		// If `i` were long then we could make this more efficent by hashing `i`
		// first to combine the computation with `derive_scalar_and_chaincode`, 
		// but `i` should never get too long, and this slower forumation makes
		// implementation mistakes less likely.
		h.chain(& self.secret.to_bytes() as &[u8])
		.xof_result()
		.read(&mut nonce);

        (SecretKey {
            key: self.secret.key.clone() + scalar,
            nonce,
		}, chaincode)
    }
}

impl Derrivation for Keypair {
    fn derived_key_prehashed<D>(&self, cc: ChainCode, h: D) -> (Keypair, ChainCode)
	where D: Input + ExtendableOutput + Default + Clone
    {
        let (secret, chaincode) = self.derive_secret_key(cc, h);
        let public = secret.to_public();
        (Keypair { secret, public }, chaincode)
    }
}

impl Derrivation for SecretKey {
    fn derived_key_prehashed<D>(&self, cc: ChainCode, h: D) -> (SecretKey, ChainCode)
	where D: Input + ExtendableOutput + Default + Clone
    {
        Keypair {
            secret: self.clone(),
            public: self.to_public(),
        }.derive_secret_key(cc, h)
    }
}

impl Derrivation for PublicKey {
    fn derived_key_prehashed<D>(&self, cc: ChainCode, h: D) -> (PublicKey, ChainCode)
	where D: Input + ExtendableOutput + Default + Clone
    {
        let (scalar, chaincode) = self.derive_scalar_and_chaincode(cc, h);
		let p = &scalar * &constants::RISTRETTO_BASEPOINT_TABLE;
        (PublicKey(self.0 + p), chaincode)
    }
}

/// A convenience wraper that combines derivable key and a chain code.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ExtendedKey<K> {
	/// Appropriate key type
    pub key: K,
	/// We cannot assume the original public key is secret and additional
	/// inputs might have low entropy, like `i` in BIP32.  As in BIP32,
	/// chain codes fill this gap by being a high entropy secret shared
	/// between public and private key holders.  These are produced by
	/// key derivations and can be incorporated into subsequence key
	/// derivations.  
    pub chaincode: ChainCode,
}
// TODO: Serialization

impl<K: Derrivation> ExtendedKey<K> {
    /// Derive key with subkey identified by a byte array
    /// presented as a hash, and a chain code.
	fn derived_key_prehashed<D>(&self, h: D) -> ExtendedKey<K>
	where D: Input + ExtendableOutput + Default + Clone
	{
        let (key, chaincode) = self.key.derived_key_prehashed(self.chaincode.clone(), h);
        ExtendedKey { key, chaincode }
	}

    /// Derive key with subkey identified by a byte array and 
    /// a chain code in the extended key.
    pub fn derived_key<B: AsRef<[u8]>>(&self, i: B) -> ExtendedKey<K>
    {
        let (key, chaincode) = self.key.derived_key(self.chaincode.clone(), i);
        ExtendedKey { key, chaincode }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use sha3::{Sha3_512}; // Shake256

    #[test]
    fn public_vs_private_paths() {
        let mut rng = thread_rng();
        let chaincode = ChainCode([0u8; CHAIN_CODE_LENGTH]);
        let msg : &'static [u8] = b"Just some test message!";
        let mut h = Sha3_512::default().chain(msg);

        let key = Keypair::generate::<Sha3_512,_>(&mut rng);
        let mut extended_public_key = ExtendedKey {
            key: key.public.clone(),
            chaincode,
        };
        let mut extended_keypair = ExtendedKey { key, chaincode, };

        let context = Some(b"testing testing 1 2 3" as &[u8]);

        for i in 0..30 {
            let extended_keypair1 = extended_keypair.derived_key(msg);
            let extended_public_key1 = extended_public_key.derived_key(msg);
            assert_eq!(
                extended_keypair1.chaincode, extended_public_key1.chaincode,
                "Chain code derivation failed!"
            );
            assert_eq!(
                extended_keypair1.key.public, extended_public_key1.key,
                "Public and secret key derivation missmatch!"
            );
            extended_keypair = extended_keypair1;
            extended_public_key = extended_public_key1;
            h.input(b"Another");

            if i % 5 == 0 {
                let good_sig = extended_keypair.key
                    .sign_prehashed::<Sha3_512>(h.clone(), context);
                let h_bad = h.clone().chain(b"oops");
                let bad_sig = extended_keypair.key
                    .sign_prehashed::<Sha3_512>(h_bad.clone(), context);

                assert!(
                    extended_public_key.key
                        .verify_prehashed::<Sha3_512>(h.clone(), context, &good_sig),
                    "Verification of a valid signature failed!"
                );
                assert!(
                    ! extended_public_key.key
                        .verify_prehashed::<Sha3_512>(h.clone(), context, &bad_sig),
                    "Verification of a signature on a different message passed!"
                );
                assert!(
                    ! extended_public_key.key
                        .verify_prehashed::<Sha3_512>(h_bad, context, &good_sig),
                    "Verification of a signature on a different message passed!"
                );
            }
        }
    }
}
