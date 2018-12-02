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

use curve25519_dalek::digest::generic_array::typenum::U64;
use curve25519_dalek::digest::Digest;
// TODO use clear_on_drop::clear::Clear;

use curve25519_dalek::constants;
use curve25519_dalek::scalar::Scalar;

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
    /// presented as a hash, and optionally a chain code.
    fn derived_key_prehashed<D>(&self, h: D, cc: Option<&ChainCode>) -> (Self, ChainCode)
    where D: Digest<OutputSize = U64> + Clone;

    /// Derive key with subkey identified by a byte array
    /// and optionally a chain code.
    fn derived_key<D>(&self, i: &[u8], cc: Option<&ChainCode>) -> (Self, ChainCode)
    where D: Digest<OutputSize = U64> + Clone + Default
    {
        let mut h = D::default();
        h.input(i);
        self.derived_key_prehashed(h, cc)
    }
}

impl PublicKey {	
    /// If `i` is the "index", `c` is the chain code, and pk the public key,
    /// then we define the derived scalar to be the 512 bits `H(i ++ c ++ pk)`
    /// reduced mod l, and define the new chain code to be low 256 bits of
    /// `H(i ++ c ++ pk ++ pk)` directly.  
	/// 
	/// As a side effect, we update the digest by scaning in the chain code
	// and public key.
    fn derive_scalar_and_chaincode<D>(&self, mut h: D, cc: Option<&ChainCode>) -> (Scalar, ChainCode)
    where D: Digest<OutputSize = U64> + Clone
    {
        if let Some(cc) = cc { h.input(&cc.0); }
        h.input(& self.to_edwards_bytes());

        // No clamping in a Schnorr group
        let mut scalar = [0u8; 64];
        let r_scalar = h.clone().chain(b"key").result();
        scalar.copy_from_slice(&r_scalar.as_slice()[00..64]);

        // We used up all 64 bytes from the digest to produce a scalar
		// that reduces mod l marginally more uniformly, so now we
		// just scan the key a second time to define the chain code.  
        let r_seed = h.chain(b"chaincode").result();
        let mut chaincode = [0u8; 32];
        chaincode.copy_from_slice(&r_seed.as_slice()[00..32]); // Ignore [32..64]

        (Scalar::from_bytes_mod_order_wide(&scalar), ChainCode(chaincode))
    }
}

impl Keypair {
    /// Derive a secret key from a key pair
    ///
    ///
    ///
    /// We expect the trait methods of `Keypair as Derrivation` to be
    /// more useful since signing anything requires the public key.
    pub fn derive_secret_key_prehashed<D>(&self, mut h: D, cc: Option<&ChainCode>) -> (SecretKey, ChainCode)
    where D: Digest<OutputSize = U64> + Clone
    {
        let (scalar, chaincode) = self.public.derive_scalar_and_chaincode(h.clone(), cc);

        // We can define the nonce however we like here since it only protects
        // the signature from bad random number generators.  It need not be
        // specified by any spcification or standard. 
        if let Some(cc) = cc { h.input(&cc.0); }
        h.input(& self.secret.to_bytes() as &[u8]);
        let r = h.chain(b"nonce").result();
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&r.as_slice()[00..32]); // Ignore [32..64]

        (SecretKey {
            key: self.secret.key.clone() + scalar,
            nonce,
		}, chaincode)
    }
}

impl Derrivation for Keypair {
    fn derived_key_prehashed<D>(&self, h: D, cc: Option<&ChainCode>) -> (Keypair, ChainCode)
    where D: Digest<OutputSize = U64> + Clone,
    {
        let (secret, chaincode) = self.derive_secret_key_prehashed(h, cc);
        let public = secret.to_public();
        (Keypair { secret, public }, chaincode)
    }
}

impl Derrivation for SecretKey {
    fn derived_key_prehashed<D>(&self, h: D, cc: Option<&ChainCode>) -> (SecretKey, ChainCode)
    where
        D: Digest<OutputSize = U64> + Clone,
    {
        Keypair {
            secret: self.clone(),
            public: self.to_public(),
        }.derive_secret_key_prehashed(h, cc)
    }
}

impl Derrivation for PublicKey {
    fn derived_key_prehashed<D>(&self, h: D, cc: Option<&ChainCode>) -> (PublicKey, ChainCode)
    where D: Digest<OutputSize = U64> + Clone,
    {
        let (scalar, chaincode) = self.derive_scalar_and_chaincode(h, cc);
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
    /// Derive key with subkey identified by a byte array presented
    /// as a hash, and a chain code in the extended key.
    pub fn derived_key_prehashed<D>(&self, h: D) -> ExtendedKey<K>
    where D: Digest<OutputSize = U64> + Clone
    {
        let (key, chaincode) = self.key.derived_key_prehashed(h, Some(&self.chaincode));
        ExtendedKey { key, chaincode }
    }


    /// Derive key with subkey identified by a byte array and 
    /// a chain code in the extended key.
    pub fn derived_key<D>(&self, i: &[u8]) -> ExtendedKey<K>
    where D: Digest<OutputSize = U64> + Clone + Default
    {
        let (key, chaincode) = self.key.derived_key::<D>(i, Some(&self.chaincode));
        ExtendedKey { key, chaincode }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use sha2::{Digest, Sha512};

    #[test]
    fn public_vs_private_paths() {
        let mut rng = thread_rng();
        let chaincode = ChainCode([0u8; CHAIN_CODE_LENGTH]);
        let mut h: Sha512 = Sha512::default();
        h.input(b"Just some test message!");

        let key = Keypair::generate::<Sha512,_>(&mut rng);
        let mut extended_public_key = ExtendedKey {
            key: key.public.clone(),
            chaincode,
        };
        let mut extended_keypair = ExtendedKey { key, chaincode, };

        let context = Some(b"testing testing 1 2 3" as &[u8]);

        for i in 0..30 {
            let extended_keypair1 =
                extended_keypair.derived_key_prehashed(h.clone());
            let extended_public_key1 = extended_public_key.derived_key_prehashed(h.clone());
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
                    .sign_prehashed::<Sha512>(h.clone(), context);
                let h_bad = h.clone().chain(b"oops");
                let bad_sig = extended_keypair.key
                    .sign_prehashed::<Sha512>(h_bad.clone(), context);

                assert!(
                    extended_public_key.key
                        .verify_prehashed::<Sha512>(h.clone(), context, &good_sig),
                    "Verification of a valid signature failed!"
                );
                assert!(
                    ! extended_public_key.key
                        .verify_prehashed::<Sha512>(h.clone(), context, &bad_sig),
                    "Verification of a signature on a different message passed!"
                );
                assert!(
                    ! extended_public_key.key
                        .verify_prehashed::<Sha512>(h_bad, context, &good_sig),
                    "Verification of a signature on a different message passed!"
                );
            }
        }
    }
}
