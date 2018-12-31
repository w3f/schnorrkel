// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2018 Isis Lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>

//! ed25519 signatures and verification
//!
//! # Example
//!
//! Creating an ed25519 signature on a message is simple.
//!
//! First, we need to generate a `Keypair`, which includes both public and
//! secret halves of an asymmetric key.  To do so, we need a cryptographically
//! secure pseudorandom number generator (CSPRNG), and a hash function which
//! has 512 bits of output.  For this example, we'll use the operating
//! system's builtin PRNG and SHA-512 to generate a keypair:
//!
//! ```
//! extern crate rand;
//! extern crate schnorr_dalek;
//!
//! # #[cfg(all(feature = "std"))]
//! # fn main() {
//! use rand::Rng;
//! use rand::OsRng;
//! use schnorr_dalek::Keypair;
//! use schnorr_dalek::Signature;
//!
//! let mut csprng: OsRng = OsRng::new().unwrap();
//! let keypair: Keypair = Keypair::generate(&mut csprng);
//! # }
//! #
//! # #[cfg(any(not(feature = "std")))]
//! # fn main() { }
//! ```
//!
//! We can now use this `keypair` to sign a message:
//!
//! ```
//! # extern crate rand;
//! # extern crate rand_chacha;
//! # extern crate sha3;
//! # extern crate schnorr_dalek;
//! # fn main() {
//! # use rand::{SeedableRng}; // Rng
//! # use rand_chacha::ChaChaRng;
//! # use sha3::Shake128;
//! # use schnorr_dalek::{Keypair,Signature,signing_context};
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate(&mut csprng);
//! let context = signing_context(b"this signature does this thing");
//! let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! let signature: Signature = keypair.sign(context.bytes(message));
//! # }
//! ```
//!
//! As well as to verify that this is, indeed, a valid signature on
//! that `message`:
//!
//! ```
//! # extern crate rand;
//! # extern crate rand_chacha;
//! # extern crate sha3;
//! # extern crate schnorr_dalek;
//! # fn main() {
//! # use rand::{SeedableRng}; // Rng
//! # use rand_chacha::ChaChaRng;
//! # use sha3::Shake128;
//! # use schnorr_dalek::{Keypair,Signature,signing_context};
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate(&mut csprng);
//! # let context = signing_context(b"this signature does this thing");
//! # let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let signature: Signature = keypair.sign(context.bytes(message));
//! assert!(keypair.verify(context.bytes(message), &signature));
//! # }
//! ```
//!
//! Anyone else, given the `public` half of the `keypair` can also easily
//! verify this signature:
//!
//! ```
//! # extern crate rand;
//! # extern crate rand_chacha;
//! # extern crate sha3;
//! # extern crate schnorr_dalek;
//! # fn main() {
//! # use rand::{SeedableRng}; // Rng
//! # use rand_chacha::ChaChaRng;
//! # use sha3::Shake128;
//! # use schnorr_dalek::{Keypair,Signature,signing_context};
//! use schnorr_dalek::PublicKey;
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate(&mut csprng);
//! # let context = signing_context(b"this signature does this thing");
//! # let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let signature: Signature = keypair.sign(context.bytes(message));
//! let public_key: PublicKey = keypair.public;
//! assert!(public_key.verify(context.bytes(message), &signature));
//! # }
//! ```
//!
//! ## Serialisation
//!
//! `PublicKey`s, `MiniSecretKey`s, `Keypair`s, and `Signature`s can be serialised
//! into byte-arrays by calling `.to_bytes()`.  It's perfectly acceptible and
//! safe to transfer and/or store those bytes.  (Of course, never transfer your
//! secret key to anyone else, since they will only need the public key to
//! verify your signatures!)
//!
//! ```
//! # extern crate rand;
//! # extern crate rand_chacha;
//! # extern crate sha3;
//! # extern crate schnorr_dalek;
//! # fn main() {
//! # use rand::{Rng, SeedableRng};
//! # use rand_chacha::ChaChaRng;
//! # use sha3::Shake128;
//! # use schnorr_dalek::{Keypair, Signature, PublicKey, signing_context};
//! use schnorr_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, KEYPAIR_LENGTH, SIGNATURE_LENGTH};
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate(&mut csprng);
//! # let context = signing_context(b"this signature does this thing");
//! # let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let signature: Signature = keypair.sign(context.bytes(message));
//! # let public_key: PublicKey = keypair.public;
//!
//! let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = public_key.to_bytes();
//! let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = keypair.secret.to_bytes();
//! let keypair_bytes:    [u8; KEYPAIR_LENGTH]    = keypair.to_bytes();
//! let signature_bytes:  [u8; SIGNATURE_LENGTH]  = signature.to_bytes();
//! # }
//! ```
//!
//! And similarly, decoded from bytes with `::from_bytes()`:
//!
//! ```
//! # extern crate rand;
//! # extern crate rand_chacha;
//! # extern crate sha3;
//! # extern crate schnorr_dalek;
//! # use rand::{Rng, SeedableRng};
//! # use rand_chacha::ChaChaRng;
//! # use sha3::Shake128;
//! # use schnorr_dalek::{SecretKey, Keypair, Signature, PublicKey, SignatureError, signing_context};
//! # use schnorr_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, KEYPAIR_LENGTH, SIGNATURE_LENGTH};
//! # fn do_test() -> Result<(SecretKey, PublicKey, Keypair, Signature), SignatureError> {
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair_orig: Keypair = Keypair::generate(&mut csprng);
//! # let context = signing_context(b"this signature does this thing");
//! # let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let signature_orig: Signature = keypair_orig.sign(context.bytes(message));
//! # let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = keypair_orig.public.to_bytes();
//! # let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = keypair_orig.secret.to_bytes();
//! # let keypair_bytes:    [u8; KEYPAIR_LENGTH]    = keypair_orig.to_bytes();
//! # let signature_bytes:  [u8; SIGNATURE_LENGTH]  = signature_orig.to_bytes();
//! #
//! let public_key: PublicKey = PublicKey::from_bytes(&public_key_bytes)?;
//! let secret_key: SecretKey = SecretKey::from_bytes(&secret_key_bytes)?;
//! let keypair:    Keypair   = Keypair::from_bytes(&keypair_bytes)?;
//! let signature:  Signature = Signature::from_bytes(&signature_bytes)?;
//! #
//! # Ok((secret_key, public_key, keypair, signature))
//! # }
//! # fn main() {
//! #     do_test();
//! # }
//! ```
//!
//! ### Using Serde
//!
//! If you prefer the bytes to be wrapped in another serialisation format, all
//! types additionally come with built-in [serde](https://serde.rs) support by
//! building `ed25519-dalek` via:
//!
//! ```bash
//! $ cargo build --features="serde"
//! ```
//!
//! They can be then serialised into any of the wire formats which serde supports.
//! For example, using [bincode](https://github.com/TyOverby/bincode):
//!
//! ```
//! # extern crate rand;
//! # extern crate rand_chacha;
//! # extern crate sha3;
//! # extern crate schnorr_dalek;
//! # #[cfg(feature = "serde")]
//! extern crate serde;
//! # #[cfg(feature = "serde")]
//! extern crate bincode;
//!
//! # #[cfg(feature = "serde")]
//! # fn main() {
//! # use rand::{Rng, SeedableRng};
//! # use rand_chacha::ChaChaRng;
//! # use sha3::Shake128;
//! # use schnorr_dalek::{Keypair, Signature, PublicKey, signing_context};
//! use bincode::{serialize, Infinite};
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate(&mut csprng);
//! # let context = signing_context(b"this signature does this thing");
//! # let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let signature: Signature = keypair.sign(context.bytes(message));
//! # let public_key: PublicKey = keypair.public;
//! # let verified: bool = public_key.verify(context.bytes(message), &signature);
//!
//! let encoded_public_key: Vec<u8> = serialize(&public_key, Infinite).unwrap();
//! let encoded_signature: Vec<u8> = serialize(&signature, Infinite).unwrap();
//! # }
//! # #[cfg(not(feature = "serde"))]
//! # fn main() {}
//! ```
//!
//! After sending the `encoded_public_key` and `encoded_signature`, the
//! recipient may deserialise them and verify:
//!
//! ```
//! # extern crate rand;
//! # extern crate rand_chacha;
//! # extern crate sha2;
//! # extern crate schnorr_dalek;
//! # #[cfg(feature = "serde")]
//! # extern crate serde;
//! # #[cfg(feature = "serde")]
//! # extern crate bincode;
//! #
//! # #[cfg(feature = "serde")]
//! # fn main() {
//! # use rand::{Rng, SeedableRng};
//! # use rand_chacha::ChaChaRng;
//! # use sha2::Sha512;
//! # use schnorr_dalek::{Keypair, Signature, PublicKey};
//! # use bincode::{serialize, Infinite};
//! use bincode::{deserialize};
//!
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate(&mut csprng);
//! let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let context = signing_context(b"this signature does this thing");
//! # let signature: Signature = keypair.sign(context.bytes(message));
//! # let public_key: PublicKey = keypair.public;
//! # let verified: bool = public_key.verify(context.bytes(message), &signature);
//! # let encoded_public_key: Vec<u8> = serialize(&public_key, Infinite).unwrap();
//! # let encoded_signature: Vec<u8> = serialize(&signature, Infinite).unwrap();
//! let decoded_public_key: PublicKey = deserialize(&encoded_public_key).unwrap();
//! let decoded_signature: Signature = deserialize(&encoded_signature).unwrap();
//!
//! # assert_eq!(public_key, decoded_public_key);
//! # assert_eq!(signature, decoded_signature);
//! #
//! let verified: bool = decoded_public_key.verify(context.bytes(message), &decoded_signature);
//!
//! assert!(verified);
//! # }
//! # #[cfg(not(feature = "serde"))]
//! # fn main() {}
//! ```

#![no_std]
#![allow(unused_features)]
#![deny(missing_docs)] // refuse to compile if documentation is missing

extern crate curve25519_dalek;
extern crate merlin;

extern crate failure;
extern crate rand;
extern crate clear_on_drop;
extern crate subtle;

// We shall prefer Shake256 for several reasons: 
//
// First, we're nolonger tied to specific bit patterns like Ed25519,
// so some scalars could be obtained by reducing 64 bytes mod l,
// which sounds marginally better.  As a result, we often want like
// 96 bytes of hash output, which makes XOFs useful.
//
// Second, Shake256 should be resistant to extension attacks without
// using HMAC constructions.  And RustCrypto's HMAC machenery is too
// ugly to foist on developers.
//
// Third, Shake256 is only marginally slower than Sha2_256.  We could
// choose KangarooTwelve by the Keccek team if we wanted raw speed, but
// this involved understanding if it retains the resistance to length
// extension attacks.  https://keccak.team/2017/is_sha3_slow.html
//
// Fourth, the strobe-rs crate, and thus the merlin crate use only Keccek.
// I do not yet understand the STROBE framework well enough, but using
// Shake256 may make switching to STROBE easier.
//
// I still think the RustCrypto traits suck, but tiny_keccak's intereface
// is not better, merely simpler.
extern crate sha3;
// extern crate tiny_keccak;

extern crate ed25519_dalek;

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(any(test, feature = "sha2"))]
extern crate sha2;

#[cfg(test)]
extern crate hex;

#[cfg(test)]
extern crate rand_chacha;

#[cfg(feature = "serde")]
extern crate serde;

#[cfg(all(test, feature = "serde"))]
extern crate bincode;

mod util;

pub mod keys;  // 
pub mod sign;
pub mod derive;
pub mod cert;
pub mod errors;

pub use keys::*; // {MiniSecretKey,SecretKey,PublicKey,Keypair}; + *_LENGTH
pub use sign::{Signature,SIGNATURE_LENGTH,signing_context,verify_batch}; // SigningContext
pub use errors::SignatureError;
