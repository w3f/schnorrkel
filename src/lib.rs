// -*- mode: rust; -*-
//
// This file is part of schnorrkel.
// Copyright (c) 2017-2019 Isis Lovecruft and Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>
// - Jeffrey Burdges <jeff@web3.foundation>

//! Schnorr signature variants using Ristretto point compression.
//!
//! # Example
//!
//! Creating a signature on a message is simple.
//!
//! First, we need to generate a `Keypair`, which includes both public and
//! secret halves of an asymmetric key.  To do so, we need a cryptographically
//! secure pseudorandom number generator (CSPRNG).
//!
//! ```
//! # #[cfg(all(feature = "std"))]
//! # fn main() {
//! use rand::{Rng, rngs::OsRng};
//! use schnorrkel::{Keypair,Signature};
//!
//! let keypair: Keypair = Keypair::generate_with(OsRng);
//! # }
//! #
//! # #[cfg(any(not(feature = "std")))]
//! # fn main() { }
//! ```
//!
//! We can now use this `keypair` to sign a message:
//!
//! ```
//! # fn main() {
//! # use rand::{SeedableRng}; // Rng
//! # use rand_chacha::ChaChaRng;
//! # use schnorrkel::{Keypair,Signature,signing_context};
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate_with(&mut csprng);
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
//! # fn main() {
//! # use rand::{SeedableRng}; // Rng
//! # use rand_chacha::ChaChaRng;
//! # use schnorrkel::{Keypair,Signature,signing_context};
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate_with(&mut csprng);
//! # let context = signing_context(b"this signature does this thing");
//! # let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let signature: Signature = keypair.sign(context.bytes(message));
//! assert!(keypair.verify(context.bytes(message), &signature).is_ok());
//! # }
//! ```
//!
//! Anyone else, given the `public` half of the `keypair` can also easily
//! verify this signature:
//!
//! ```
//! # fn main() {
//! # use rand::{SeedableRng}; // Rng
//! # use rand_chacha::ChaChaRng;
//! # use schnorrkel::{Keypair,Signature,signing_context};
//! use schnorrkel::PublicKey;
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate_with(&mut csprng);
//! # let context = signing_context(b"this signature does this thing");
//! # let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let signature: Signature = keypair.sign(context.bytes(message));
//! let public_key: PublicKey = keypair.public;
//! assert!(public_key.verify(context.bytes(message), &signature).is_ok());
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
//! # fn main() {
//! # use rand::{Rng, SeedableRng};
//! # use rand_chacha::ChaChaRng;
//! # use schnorrkel::{Keypair, Signature, PublicKey, signing_context};
//! use schnorrkel::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, KEYPAIR_LENGTH, SIGNATURE_LENGTH};
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate_with(&mut csprng);
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
//! # use rand::{Rng, SeedableRng};
//! # use rand_chacha::ChaChaRng;
//! # use schnorrkel::{SecretKey, Keypair, Signature, PublicKey, SignatureError, signing_context};
//! # use schnorrkel::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, KEYPAIR_LENGTH, SIGNATURE_LENGTH};
//! # fn do_test() -> Result<(SecretKey, PublicKey, Keypair, Signature), SignatureError> {
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair_orig: Keypair = Keypair::generate_with(&mut csprng);
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
//! building `schnorrkell` via:
//!
//! ```bash
//! $ cargo build --features="serde"
//! ```
//!
//! They can be then serialised into any of the wire formats which serde supports.
//! For example, using [bincode](https://github.com/TyOverby/bincode):
//!
//! ```
//! # #[cfg(feature = "serde")]
//! # fn main() {
//! # use rand::{Rng, SeedableRng};
//! # use rand_chacha::ChaChaRng;
//! # use schnorrkel::{Keypair, Signature, PublicKey, signing_context};
//! use bincode::{serialize};
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate_with(&mut csprng);
//! # let context = signing_context(b"this signature does this thing");
//! # let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let signature: Signature = keypair.sign(context.bytes(message));
//! # let public_key: PublicKey = keypair.public;
//! # assert!( public_key.verify(context.bytes(message), &signature).is_ok() );
//!
//! let encoded_public_key: Vec<u8> = serialize(&public_key).unwrap();
//! let encoded_signature: Vec<u8> = serialize(&signature).unwrap();
//! # }
//! # #[cfg(not(feature = "serde"))]
//! # fn main() {}
//! ```
//!
//! After sending the `encoded_public_key` and `encoded_signature`, the
//! recipient may deserialise them and verify:
//!
//! ```
//! # #[cfg(feature = "serde")]
//! # fn main() {
//! # use rand::{Rng, SeedableRng};
//! # use rand_chacha::ChaChaRng;
//! # use schnorrkel::{Keypair, Signature, PublicKey, signing_context};
//! # use bincode::{serialize};
//! use bincode::{deserialize};
//!
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate_with(&mut csprng);
//! let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let context = signing_context(b"this signature does this thing");
//! # let signature: Signature = keypair.sign(context.bytes(message));
//! # let public_key: PublicKey = keypair.public;
//! # let encoded_public_key: Vec<u8> = serialize(&public_key).unwrap();
//! # let encoded_signature: Vec<u8> = serialize(&signature).unwrap();
//! let decoded_public_key: PublicKey = deserialize(&encoded_public_key).unwrap();
//! let decoded_signature: Signature = deserialize(&encoded_signature).unwrap();
//!
//! # assert_eq!(public_key, decoded_public_key);
//! # assert_eq!(signature, decoded_signature);
//! #
//! assert!( public_key.verify(context.bytes(message), &signature).is_ok() );
//! # }
//! # #[cfg(not(feature = "serde"))]
//! # fn main() {}
//! ```

#![no_std]
#![warn(future_incompatible)]
#![warn(rust_2018_compatibility)]
#![warn(rust_2018_idioms)]
#![deny(missing_docs)] // refuse to compile if documentation is missing

#[cfg(any(feature = "std"))]
#[macro_use]
extern crate std;

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

use rand_core::{RngCore,CryptoRng};

#[cfg(all(feature = "getrandom", feature = "rand"))] 
fn rand_hack() -> impl RngCore+CryptoRng {
    ::rand::thread_rng()
}

#[cfg(all(feature = "getrandom", not(feature = "rand")))] 
fn rand_hack() -> impl RngCore+CryptoRng {
    ::rand_core::OsRng
}

#[cfg(not(feature = "getrandom"))]
fn rand_hack() -> impl RngCore+CryptoRng {
    const PRM : &'static str = "Attempted to use functionality that requires system randomness!!";

    struct PanicRng;
    impl ::rand_core::RngCore for PanicRng {
        fn next_u32(&mut self) -> u32 {  panic!(&PRM)  }
        fn next_u64(&mut self) -> u64 {  panic!(&PRM)  }
        fn fill_bytes(&mut self, _dest: &mut [u8]) {  panic!(&PRM)  }
        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), ::rand_core::Error> {  panic!(&PRM)  }
    }
    impl ::rand_core::CryptoRng for PanicRng {}

    PanicRng
}

#[macro_use]
extern crate arrayref;

#[macro_use]
mod serdey;

pub mod points;
mod scalars;
pub mod keys;

pub mod context;
pub mod sign;
pub mod vrf;
pub mod derive;
pub mod cert;
pub mod errors;

#[cfg(feature = "aead")]
pub mod aead;

#[cfg(any(feature = "alloc", feature = "std"))]
mod batch;

// Not safe because need randomness  #[cfg(any(feature = "alloc", feature = "std"))]
#[cfg(feature = "std")]
pub mod musig;

pub use crate::keys::*; // {MiniSecretKey,SecretKey,PublicKey,Keypair,ExpansionMode}; + *_LENGTH
pub use crate::context::{signing_context}; // SigningContext,SigningTranscript
pub use crate::sign::{Signature,SIGNATURE_LENGTH};
pub use crate::errors::{SignatureError,SignatureResult};

#[cfg(any(feature = "alloc", feature = "std"))]
pub use crate::batch::{verify_batch,verify_batch_rng,verify_batch_deterministic};
