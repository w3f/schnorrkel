// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2018 Isis Lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>
// - Jeff Burdges <jeff@web3.foundation>

//! Schnorr signatures on the 2-tortsion free subgroup of ed25519,
//! as provided by the Ristretto point compression.

use core::default::Default;
use core::fmt::{Debug};

use rand::{CryptoRng,Rng};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};
#[cfg(feature = "serde")]
use serde::{Serializer, Deserializer};
#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;

#[cfg(feature = "sha2")]
use sha2::Sha512;

use clear_on_drop::clear::Clear;

use curve25519_dalek::digest;
use curve25519_dalek::digest::{Input,FixedOutput,ExtendableOutput,XofReader};
use curve25519_dalek::digest::generic_array::typenum::U64;

use curve25519_dalek::constants;
use curve25519_dalek::edwards::{CompressedEdwardsY}; // EdwardsPoint
use curve25519_dalek::ristretto::{CompressedRistretto,RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

use subtle::{Choice,ConstantTimeEq};

use context::{SigningContext,signing_context};
use util;
use errors::SignatureError;

/// The length of a curve25519 EdDSA `Signature`, in bytes.
pub const SIGNATURE_LENGTH: usize = 64;

/// The length of a curve25519 EdDSA `MiniSecretKey`, in bytes.
pub const MINI_SECRET_KEY_LENGTH: usize = 32;

/// The length of an ed25519 EdDSA `PublicKey`, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// The length of the "key" portion of an "expanded" curve25519 EdDSA secret key, in bytes.
const SECRET_KEY_KEY_LENGTH: usize = 32;

/// The length of the "nonce" portion of an "expanded" curve25519 EdDSA secret key, in bytes.
const SECRET_KEY_NONCE_LENGTH: usize = 32;

/// The length of an "expanded" curve25519 EdDSA key, `SecretKey`, in bytes.
pub const SECRET_KEY_LENGTH: usize = SECRET_KEY_KEY_LENGTH + SECRET_KEY_NONCE_LENGTH;

/// The length of an ed25519 EdDSA `Keypair`, in bytes.
pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

type Ed25519Signature = [u8; ::ed25519_dalek::SIGNATURE_LENGTH];

/// A Ristretto Schnorr signature "detached" from the signed message.
///
/// These cannot be converted to any Ed25519 signature because they hash
/// curve points in the Ristretto encoding.
#[allow(non_snake_case)]
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct Signature {
    /// `R` is an `EdwardsPoint`, formed by using an hash function with
    /// 512-bits output to produce the digest of:
    ///
    /// - the nonce half of the `SecretKey`, and
    /// - the message to be signed.
    ///
    /// This digest is then interpreted as a `Scalar` and reduced into an
    /// element in ℤ/lℤ.  The scalar is then multiplied by the distinguished
    /// basepoint to produce `R`, and `EdwardsPoint`.
    pub (crate) R: CompressedRistretto,

    /// `s` is a `Scalar`, formed by using an hash function with 512-bits output
    /// to produce the digest of:
    ///
    /// - the `r` portion of this `Signature`,
    /// - the `PublicKey` which should be used to verify this `Signature`, and
    /// - the message to be signed.
    ///
    /// This digest is then interpreted as a `Scalar` and reduced into an
    /// element in ℤ/lℤ.
    pub (crate) s: Scalar,
}

impl Debug for Signature {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "Signature( R: {:?}, s: {:?} )", &self.R, &self.s)
    }
}

impl Signature {
    /// Convert this `Signature` to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        let mut signature_bytes: [u8; SIGNATURE_LENGTH] = [0u8; SIGNATURE_LENGTH];

        signature_bytes[..32].copy_from_slice(&self.R.as_bytes()[..]);
        signature_bytes[32..].copy_from_slice(&self.s.as_bytes()[..]);
        signature_bytes
    }

    /// Construct a `Signature` from a slice of bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, SignatureError> {
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(SignatureError::BytesLengthError{
                name: "Signature", length: SIGNATURE_LENGTH });
        }
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        lower.copy_from_slice(&bytes[..32]);
        upper.copy_from_slice(&bytes[32..]);

        // TODO: We could pass this check but exceed l, so maybe we should
        // reduce and error if the result change?
        if upper[31] & 224 != 0 {
            return Err(SignatureError::ScalarFormatError);
        }

        Ok(Signature{ R: CompressedRistretto(lower), s: Scalar::from_bits(upper) })
    }
}

#[cfg(feature = "serde")]
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'d> {
        struct SignatureVisitor;

        impl<'d> Visitor<'d> for SignatureVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("An ed25519 signature as 64 bytes, as specified in RFC8032.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Signature, E> where E: SerdeError{
                Ok(Signature::from_bytes(bytes) ?)
                // REMOVE .or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(SignatureVisitor)
    }
}

/// An EdDSA compatabile "secret" key seed.
///
/// These are seeds from which we produce a real `SecretKey`, which
/// EdDSA itself calls an extended secret key by hashing.  We require
/// homomorphic properties unavailable from these seeds, so we renamed
/// these and reserve `SecretKey` for what EdDSA calls an extended
/// secret key.
#[repr(C)]
#[derive(Default,Clone)] // we derive Default in order to use the clear() method in Drop
pub struct MiniSecretKey(pub (crate) [u8; MINI_SECRET_KEY_LENGTH]);

impl Debug for MiniSecretKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "MiniSecretKey: {:?}", &self.0[..])
    }
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for MiniSecretKey {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl Eq for MiniSecretKey {}
impl PartialEq for MiniSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}
impl ConstantTimeEq for MiniSecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl MiniSecretKey {
    /// Expand this `MiniSecretKey` into a `SecretKey`.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate sha2;
    /// # extern crate schnorr_dalek;
    /// #
    /// # #[cfg(all(feature = "std", feature = "sha2"))]
    /// # fn main() {
    /// #
    /// use rand::{Rng, OsRng};
    /// use sha2::Sha512;
    /// use schnorr_dalek::{MiniSecretKey, SecretKey};
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let mini_secret_key: MiniSecretKey = MiniSecretKey::generate(&mut csprng);
    /// let secret_key: SecretKey = mini_secret_key.expand::<Sha512>();
    /// # }
    /// #
    /// # #[cfg(any(not(feature = "sha2"), not(feature = "std")))]
    /// # fn main() { }
    /// ```
    pub fn expand<D>(&self) -> SecretKey
    where D: Input + FixedOutput<OutputSize = U64> + Default + Clone
    {
        let mut h: D = D::default();
        h.input(self.as_bytes());
        let r = h.fixed_result();

        // We need not clamp in a Schnorr group like Ristretto, but here
        // we do so to improve Ed25519 comparability.  
        let mut key = [0u8; 32];
        key.copy_from_slice(&r.as_slice()[0..32]);
        key[0]  &= 248;
        key[31] &=  63;
        key[31] |=  64;
        // We then devide by the cofactor to internally keep a clean
        // representation mod l.
        util::divide_scalar_bytes_by_cofactor(&mut key);
        let key = Scalar::from_bits(key);

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&r.as_slice()[32..64]);

        SecretKey{ key, nonce }
    }

    /// Derive the `PublicKey` corresponding to this `MiniSecretKey`.
    pub fn expand_to_keypair<D>(&self) -> Keypair
    where D: Input + FixedOutput<OutputSize = U64> + Default + Clone
    {
        self.expand::<D>().into()
    }

    /// Derive the `PublicKey` corresponding to this `MiniSecretKey`.
    pub fn expand_to_public<D>(&self) -> PublicKey
    where D: Input + FixedOutput<OutputSize = U64> + Default + Clone
    {
        self.expand::<D>().to_public()
    }

    /// Convert this secret key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; MINI_SECRET_KEY_LENGTH] {
        self.0
    }

    /// View this secret key as a byte array.
    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; MINI_SECRET_KEY_LENGTH] {
        &self.0
    }

    /// Construct a `MiniSecretKey` from a slice of bytes.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate schnorr_dalek;
    /// #
    /// use schnorr_dalek::MiniSecretKey;
    /// use schnorr_dalek::MINI_SECRET_KEY_LENGTH;
    /// use schnorr_dalek::SignatureError;
    ///
    /// # fn doctest() -> Result<MiniSecretKey, SignatureError> {
    /// let secret_key_bytes: [u8; MINI_SECRET_KEY_LENGTH] = [
    ///    157, 097, 177, 157, 239, 253, 090, 096,
    ///    186, 132, 074, 244, 146, 236, 044, 196,
    ///    068, 073, 197, 105, 123, 050, 105, 025,
    ///    112, 059, 172, 003, 028, 174, 127, 096, ];
    ///
    /// let secret_key: MiniSecretKey = MiniSecretKey::from_bytes(&secret_key_bytes)?;
    /// #
    /// # Ok(secret_key)
    /// # }
    /// #
    /// # fn main() {
    /// #     let result = doctest();
    /// #     assert!(result.is_ok());
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an EdDSA `MiniSecretKey` or whose error value
    /// is an `SignatureError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<MiniSecretKey, SignatureError> {
        if bytes.len() != MINI_SECRET_KEY_LENGTH {
            return Err(SignatureError::BytesLengthError{
                name: "MiniSecretKey", length: MINI_SECRET_KEY_LENGTH });
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);
        Ok(MiniSecretKey(bits))
    }

    /// Generate a `MiniSecretKey` from a `csprng`.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate rand;
    /// extern crate sha2;
    /// extern crate schnorr_dalek;
    ///
    /// # #[cfg(feature = "std")]
    /// # fn main() {
    /// #
    /// use rand::Rng;
    /// use rand::OsRng;
    /// use sha2::Sha512;
    /// use schnorr_dalek::PublicKey;
    /// use schnorr_dalek::MiniSecretKey;
    /// use schnorr_dalek::Signature;
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let secret_key: MiniSecretKey = MiniSecretKey::generate(&mut csprng);
    /// # }
    /// #
    /// # #[cfg(not(feature = "std"))]
    /// # fn main() { }
    /// ```
    ///
    /// Afterwards, you can generate the corresponding public—provided you also
    /// supply a hash function which implements the `FixedOutput` and `Default`
    /// traits, and which returns 512 bits of output—via:
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate sha2;
    /// # extern crate schnorr_dalek;
    /// #
    /// # fn main() {
    /// #
    /// # use rand::Rng;
    /// # use rand::ChaChaRng;
    /// # use rand::SeedableRng;
    /// # use sha2::Sha512;
    /// # use schnorr_dalek::PublicKey;
    /// # use schnorr_dalek::MiniSecretKey;
    /// # use schnorr_dalek::Signature;
    /// #
    /// # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
    /// # let secret_key: MiniSecretKey = MiniSecretKey::generate(&mut csprng);
    ///
    /// let public_key: PublicKey = secret_key.expand_to_public::<Sha512>();
    /// # }
    /// ```
    ///
    /// The standard hash function used for most ed25519 libraries is SHA-512,
    /// which is available with `use sha2::Sha512` as in the example above.
    /// Other suitable hash functions include Keccak-512 and Blake2b-512.
    ///
    /// # Input
    ///
    /// A CSPRNG with a `fill_bytes()` method, e.g. `rand::ChaChaRng`
    pub fn generate<R>(csprng: &mut R) -> MiniSecretKey
    where R: CryptoRng + Rng,
    {
        let mut sk: MiniSecretKey = MiniSecretKey([0u8; 32]);
        csprng.fill_bytes(&mut sk.0);
        sk
    }
}

#[cfg(feature = "serde")]
impl Serialize for MiniSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_bytes(self.as_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for MiniSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'d> {
        struct MiniSecretKeyVisitor;

        impl<'d> Visitor<'d> for MiniSecretKeyVisitor {
            type Value = MiniSecretKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("An ed25519 secret key as 32 bytes, as specified in RFC8032.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<MiniSecretKey, E> where E: SerdeError {
                Ok(MiniSecretKey::from_bytes(bytes) ?)
            }
        }
        deserializer.deserialize_bytes(MiniSecretKeyVisitor)
    }
}


/// A seceret key for use with Ristretto Schnorr signatures.
///
/// Internally, these consist of a scalar mod l along with a seed for
/// nonce generation.  In this way, we ensure all scalar arithmatic
/// works smoothly in operations like threshold or multi-signatures,
/// or hierarchical deterministic key derivations.
///
/// We keep our secret key serializaion "almost" compatable with EdDSA
/// "expanded" secret key serializaion by multiplying the scalar by the
/// cofactor 8, as integers, and dividing on deserializaion.
/// We do not however attempt to keep the scalar's high bit set, especially
/// not during hierarchical deterministic key derivations, so some Ed25519
/// libraries might compute the public key incorrectly from our secret key.
#[repr(C)]
#[derive(Default,Clone)] // we derive Default in order to use the clear() method in Drop
pub struct SecretKey {
    /// Actual public key represented as a scalar.
    pub (crate) key: Scalar,
    /// Seed for deriving the nonces used in signing.
    ///
    /// We require this be random and secret or else key compromise attacks will ensue.
    /// Any modificaiton here may dirupt some non-public key derivation techniques.
    pub (crate) nonce: [u8; 32],
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "SecretKey {{ key: {:?} nonce: {:?} }}", &self.key, &self.nonce)
    }
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.key.clear();
        self.nonce.clear();
    }
}

impl Eq for SecretKey {}
impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}
impl ConstantTimeEq for SecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.key.ct_eq(&other.key)
    }
}

#[cfg(feature = "sha2")]
impl<'a> From<&'a MiniSecretKey> for SecretKey {
    /// Construct an `SecretKey` from a `MiniSecretKey`.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate sha2;
    /// # extern crate schnorr_dalek;
    /// #
    /// # #[cfg(all(feature = "std", feature = "sha2"))]
    /// # fn main() {
    /// #
    /// use rand::{Rng, OsRng};
    /// use sha2::Sha512;
    /// use schnorr_dalek::{MiniSecretKey, SecretKey};
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let mini_secret_key: MiniSecretKey = MiniSecretKey::generate(&mut csprng);
    /// let secret_key: SecretKey = SecretKey::from(&mini_secret_key);
    /// # }
    /// #
    /// # #[cfg(any(not(feature = "std"), not(feature = "sha2")))]
    /// # fn main() {}
    /// ```
    fn from(msk: &'a MiniSecretKey) -> SecretKey {
        msk.expand::<Sha512>()
    }
}

impl SecretKey {
    /// Convert this `SecretKey` into an array of 64 bytes, corresponding to
    /// an Ed25519 expanded secreyt key.
    ///
    /// # Returns
    ///
    /// An array of 64 bytes.  The first 32 bytes represent the "expanded"
    /// secret key, and the last 32 bytes represent the "domain-separation"
    /// "nonce".
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate sha2;
    /// # extern crate schnorr_dalek;
    /// #
    /// # #[cfg(all(feature = "sha2", feature = "std"))]
    /// # fn main() {
    /// #
    /// use rand::{Rng, OsRng};
    /// use sha2::Sha512;
    /// use schnorr_dalek::{MiniSecretKey, SecretKey};
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let mini_secret_key: MiniSecretKey = MiniSecretKey::generate(&mut csprng);
    /// let secret_key: SecretKey = SecretKey::from(&mini_secret_key);
    /// let secret_key_bytes: [u8; 64] = secret_key.to_bytes();
    ///
    /// assert!(&secret_key_bytes[..] != &[0u8; 64][..]);
    /// # }
    /// #
    /// # #[cfg(any(not(feature = "sha2"), not(feature = "std")))]
    /// # fn main() { }
    /// ```
    #[inline]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        let mut bytes: [u8; 64] = [0u8; 64];
        let mut key = self.key.to_bytes();
        // We multiply by the cofactor to improve ed25519 compatability,
        // while our internally using a scalar mod l.
        util::multiply_scalar_bytes_by_cofactor(&mut key);
        bytes[..32].copy_from_slice(&key[..]);
        bytes[32..].copy_from_slice(&self.nonce[..]);
        bytes
    }

    /// Convert this `SecretKey` into Ed25519 expanded secreyt key.
    pub fn to_ed25519_expanded_secret_key(&self) -> ::ed25519_dalek::ExpandedSecretKey {
		::ed25519_dalek::ExpandedSecretKey::from_bytes(&self.to_bytes()[..])
		.expect("Improper serialisation of Ed25519 secret key!")
    }

    /// Construct an `SecretKey` from a slice of bytes.
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an EdDSA `SecretKey` or whose
    /// error value is an `SignatureError` describing the error that occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate sha2;
    /// # extern crate schnorr_dalek;
    /// #
    /// # #[cfg(all(feature = "sha2", feature = "std"))]
    /// # fn do_test() -> Result<SecretKey, SignatureError> {
    /// #
    /// use rand::{Rng, OsRng};
    /// use schnorr_dalek::{MiniSecretKey, SecretKey};
    /// use schnorr_dalek::SignatureError;
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let mini_secret_key: MiniSecretKey = MiniSecretKey::generate(&mut csprng);
    /// let secret_key: SecretKey = SecretKey::from(&mini_secret_key);
    /// let bytes: [u8; 64] = secret_key.to_bytes();
    /// let secret_key_again = SecretKey::from_bytes(&bytes)?;
    /// #
    /// # Ok(secret_key_again)
    /// # }
    /// #
    /// # #[cfg(all(feature = "sha2", feature = "std"))]
    /// # fn main() {
    /// #     let result = do_test();
    /// #     assert!(result.is_ok());
    /// # }
    /// #
    /// # #[cfg(any(not(feature = "sha2"), not(feature = "std")))]
    /// # fn main() { }
    /// ```
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, SignatureError> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(SignatureError::BytesLengthError{
                name: "SecretKey", length: SECRET_KEY_LENGTH });
        }

        let mut key: [u8; 32] = [0u8; 32];
        key.copy_from_slice(&bytes[00..32]);
        // TODO:  We should consider making sure the scalar is valid,
        // maybe by zering the high bit, orp referably by checking < l.
        // key[31] &= 0b0111_1111;
        // We devide by the cofactor to internally keep a clean
        // representation mod l.
        util::divide_scalar_bytes_by_cofactor(&mut key);

        let mut nonce: [u8; 32] = [0u8; 32];
        nonce.copy_from_slice(&bytes[32..64]);

        Ok(SecretKey{
            key: Scalar::from_bits(key),
            nonce,  
        })
    }

    /// Generate an "unbiased" `SecretKey` directly, bypassing the
    /// `MiniSecretKey` Ed25519 compatability layer.
    ///
    /// As we generate a `SecretKey` directly bypassing `MiniSecretKey`,
    /// so our secret keys do not satisfy the high bit "clamping"
    /// impoised on Ed25519 keys.
    pub fn generate<R>(csprng: &mut R) -> SecretKey
    where R: CryptoRng + Rng,
    {
        let mut key: [u8; 64] = [0u8; 64];
        csprng.fill_bytes(&mut key);
        let mut nonce: [u8; 32] = [0u8; 32];
        csprng.fill_bytes(&mut nonce);
        SecretKey { key: Scalar::from_bytes_mod_order_wide(&key), nonce }
    }

    /// Derive the `PublicKey` corresponding to this `SecretKey`.
    pub fn to_public(&self) -> PublicKey {
        // No clamping in a Schnorr group
        PublicKey(&self.key * &constants::RISTRETTO_BASEPOINT_TABLE)
        // let pk = &self.key * &constants::RISTRETTO_BASEPOINT_TABLE;
        // CompressedPublicKey(CompressedRistretto(pk.compress().to_bytes()))
    }

    /// Sign a message with this `SecretKey` using the old Ed25519
	/// algorithm.
	///
	/// Incurs a public key comression cost which Ed25519 normally avoids,
	/// making the `ed25519-dalek` crate faster.
    #[allow(non_snake_case)]
    pub fn sign_ed25519<D>(&self, message: &[u8], public_key: &PublicKey) -> Ed25519Signature
    where D: digest::Digest<OutputSize = U64> + Default
	{
		let public_key = public_key.to_ed25519_public_key();
		self.to_ed25519_expanded_secret_key()
		.sign::<D>(message,&public_key).to_bytes()
	}

    /// Sign a `prehashed_message` with this `SecretKey` using the
    /// Ed25519ph algorithm defined in [RFC8032 §5.1][rfc8032].
	///
	/// Incurs a public key comression cost which Ed25519ph normally avoids,
	/// making the `ed25519-dalek` crate faster.
	///
    /// [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
    #[allow(non_snake_case)]
    pub fn sign_ed25519_prehashed<D>(
        &self,
        prehashed_message: D,
        public_key: &PublicKey,
        context: Option<&'static [u8]>,
    ) -> Ed25519Signature
    where D: digest::Digest<OutputSize = U64> + Default + Clone,
    {
		let public_key = public_key.to_ed25519_public_key();
		self.to_ed25519_expanded_secret_key()
		.sign_prehashed::<D>(prehashed_message,&public_key,context).to_bytes()
	}

    /// Sign a message with this `SecretKey`.
    #[allow(non_snake_case)]
    pub fn sign<C>(&self, context: &C, message: &[u8], public_key: &PublicKey) -> Signature
    where C: SigningContext,
	      C::Digest: ExtendableOutput
    {
        let R: CompressedRistretto;
        let r: Scalar;
        let s: Scalar;
        let k: Scalar;

        r = util::scalar_from_xof(
            context.nonce_randomness()
            .chain(&self.nonce)
            .chain(&message)
        );
        R = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();

        k = util::scalar_from_xof(
            context.context_digest()
            .chain(R.as_bytes())
            .chain(& public_key.to_ed25519_public_key_bytes())
            .chain(&message)
        );
        s = &(&k * &self.key) + &r;

        Signature{ R, s }
    }

    /// Sign a `prehashed_message` with this `SecretKey` using the
    /// Ed25519ph algorithm defined in [RFC8032 §5.1][rfc8032].
    ///
    /// # Inputs
    ///
    /// * `prehashed_message` is an instantiated hash digest with 512-bits of
    ///   output which has had the message to be signed previously fed into its
    ///   state.
    /// * `public_key` is a [`PublicKey`] which corresponds to this secret key.
    /// * `context` is an optional context string, up to 255 bytes inclusive,
    ///   which may be used to provide additional domain separation.  If not
    ///   set, this will default to an empty string.
    ///
    /// # Returns
    ///
    /// An Ed25519ph [`Signature`] on the `prehashed_message`.
    ///
    /// [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
    #[allow(non_snake_case)]
    pub fn sign_prehashed<C>(
        &self,
        context: &C,
        prehashed_message: C::Digest,
        public_key: &PublicKey,
    ) -> Signature
    where C: SigningContext,
	      C::Digest: ExtendableOutput
    {
        // Get the result of the pre-hashed message.
        let mut prehash = [0u8; 64];
        prehashed_message.xof_result().read(&mut prehash);

        self.sign::<C>(context,&prehash,public_key)
    }
}

#[cfg(feature = "serde")]
impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'d> {
        struct SecretKeyVisitor;

        impl<'d> Visitor<'d> for SecretKeyVisitor {
            type Value = SecretKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("An ed25519 expanded secret key as 64 bytes, as specified in RFC8032.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<SecretKey, E> where E: SerdeError {
                Ok(SecretKey::from_bytes(bytes) ?)
                // REMOVE .or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(SecretKeyVisitor)
    }
}


/// A Ristretto Schnorr public key.
/// 
/// Internally, these are represented as a `RistrettoPoint`, meaning
/// an Edwards point with a static guarantee to be 2-torsion free. 
///
/// At present, we decompress `PublicKey`s into this representation
/// during deserialization, which improves error handling, but costs
/// a compression during signing and verifiaction.
#[derive(Copy, Clone, Default, Eq, PartialEq)]
#[repr(C)]
pub struct PublicKey(pub (crate) RistrettoPoint);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "PublicKey( RistrettoPoint( {:?} ))", self.0.compress())
    }
}

impl PublicKey {
    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.compress().to_bytes()
    }

    /// Construct a `PublicKey` from a slice of bytes.
    ///
    /// # Warning
    ///
    /// The caller is responsible for ensuring that the bytes passed into this
    /// method actually represent a `curve25519_dalek::ristretto::CompressedRistretto`
    /// and that said compressed point is actually a point on the curve.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate schnorr_dalek;
    /// #
    /// use schnorr_dalek::PublicKey;
    /// use schnorr_dalek::PUBLIC_KEY_LENGTH;
    /// use schnorr_dalek::SignatureError;
    ///
    /// # fn doctest() -> Result<PublicKey, SignatureError> {
    /// let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = [
    ///    215,  90, 152,   1, 130, 177,  10, 183, 213,  75, 254, 211, 201, 100,   7,  58,
    ///     14, 225, 114, 243, 218, 166,  35,  37, 175,   2,  26, 104, 247,   7,   81, 26];
    ///
    /// let public_key = PublicKey::from_bytes(&public_key_bytes)?;
    /// #
    /// # Ok(public_key)
    /// # }
    /// #
    /// # fn main() {
    /// #     doctest();
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an EdDSA `PublicKey` or whose error value
    /// is an `SignatureError` describing the error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, SignatureError> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(SignatureError::BytesLengthError{
                name: "PublicKey", length: PUBLIC_KEY_LENGTH });
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);
        Ok(PublicKey(
            CompressedRistretto(bits).decompress()
            .ok_or(SignatureError::PointDecompressionError) ?
        ))
        // Ok(CompressedPublicKey::from_bytes(bytes)?.compress()?)
    }

    /// A serialized Ed25519 public key compatable with our serialization
    /// of the corresponding `SecretKey`.  
    /// 
    /// We multiply by the cofactor 8 here because we multiply our
    /// scalars by the cofactor 8 in serialization as well.  In this way,
    /// our serializations remain somewhat ed25519 compatable, except for  
    /// clamping, but internally we only operate on honest scalars
    /// represented mod l, and thus avoid spooky cofactor bugs.
    pub fn to_ed25519_public_key_bytes(&self) -> [u8; 32] {
        util::ristretto_to_edwards(self.0).mul_by_cofactor().compress().to_bytes()
    }

    /// An Ed25519 public key compatable with our serialization of
    /// the corresponding `SecretKey`.  
    pub fn to_ed25519_public_key(&self) -> ::ed25519_dalek::PublicKey {
		let pkb = self.to_ed25519_public_key_bytes();
		::ed25519_dalek::PublicKey::from_bytes(&pkb[..])
		.expect("Improper serialisation of Ed25519 public key!")
	}	

    /// Deserialized an Ed25519 public key compatable with our serialization
    /// of the corresponding `SecretKey`. 
    /// 
    /// Avoid using this function.  It is necessarily painfully slow and
    /// will make you look bad.  Instead, communitate and use only Ristretto
    /// public keys, and convert to ed25519 keys as required.
    pub fn from_ed25519_public_key_bytes(bytes: &[u8]) -> Result<PublicKey, SignatureError> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(SignatureError::BytesLengthError{
                name: "PublicKey", length: PUBLIC_KEY_LENGTH });
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        let p = CompressedEdwardsY(bits).decompress().ok_or(SignatureError::PointDecompressionError) ?;
        if ! p.is_torsion_free() {
            return Err(SignatureError::PointDecompressionError);
        }
		let eighth = Scalar::from(8u8).invert();
		debug_assert_eq!(Scalar::one(), eighth * Scalar::from(8u8));
        Ok(PublicKey(util::edwards_to_ristretto(&eighth * p)))
		// debug_assert_eq!(bytes,p.to_ed25519_public_key_bytes());
    }

    /// Verify a signature on a message with this public key.
    ///
	/// Incurs a public key comression cost which Ed25519 normally avoids,
	/// making the `ed25519-dalek` crate faster.
    #[allow(non_snake_case)]
    pub fn verify_ed25519<D>(&self, message: &[u8], signature: &Ed25519Signature) -> bool
    where D: digest::Digest<OutputSize = U64> + Default
	{
		::ed25519_dalek::Signature::from_bytes(&signature[..])
		.and_then(|s| self.to_ed25519_public_key().verify::<D>(message,&s)).is_ok()
	}

    /// Verify a `signature` on a `prehashed_message` using the
    /// Ed25519ph algorithm defined in [RFC8032 §5.1][rfc8032].
	///
	/// Incurs a public key comression cost which Ed25519ph normally avoids,
	/// making the `ed25519-dalek` crate faster.
	///
    /// [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
    #[allow(non_snake_case)]
    pub fn verify_ed25519_prehashed<D>(
        &self,
        prehashed_message: D,
        context: Option<&[u8]>,
        signature: &Ed25519Signature
    ) -> bool
    where D: digest::Digest<OutputSize = U64> + Default
    {
		::ed25519_dalek::Signature::from_bytes(&signature[..])
		.and_then(|s| self.to_ed25519_public_key().verify_prehashed::<D>(prehashed_message,context,&s)).is_ok()
	}

    /// Verify a signature on a message with this public key.
    ///
    /// # Return
    ///
    /// Returns `Ok(())` if the signature is valid, and `Err` otherwise.
    #[allow(non_snake_case)]
    pub fn verify<C>(&self, context: &C, message: &[u8], signature: &Signature) -> bool
    where C: SigningContext,
	      C::Digest: ExtendableOutput
    {
        let A: RistrettoPoint = self.0;
        let R: RistrettoPoint;
        let k: Scalar;

        k = util::scalar_from_xof(
            context.context_digest()
            .chain(signature.R.as_bytes())
            .chain(& self.to_ed25519_public_key_bytes())
            .chain(&message)
        );
        R = RistrettoPoint::vartime_double_scalar_mul_basepoint(&k, &(-A), &signature.s);

        R.compress() == signature.R
    }

    /// Verify a `signature` on a `prehashed_message` using the Ed25519ph algorithm.
    ///
    /// # Inputs
    ///
    /// * `prehashed_message` is an instantiated hash digest with 512-bits of
    ///   output which has had the message to be signed previously fed into its
    ///   state.
    /// * `context` is an optional context string, up to 255 bytes inclusive,
    ///   which may be used to provide additional domain separation.  If not
    ///   set, this will default to an empty string.
    /// * `signature` is a purported Ed25519ph [`Signature`] on the `prehashed_message`.
    ///
    /// # Returns
    ///
    /// Returns `true` if the `signature` was a valid signature created by this
    /// `Keypair` on the `prehashed_message`.
    ///
    /// [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
    #[allow(non_snake_case)]
    pub fn verify_prehashed<C>(
	    &self,
	    context: &C,
	    prehashed_message: C::Digest,
	    signature: &Signature
	) -> bool
    where C: SigningContext, 
	      C::Digest: ExtendableOutput
    {
        // Get the result of the pre-hashed message.
        let mut prehash = [0u8; 64];
        prehashed_message.xof_result().read(&mut prehash);

        self.verify::<C>(context,&prehash,signature)
    }
}

impl From<SecretKey> for PublicKey {
    fn from(source: SecretKey) -> PublicKey {
        source.to_public()
    }
}


#[cfg(feature = "serde")]
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_bytes(self.0.compress().as_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'d> {

        struct PublicKeyVisitor;

        impl<'d> Visitor<'d> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("An ed25519 public key as a 32-byte compressed point, as specified in RFC8032")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<PublicKey, E> where E: SerdeError {
                Ok(PublicKey::from_bytes(bytes) ?)
                /*
                REMOVE
                if bytes.len() != PUBLIC_KEY_LENGTH {
                    return Err(SerdeError::invalid_length(bytes.len(), &self));
                }
                let mut bits: [u8; 32] = [0u8; 32];
                bits.copy_from_slice(&bytes[..32]);
                Ok(PublicKey(  
                    CompressedRistretto(bits).decompress()
                    .or(Err(SerdeError::custom("Ristretto point decompression failed")))?
                ))
                */
            }
        }
        deserializer.deserialize_bytes(PublicKeyVisitor)
    }
}


/// Verify a batch of `signatures` on `messages` with their respective `public_keys`.
///
/// # Inputs
///
/// * `messages` is a slice of byte slices, one per signed message.
/// * `signatures` is a slice of `Signature`s.
/// * `public_keys` is a slice of `PublicKey`s.
/// * `csprng` is an implementation of `Rng + CryptoRng`, such as `rand::ThreadRng`.
///
/// # Panics
///
/// This function will panic if the `messages, `signatures`, and `public_keys`
/// slices are not equal length.
///
/// # Returns
///
/// * A `Result` whose `Ok` value is an emtpy tuple and whose `Err` value is a
///   `SignatureError` containing a description of the internal error which
///   occured.
///
/// # Examples
///
/// ```
/// extern crate schnorr_dalek;
/// extern crate rand;
/// extern crate sha3;
///
/// use schnorr_dalek::context::signing_context;
/// use schnorr_dalek::{Keypair,PublicKey,Signature,verify_batch};
/// use rand::thread_rng;
/// use rand::ThreadRng;
/// use sha3::Shake128;
///
/// # fn main() {
/// let ctx = signing_context::<Shake128>(b"some batch");
/// let mut csprng: ThreadRng = thread_rng();
/// let keypairs: Vec<Keypair> = (0..64).map(|_| Keypair::generate(&mut csprng)).collect();
/// let msg: &[u8] = b"They're good dogs Brant";
/// let messages: Vec<&[u8]> = (0..64).map(|_| msg).collect();
/// let signatures:  Vec<Signature> = keypairs.iter().map(|key| key.sign(&ctx,&msg)).collect();
/// let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
///
/// assert!( verify_batch(&ctx, &messages[..], &signatures[..], &public_keys[..]) );
/// # }
/// ```
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(non_snake_case)]
pub fn verify_batch<C>(
	context: &C,
	messages: &[&[u8]],
	signatures: &[Signature],
	public_keys: &[PublicKey]
) -> bool
where C: SigningContext,
      C::Digest: ExtendableOutput
{
    const ASSERT_MESSAGE: &'static [u8] = b"The number of messages, signatures, and public keys must be equal.";
    assert!(signatures.len()  == messages.len(),    ASSERT_MESSAGE);
    assert!(signatures.len()  == public_keys.len(), ASSERT_MESSAGE);
    assert!(public_keys.len() == messages.len(),    ASSERT_MESSAGE);
 
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;
    #[cfg(feature = "std")]
    use std::vec::Vec;

    use core::iter::once;
    use rand::thread_rng;

    use curve25519_dalek::traits::IsIdentity;
    use curve25519_dalek::traits::VartimeMultiscalarMul;

    // Select a random 128-bit scalar for each signature.
    let zs: Vec<Scalar> = signatures.iter()
        .map(|_| Scalar::from(thread_rng().gen::<u128>()))
        .collect();

    // Compute the basepoint coefficient, ∑ s[i]z[i] (mod l)
    let B_coefficient: Scalar = signatures.iter()
        .map(|sig| sig.s)
        .zip(zs.iter())
        .map(|(s, z)| z * s)
        .sum();

    // Compute H(R || A || M) for each (signature, public_key, message) triplet
    let hrams = (0..signatures.len()).map(|i| {
        util::scalar_from_xof(
            context.context_digest()
            .chain(signatures[i].R.as_bytes())
            .chain(& public_keys[i].to_ed25519_public_key_bytes())
            .chain(&messages[i])
        )
    });

    // Multiply each H(R || A || M) by the random value
    let zhrams = hrams.zip(zs.iter()).map(|(hram, z)| hram * z);

    let Rs = signatures.iter().map(|sig| sig.R.decompress());
    let As = public_keys.iter().map(|pk| Some(pk.0));  // TODO batch decompress()?
    let B = once(Some(constants::RISTRETTO_BASEPOINT_POINT));

    // Compute (-∑ z[i]s[i] (mod l)) B + ∑ z[i]R[i] + ∑ (z[i]H(R||A||M)[i] (mod l)) A[i] = 0
    RistrettoPoint::optional_multiscalar_mul(
        once(-B_coefficient).chain(zs.iter().cloned()).chain(zhrams),
        B.chain(Rs).chain(As),
    ).map(|id| id.is_identity()).unwrap_or(false)
    // We need not return SigenatureError::PointDecompressionError because
    // the decompression failures occur for R represent invalid signatures.
}


/// An ed25519 keypair.
#[derive(Debug, Default)] // we derive Default in order to use the clear() method in Drop
#[repr(C)]
pub struct Keypair {
    /// The secret half of this keypair.
    pub secret: SecretKey,
    /// The public half of this keypair.
    pub public: PublicKey,
}

impl From<SecretKey> for Keypair {
    fn from(secret: SecretKey) -> Keypair {
        let public = secret.to_public();
        Keypair{ secret, public }
    }
}

impl Keypair {
    /// Convert this keypair to bytes.
    ///
    /// # Returns
    ///
    /// An array of bytes, `[u8; KEYPAIR_LENGTH]`.  The first
    /// `MINI_SECRET_KEY_LENGTH` of bytes is the `MiniSecretKey`, and the next
    /// `PUBLIC_KEY_LENGTH` bytes is the `PublicKey` (the same as other
    /// libraries, such as [Adam Langley's ed25519 Golang
    /// implementation](https://github.com/agl/ed25519/)).
    pub fn to_bytes(&self) -> [u8; KEYPAIR_LENGTH] {
        let mut bytes: [u8; KEYPAIR_LENGTH] = [0u8; KEYPAIR_LENGTH];

        bytes[..SECRET_KEY_LENGTH].copy_from_slice(& self.secret.to_bytes());
        bytes[SECRET_KEY_LENGTH..].copy_from_slice(& self.public.to_bytes());
        bytes
    }

    /// Construct a `Keypair` from the bytes of a `PublicKey` and `MiniSecretKey`.
    ///
    /// # Inputs
    ///
    /// * `bytes`: an `&[u8]` representing the scalar for the secret key, and a
    ///   compressed Ristretto point, both as bytes.
    ///   (As obtained from `Keypair::to_bytes()`.)
    ///
    /// # Warning
    ///
    /// Absolutely no validation is done on the key.  If you give this function
    /// bytes which do not represent a valid point, or which do not represent
    /// corresponding parts of the key, then your `Keypair` will be broken and
    /// it will be your fault.
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an EdDSA `Keypair` or whose error value
    /// is an `SignatureError` describing the error that occurred.
    pub fn from_bytes<'a>(bytes: &'a [u8]) -> Result<Keypair, SignatureError> {
        if bytes.len() != KEYPAIR_LENGTH {
            return Err(SignatureError::BytesLengthError{
                name: "Keypair", length: KEYPAIR_LENGTH});
        }
        let secret = SecretKey::from_bytes(&bytes[..SECRET_KEY_LENGTH])?;
        let public = PublicKey::from_bytes(&bytes[SECRET_KEY_LENGTH..])?;

        Ok(Keypair{ secret: secret, public: public })
    }

    /// Generate a Ristretto Schnorr keypair.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate rand;
    /// extern crate schnorr_dalek;
    ///
    /// # fn main() {
    ///
    /// use rand::Rng;
    /// use rand::OsRng;
    /// use schnorr_dalek::Keypair;
    /// use schnorr_dalek::Signature;
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let keypair: Keypair = Keypair::generate(&mut csprng);
    ///
    /// # }
    /// ```
    ///
    /// # Input
    ///
    /// A CSPRNG with a `fill_bytes()` method, e.g. `rand::ChaChaRng`.
    /// 
    /// We generate a `SecretKey` directly bypassing `MiniSecretKey`,
    /// so our secret keys do not satisfy the high bit "clamping"
    /// impoised on Ed25519 keys.
    pub fn generate<R>(csprng: &mut R) -> Keypair
    where R: CryptoRng + Rng,
    {
        let secret: SecretKey = SecretKey::generate(csprng);
        let public: PublicKey = secret.to_public();

        Keypair{ public, secret }
    }

    /// Sign a message with this `SecretKey` using ed25519.
    #[allow(non_snake_case)]
    pub fn sign_ed25519<D>(&self, message: &[u8]) -> Ed25519Signature
    where D: digest::Digest<OutputSize = U64> + Default
	{
		self.secret.sign_ed25519::<D>(message, &self.public)
	}

    /// Sign a `prehashed_message` with this `SecretKey` using the
    /// Ed25519ph algorithm defined in [RFC8032 §5.1][rfc8032].
    #[allow(non_snake_case)]
    pub fn sign_ed25519_prehashed<D>(
        &self,
        prehashed_message: D,
        context: Option<&'static [u8]>,
    ) -> Ed25519Signature
    where D: digest::Digest<OutputSize = U64> + Default + Clone,
    {
        self.secret.sign_ed25519_prehashed::<D>(prehashed_message, &self.public, context)
	}

    /// Verify a signature on a message with this public key.
    ///
	/// Incurs a public key comression cost which Ed25519 normally avoids,
	/// making the `ed25519-dalek` crate faster.
    #[allow(non_snake_case)]
    pub fn verify_ed25519<D>(&self, message: &[u8], signature: &Ed25519Signature) -> bool
    where D: digest::Digest<OutputSize = U64> + Default
	{
        self.public.verify_ed25519::<D>(message,signature)
	}

    /// Verify a `signature` on a `prehashed_message` using the
    /// Ed25519ph algorithm defined in [RFC8032 §5.1][rfc8032].
	///
	/// Incurs a public key comression cost which Ed25519ph normally avoids,
	/// making the `ed25519-dalek` crate faster.
	///
    /// [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
    #[allow(non_snake_case)]
    #[allow(non_snake_case)]
    pub fn verify_ed25519_prehashed<D>(
        &self,
        prehashed_message: D,
        context: Option<&[u8]>,
        signature: &Ed25519Signature
    ) -> bool
    where D: digest::Digest<OutputSize = U64> + Default
    {
		self.public.verify_ed25519_prehashed::<D>(prehashed_message,context,signature)
	}


    /// Sign a message with this keypair's secret key.
    pub fn sign<C>(&self, context: &C, message: &[u8]) -> Signature
    where C: SigningContext,
          C::Digest: ExtendableOutput
    {
        self.secret.sign::<C>(context, &message, &self.public)
    }

    /// Sign a `prehashed_message` with this `Keypair` using the
    /// Ed25519ph algorithm defined in [RFC8032 §5.1][rfc8032].
    ///
    /// # Inputs
    ///
    /// * `prehashed_message` is an instantiated hash digest with 512-bits of
    ///   output which has had the message to be signed previously fed into its
    ///   state.
    /// * `context` is an optional context string, up to 255 bytes inclusive,
    ///   which may be used to provide additional domain separation.  If not
    ///   set, this will default to an empty string.
    ///
    /// # Returns
    ///
    /// An Ed25519ph [`Signature`] on the `prehashed_message`.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate schnorr_dalek;
    /// extern crate rand;
    /// extern crate sha3;
    ///
    /// use schnorr_dalek::Keypair;
    /// use schnorr_dalek::Signature;
    /// use rand::thread_rng;
    /// use rand::ThreadRng;
    /// # use sha3::Shake128;
    ///
    /// # #[cfg(all(feature = "std", feature = "sha2"))]
    /// # fn main() {
    /// let mut csprng: ThreadRng = thread_rng();
    /// let keypair: Keypair = Keypair::generate(&mut csprng);
    /// let message: &[u8] = b"All I want is to pet all of the dogs.";
    ///
    /// // Create a hash digest object which we'll feed the message into:
    /// let prehashed = Shake128::default();
    /// prehashed.input(message);
    /// # }
    /// #
    /// # #[cfg(any(not(feature = "sha2"), not(feature = "std")))]
    /// # fn main() { }
    /// ```
    ///
    /// If you want, you can optionally pass a "context".  It is generally a
    /// good idea to choose a context and try to make it unique to your project
    /// and this specific usage of signatures.
    ///
    /// For example, without this, if you were to [convert your OpenPGP key
    /// to a Bitcoin key][terrible_idea] (just as an example, and also Don't
    /// Ever Do That) and someone tricked you into signing an "email" which was
    /// actually a Bitcoin transaction moving all your magic internet money to
    /// their address, it'd be a valid transaction.
    ///
    /// By adding a context, this trick becomes impossible, because the context
    /// is concatenated into the hash, which is then signed.  So, going with the
    /// previous example, if your bitcoin wallet used a context of
    /// "BitcoinWalletAppTxnSigning" and OpenPGP used a context (this is likely
    /// the least of their safety problems) of "GPGsCryptoIsntConstantTimeLol",
    /// then the signatures produced by both could never match the other, even
    /// if they signed the exact same message with the same key.
    ///
    /// Let's add a context for good measure (remember, you'll want to choose
    /// your own!):
    ///
    /// ```
    /// # extern crate schnorr_dalek;
    /// # extern crate rand;
    /// # extern crate sha3;
    /// #
    /// # use schnorr_dalek::{Keypair,Signature};
    /// # use schnorr_dalek::context::signing_context;
    /// # use rand::thread_rng;
    /// # use rand::ThreadRng;
    /// # use sha3::Shake128;
    /// #
    /// # #[cfg(all(feature = "std", feature = "sha2"))]
    /// # fn main() {
    /// # let mut csprng: ThreadRng = thread_rng();
    /// # let keypair: Keypair = Keypair::generate(&mut csprng);
    /// # let message: &[u8] = b"All I want is to pet all of the dogs.";
    /// # let prehashed = Shake256::default();
    /// # prehashed.input(message);
    /// #
    /// let ctx = signing_context::<Shake128>(b"Ed25519DalekSignPrehashedDoctest");
    ///
    /// let sig: Signature = keypair.sign_prehashed(ctx, prehashed);
    /// # }
    /// #
    /// # #[cfg(any(not(feature = "sha2"), not(feature = "std")))]
    /// # fn main() { }
    /// ```
    ///
    /// [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
    /// [terrible_idea]: https://github.com/isislovecruft/scripts/blob/master/gpgkey2bc.py
    pub fn sign_prehashed<C>(
        &self,
        context: &C,
        prehashed_message: C::Digest,
    ) -> Signature
    where C: SigningContext,
          C::Digest: ExtendableOutput
    {
        self.secret.sign_prehashed::<C>(context, prehashed_message, &self.public)
    }

    /// Verify a signature on a message with this keypair's public key.
    pub fn verify<C>(&self, context: &C, message: &[u8], signature: &Signature) -> bool
    where C: SigningContext,
          C::Digest: ExtendableOutput
    {
        self.public.verify::<C>(context, message, signature)
    }

    /// Verify a `signature` on a `prehashed_message` using the Ed25519ph algorithm.
    ///
    /// # Inputs
    ///
    /// * `prehashed_message` is an instantiated hash digest with 512-bits of
    ///   output which has had the message to be signed previously fed into its
    ///   state.
    /// * `context` is an optional context string, up to 255 bytes inclusive,
    ///   which may be used to provide additional domain separation.  If not
    ///   set, this will default to an empty string.
    /// * `signature` is a purported Ed25519ph [`Signature`] on the `prehashed_message`.
    ///
    /// # Returns
    ///
    /// Returns `true` if the `signature` was a valid signature created by this
    /// `Keypair` on the `prehashed_message`.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate schnorr_dalek;
    /// extern crate rand;
    /// extern crate sha3;
    ///
    /// use schnorr_dalek::{Keypair,Signature};
    /// use schnorr_dalek::context::signing_context;
    /// use rand::{thread_rng,ThreadRng};
    /// use sha3::Shake128;
	/// use sha3::digest::{Input};
    ///
    /// # fn main() {
    /// let mut csprng: ThreadRng = thread_rng();
    /// let keypair: Keypair = Keypair::generate(&mut csprng);
    /// let message: &[u8] = b"All I want is to pet all of the dogs.";
    ///
    /// let mut prehashed: Shake128 = Shake128::default();
    /// prehashed.input(message);
    ///
    /// let ctx = signing_context::<Shake128>(b"Ed25519DalekSignPrehashedDoctest");
    ///
	/// // `Shake128: Clone` is a copy dispite not being `Copy`.
    /// let sig: Signature = keypair.sign_prehashed(&ctx, prehashed.clone());
    ///
    /// assert!( keypair.public.verify_prehashed(&ctx, prehashed, &sig) );
    /// # }
    /// ```
    ///
    /// [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
    pub fn verify_prehashed<C>(
	    &self,
	    context: &C,
	    prehashed_message: C::Digest,
	    signature: &Signature
	) -> bool
    where C: SigningContext, 
          C::Digest: ExtendableOutput
    {
        self.public.verify_prehashed::<C>(context, prehashed_message, signature)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Keypair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for Keypair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'d> {

        struct KeypairVisitor;

        impl<'d> Visitor<'d> for KeypairVisitor {
            type Value = Keypair;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("An ed25519 keypair, 64 bytes in total where the secret key is \
                                     the first 32 bytes and is in unexpanded form, and the second \
                                     32 bytes is a compressed point for a public key.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Keypair, E> where E: SerdeError {
                let secret_key = SecretKey::from_bytes(&bytes[..SECRET_KEY_LENGTH]) ?;
                let public_key = PublicKey::from_bytes(&bytes[SECRET_KEY_LENGTH..]) ?;
                Ok(Keypair{ secret, public })
            }
        }
        deserializer.deserialize_bytes(KeypairVisitor)
    }
}

#[cfg(test)]
mod test {
    use std::io::BufReader;
    use std::io::BufRead;
    use std::fs::File;
    use std::string::String;
    use std::vec::Vec;
    use rand::thread_rng;
    use rand::ChaChaRng;
    use rand::SeedableRng;
    use rand::ThreadRng;
    use hex::FromHex;
	use sha3::Shake128;
    use sha2::Sha512;
    use super::*;

    use curve25519_dalek::edwards::{CompressedEdwardsY};  // EdwardsPoint

    use context::signing_context;

    #[cfg(all(test, feature = "serde"))]
    static ED25519_PUBLIC_KEY: PublicKey = PublicKey(CompressedEdwardsY([
        130, 039, 155, 015, 062, 076, 188, 063,
        124, 122, 026, 251, 233, 253, 225, 220,
        014, 041, 166, 120, 108, 035, 254, 077,
        160, 083, 172, 058, 219, 042, 086, 120, ]));

    #[cfg(all(test, feature = "serde"))]
    static ED25519_SECRET_KEY: MiniSecretKey = MiniSecretKey([
        062, 070, 027, 163, 092, 182, 011, 003,
        077, 234, 098, 004, 011, 127, 079, 228,
        243, 187, 150, 073, 201, 137, 076, 022,
        085, 251, 152, 002, 241, 042, 072, 054, ]);

    /// Signature with the above keypair of a blank message.
    #[cfg(all(test, feature = "serde"))]
    static SIGNATURE_BYTES: [u8; SIGNATURE_LENGTH] = [
        010, 126, 151, 143, 157, 064, 047, 001,
        196, 140, 179, 058, 226, 152, 018, 102,
        160, 123, 080, 016, 210, 086, 196, 028,
        053, 231, 012, 157, 169, 019, 158, 063,
        045, 154, 238, 007, 053, 185, 227, 229,
        079, 108, 213, 080, 124, 252, 084, 167,
        216, 085, 134, 144, 129, 149, 041, 081,
        063, 120, 126, 100, 092, 059, 050, 011, ];

    #[test]
    fn sign_verify() {  // TestSignVerify
        let mut csprng: ChaChaRng;
        let keypair: Keypair;
        let good_sig: Signature;
        let bad_sig:  Signature;

        let ctx = signing_context::<Shake128>(b"good");
		
        let good: &[u8] = "test message".as_bytes();
        let bad:  &[u8] = "wrong message".as_bytes();

        csprng  = ChaChaRng::from_seed([0u8; 32]);
        keypair  = Keypair::generate(&mut csprng);
        good_sig = keypair.sign(&ctx,&good);
        bad_sig  = keypair.sign(&ctx,&bad);

        assert!(keypair.verify(&ctx, &good, &good_sig),
                "Verification of a valid signature failed!");
        assert!(!keypair.verify(&ctx, &good, &bad_sig),
                "Verification of a signature on a different message passed!");
        assert!(!keypair.verify(&ctx, &bad,  &good_sig),
                "Verification of a signature on a different message passed!");
        assert!(!keypair.verify(& signing_context::<Shake128>(b"bad"), &good,  &good_sig),
                "Verification of a signature on a different message passed!");
    }

    /* *** We have no test vectors obviously ***

    // TESTVECTORS is taken from sign.input.gz in agl's ed25519 Golang
    // package. It is a selection of test cases from
    // http://ed25519.cr.yp.to/python/sign.input
    #[cfg(test)]
    #[cfg(not(release))]
    #[test]
    fn golden() { // TestGolden
        let mut line: String;
        let mut lineno: usize = 0;

        let f = File::open("TESTVECTORS");
        if f.is_err() {
            println!("This test is only available when the code has been cloned \
                      from the git repository, since the TESTVECTORS file is large \
                      and is therefore not included within the distributed crate.");
            panic!();
        }
        let file = BufReader::new(f.unwrap());

        for l in file.lines() {
            lineno += 1;
            line = l.unwrap();

            let parts: Vec<&str> = line.split(':').collect();
            assert_eq!(parts.len(), 5, "wrong number of fields in line {}", lineno);

            let sec_bytes: Vec<u8> = FromHex::from_hex(&parts[0]).unwrap();
            let pub_bytes: Vec<u8> = FromHex::from_hex(&parts[1]).unwrap();
            let msg_bytes: Vec<u8> = FromHex::from_hex(&parts[2]).unwrap();
            let sig_bytes: Vec<u8> = FromHex::from_hex(&parts[3]).unwrap();

            let secret: MiniSecretKey = MiniSecretKey::from_bytes(&sec_bytes[..MINI_SECRET_KEY_LENGTH]).unwrap();
            let public: PublicKey = PublicKey::from_bytes(&pub_bytes[..PUBLIC_KEY_LENGTH]).unwrap();
            let keypair: Keypair  = Keypair{ secret: secret, public: public };

            // The signatures in the test vectors also include the message
            // at the end, but we just want R and S.
            let sig1: Signature = Signature::from_bytes(&sig_bytes[..64]).unwrap();
            let sig2: Signature = keypair.sign::<Sha512>(&msg_bytes);

            assert!(sig1 == sig2, "Signature bytes not equal on line {}", lineno);
            assert!(keypair.verify::<Sha512>(&msg_bytes, &sig2),
                    "Signature verification failed on line {}", lineno);
        }
    }
    *** We have no test vectors obviously *** */

    // From https://tools.ietf.org/html/rfc8032#section-7.3
    #[test]
    fn ed25519ph_rf8032_test_vector() {
        let secret_key: &[u8] = b"833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
        let public_key: &[u8] = b"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
        let message: &[u8] = b"616263";
        let sig1: &[u8] = b"98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406";

        let sec_bytes: Vec<u8> = FromHex::from_hex(secret_key).unwrap();
        let pub_bytes: Vec<u8> = FromHex::from_hex(public_key).unwrap();
        let msg_bytes: Vec<u8> = FromHex::from_hex(message).unwrap();
        let sig1: Vec<u8> = FromHex::from_hex(sig1).unwrap();

        let secret: MiniSecretKey = MiniSecretKey::from_bytes(&sec_bytes[..MINI_SECRET_KEY_LENGTH]).unwrap();
        let public: PublicKey = PublicKey::from_ed25519_public_key_bytes(&pub_bytes[..PUBLIC_KEY_LENGTH]).unwrap();
        let keypair: Keypair  = Keypair{ secret: secret.expand::<Sha512>(), public: public };

        let mut prehash_for_signing: Sha512 = Sha512::default().chain(&msg_bytes[..]);
        let mut prehash_for_verifying: Sha512 = Sha512::default().chain(&msg_bytes[..]);

        let sig2 = keypair.sign_ed25519_prehashed(prehash_for_signing, None);

        assert!(&sig1[..] == &sig2[..],
                "Original signature from test vectors doesn't equal signature produced:\
                \noriginal:\n{:?}\nproduced:\n{:?}", &sig1[..], &sig2[..]);
        assert!(keypair.verify_ed25519_prehashed(prehash_for_verifying, None, &sig2),
                "Could not verify ed25519ph signature!");
    }

    #[test]
    fn ed25519ph_sign_verify() {
        let mut csprng: ChaChaRng;
        let keypair: Keypair;
        let good_sig: Signature;
        let bad_sig:  Signature;

        let ctx = signing_context::<Shake128>(b"testing testing 1 2 3");

        let good: &[u8] = b"test message";
        let bad:  &[u8] = b"wrong message";

        // ugh… there's no `impl Copy for Sha512`… i hope we can all agree these are the same hashes
        let mut prehashed_good1: Shake128 = Shake128::default().chain(good);
        let mut prehashed_good2: Shake128 = Shake128::default().chain(good);
        let mut prehashed_good3: Shake128 = Shake128::default().chain(good);
        let mut prehashed_bad: Shake128 = Shake128::default().chain(bad);

        csprng   = ChaChaRng::from_seed([0u8; 32]);
        keypair  = Keypair::generate(&mut csprng);
        good_sig = keypair.sign_prehashed(&ctx, prehashed_good1);
        bad_sig  = keypair.sign_prehashed(&ctx, prehashed_bad.clone());

        assert!(keypair.verify_prehashed(&ctx, prehashed_good2, &good_sig),
                "Verification of a valid signature failed!");
        assert!(! keypair.verify_prehashed(&ctx, prehashed_good3, &bad_sig),
                "Verification of a signature on a different message passed!");
        assert!(! keypair.verify_prehashed(&ctx, prehashed_bad.clone(), &good_sig),
                "Verification of a signature on a different message passed!");
        assert!(! keypair.verify_prehashed(& signing_context::<Shake128>(b"oops"), prehashed_bad, &good_sig),
                "Verification of a signature on a different message passed!");
    }

    #[test]
    fn verify_batch_seven_signatures() {
        let ctx = signing_context::<Shake128>(b"my batch context");

        let messages: [&[u8]; 7] = [
            b"Watch closely everyone, I'm going to show you how to kill a god.",
            b"I'm not a cryptographer I just encrypt a lot.",
            b"Still not a cryptographer.",
            b"This is a test of the tsunami alert system. This is only a test.",
            b"Fuck dumbin' it down, spit ice, skip jewellery: Molotov cocktails on me like accessories.",
            b"Hey, I never cared about your bucks, so if I run up with a mask on, probably got a gas can too.",
            b"And I'm not here to fill 'er up. Nope, we came to riot, here to incite, we don't want any of your stuff.", ];
        let mut csprng: ThreadRng = thread_rng();
        let mut keypairs: Vec<Keypair> = Vec::new();
        let mut signatures: Vec<Signature> = Vec::new();

        for i in 0..messages.len() {
            let keypair: Keypair = Keypair::generate(&mut csprng);
            signatures.push(keypair.sign(&ctx, &messages[i]));
            keypairs.push(keypair);
        }
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();

        assert!( verify_batch(&ctx, &messages, &signatures[..], &public_keys[..]) );
    }

    #[test]
    fn public_key_from_bytes() {
        static ED25519_PUBLIC_KEY : CompressedEdwardsY = CompressedEdwardsY([
            215, 090, 152, 001, 130, 177, 010, 183,
            213, 075, 254, 211, 201, 100, 007, 058,
            014, 225, 114, 243, 218, 166, 035, 037,
            175, 002, 026, 104, 247, 007, 081, 026, ]);
        let pk = ED25519_PUBLIC_KEY.decompress().unwrap();
        let ristretto_public_key = util::edwards_to_ristretto(pk);

        assert_eq!(
            PublicKey(ristretto_public_key).to_ed25519_public_key_bytes(),
            pk.mul_by_cofactor().compress().0
        );

        // Make another function so that we can test the ? operator.
        fn do_the_test(s: &[u8]) -> Result<PublicKey, SignatureError> {
            let public_key = PublicKey::from_bytes(s) ?;
            Ok(public_key)
        }
        assert_eq!(
            do_the_test(ristretto_public_key.compress().as_bytes()),
            Ok(PublicKey(ristretto_public_key))
        );
        assert_eq!(
            do_the_test(&ED25519_PUBLIC_KEY.0),  // Not a Ristretto public key
            Err(SignatureError::PointDecompressionError)
        );
    }

    #[test]
    fn keypair_clear_on_drop() {
        let mut keypair: Keypair = Keypair::generate(&mut thread_rng());

        keypair.clear();

        fn as_bytes<T>(x: &T) -> &[u8] {
            use core::mem;
            use core::slice;

            unsafe {
                slice::from_raw_parts(x as *const T as *const u8, mem::size_of_val(x))
            }
        }

        assert!(!as_bytes(&keypair).iter().all(|x| *x == 0u8));
    }

    #[test]
    fn pubkey_from_mini_secret_and_expanded_secret() {
        let mut csprng = thread_rng();
        let mini_secret: MiniSecretKey = MiniSecretKey::generate(&mut csprng);
        let secret: SecretKey = mini_secret.expand::<Sha512>();
        let public_from_mini_secret: PublicKey = mini_secret.expand_to_public::<Sha512>();
        let public_from_secret: PublicKey = secret.to_public();

        assert!(public_from_mini_secret == public_from_secret);
    }

    #[cfg(all(test, feature = "serde"))]
    use bincode::{serialize, deserialize, Infinite};

    #[cfg(all(test, feature = "serde"))]
    #[test]
    fn serialize_deserialize_signature() {
        let signature: Signature = Signature::from_bytes(&SIGNATURE_BYTES).unwrap();
        let encoded_signature: Vec<u8> = serialize(&signature, Infinite).unwrap();
        let decoded_signature: Signature = deserialize(&encoded_signature).unwrap();

        assert_eq!(signature, decoded_signature);
    }

    #[cfg(all(test, feature = "serde"))]
    #[test]
    fn serialize_deserialize_public_key() {
        let encoded_public_key: Vec<u8> = serialize(&PUBLIC_KEY, Infinite).unwrap();
        let decoded_public_key: PublicKey = deserialize(&encoded_public_key).unwrap();

        assert_eq!(PUBLIC_KEY, decoded_public_key);
    }

    #[cfg(all(test, feature = "serde"))]
    #[test]
    fn serialize_deserialize_secret_key() {
        let encoded_secret_key: Vec<u8> = serialize(&SECRET_KEY, Infinite).unwrap();
        let decoded_secret_key: MiniSecretKey = deserialize(&encoded_secret_key).unwrap();

        for i in 0..32 {
            assert_eq!(SECRET_KEY.0[i], decoded_secret_key.0[i]);
        }
    }
}
