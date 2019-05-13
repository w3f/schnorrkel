// -*- mode: rust; -*-
//
// This file is part of schnorrkel.
// Copyright (c) 2019 Isis Lovecruft and Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>
// - Jeff Burdges <jeff@web3.foundation>

//! ### Schnorr signatures on the 2-torsion free subgroup of ed25519, as provided by the Ristretto point compression.

use core::convert::AsRef;
use core::default::Default;
use core::fmt::{Debug};

use rand::prelude::*;  // {RngCore,thread_rng};
use sha2::Sha512;

// TODO: Replace with Zeroize but ClearOnDrop does not work with std
#[cfg(any(feature = "std"))]
use clear_on_drop::clear::Clear;

use curve25519_dalek::digest::{Input,FixedOutput};  // ExtendableOutput,XofReader
// use curve25519_dalek::digest::generic_array::typenum::U64;

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{CompressedRistretto,RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

use subtle::{Choice,ConstantTimeEq};

use crate::scalars;
use crate::points::RistrettoBoth;
use crate::errors::{SignatureError,SignatureResult};


/// The length of a Ristretto Schnorr `MiniSecretKey`, in bytes.
pub const MINI_SECRET_KEY_LENGTH: usize = 32;

/// The length of a Ristretto Schnorr `PublicKey`, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// The length of the "key" portion of a Ristretto Schnorr secret key, in bytes.
const SECRET_KEY_KEY_LENGTH: usize = 32;

/// The length of the "nonce" portion of a Ristretto Schnorr secret key, in bytes.
const SECRET_KEY_NONCE_LENGTH: usize = 32;

/// The length of a Ristretto Schnorr key, `SecretKey`, in bytes.
pub const SECRET_KEY_LENGTH: usize = SECRET_KEY_KEY_LENGTH + SECRET_KEY_NONCE_LENGTH;

/// The length of an Ristretto Schnorr `Keypair`, in bytes.
pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;


/// An EdDSA compatabile "secret" key seed.
///
/// These are seeds from which we produce a real `SecretKey`, which
/// EdDSA itself calls an extended secret key by hashing.  We require
/// homomorphic properties unavailable from these seeds, so we renamed
/// these and reserve `SecretKey` for what EdDSA calls an extended
/// secret key.
#[derive(Default,Clone)] // we derive Default in order to use the clear() method in Drop
pub struct MiniSecretKey(pub (crate) [u8; MINI_SECRET_KEY_LENGTH]);

impl Debug for MiniSecretKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "MiniSecretKey: {:?}", &self.0[..])
    }
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for MiniSecretKey {
    fn drop(&mut self) {
        // TODO: Replace with Zeroize but ClearOnDrop does not work with std
        #[cfg(any(feature = "std"))]
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
    const DESCRIPTION : &'static str = "An ed25519 secret key as 32 bytes, as specified in RFC8032.";

    /// Expand this `MiniSecretKey` into a `SecretKey`.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate schnorrkel;
    /// #
    /// # fn main() {
    /// use rand::{Rng, rngs::OsRng};
    /// use schnorrkel::{MiniSecretKey, SecretKey};
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let mini_secret_key: MiniSecretKey = MiniSecretKey::generate(&mut csprng);
    /// let secret_key: SecretKey = mini_secret_key.expand();
    /// # }
    /// ```
    pub fn expand(&self) -> SecretKey {
        let mut t = merlin::Transcript::new(b"");
        t.append_message(b"mini", &self.0[..]);

        let mut scalar_bytes = [0u8; 64];
        t.challenge_bytes(b"sk", &mut scalar_bytes);
        let key = Scalar::from_bytes_mod_order_wide(&scalar_bytes);

        let mut nonce = [0u8; 32];
        t.challenge_bytes(b"no", &mut nonce);

        SecretKey { key, nonce }
    }

    /// Derive the `PublicKey` corresponding to this `MiniSecretKey`.
    pub fn expand_to_keypair(&self) -> Keypair {
        self.expand().into()
    }

    /// Derive the `PublicKey` corresponding to this `MiniSecretKey`.
    pub fn expand_to_public(&self) -> PublicKey {
        self.expand().to_public()
    }

    /// Expand this `MiniSecretKey` into a `SecretKey` using
    /// ed25519-style bit clamping.
    ///
    /// We recommend the `expand` method instead because it provides
    /// a more uniformly distributed secret key, poly benifiting some
    /// future protocols. 
    ///
    /// At present, there is no exposed mapping from Ristretto
    /// to the underlying Edwards curve because Ristretto invovles
    /// an inverse square root and thus two such mappings exist.
    /// Ristretto could be made usable with Ed25519 keys by choosing
    /// one mapping as standard, but doing so makes the standard more
    /// complex, and possibly harder to implement.  If anyone does
    /// standardize the mapping to the curve then this method becomes
    /// useful.
    pub fn expand_ed25519(&self) -> SecretKey {
        let mut h: Sha512 = Sha512::default();
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
        scalars::divide_scalar_bytes_by_cofactor(&mut key);
        let key = Scalar::from_bits(key);

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&r.as_slice()[32..64]);

        SecretKey{ key, nonce }
    }

    /// Convert this secret key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; MINI_SECRET_KEY_LENGTH] {
        self.0
    }

    /// View this secret key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; MINI_SECRET_KEY_LENGTH] {
        &self.0
    }

    /// Construct a `MiniSecretKey` from a slice of bytes.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate schnorrkel;
    /// #
    /// use schnorrkel::MiniSecretKey;
    /// use schnorrkel::MINI_SECRET_KEY_LENGTH;
    /// use schnorrkel::SignatureError;
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
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<MiniSecretKey> {
        if bytes.len() != MINI_SECRET_KEY_LENGTH {
            return Err(SignatureError::BytesLengthError {
                name: "MiniSecretKey",
                description: MiniSecretKey::DESCRIPTION,
                length: MINI_SECRET_KEY_LENGTH
            });
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
    /// extern crate schnorrkel;
    ///
    /// # #[cfg(feature = "std")]
    /// # fn main() {
    /// #
    /// use rand::{Rng, rngs::OsRng};
    /// use sha2::Sha512;
    /// use schnorrkel::PublicKey;
    /// use schnorrkel::MiniSecretKey;
    /// use schnorrkel::Signature;
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
    /// # extern crate rand_chacha;
    /// # extern crate sha2;
    /// # extern crate schnorrkel;
    /// #
    /// # fn main() {
    /// #
    /// # use rand::Rng;
    /// # use rand_chacha::ChaChaRng;
    /// # use rand::SeedableRng;
    /// # use sha2::Sha512;
    /// # use schnorrkel::PublicKey;
    /// # use schnorrkel::MiniSecretKey;
    /// # use schnorrkel::Signature;
    /// #
    /// # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
    /// # let secret_key: MiniSecretKey = MiniSecretKey::generate(&mut csprng);
    ///
    /// let public_key: PublicKey = secret_key.expand_to_public();
    /// # }
    /// ```
    ///
    /// The standard hash function used for most ed25519 libraries is SHA-512,
    /// which is available with `use sha2::Sha512` as in the example above.
    /// Other suitable hash functions include Keccak-512 and Blake2b-512.
    ///
    /// # Input
    ///
    /// A CSPRNG with a `fill_bytes()` method, e.g. `rand_chacha::ChaChaRng`
    pub fn generate<R>(mut csprng: R) -> MiniSecretKey
    where R: CryptoRng + Rng,
    {
        let mut sk: MiniSecretKey = MiniSecretKey([0u8; 32]);
        csprng.fill_bytes(&mut sk.0);
        sk
    }
}

serde_boilerplate!(MiniSecretKey);


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
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "SecretKey {{ key: {:?} nonce: {:?} }}", &self.key, &self.nonce)
    }
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for SecretKey {
    fn drop(&mut self) {
        // TODO: Replace with Zeroize but ClearOnDrop does not work with std
        #[cfg(any(feature = "std"))]
        self.key.clear();
        #[cfg(any(feature = "std"))]
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

impl From<&MiniSecretKey> for SecretKey {
    /// Construct an `SecretKey` from a `MiniSecretKey`.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate sha2;
    /// # extern crate schnorrkel;
    /// #
    /// # fn main() {
    /// use rand::{Rng, rngs::OsRng};
    /// use sha2::Sha512;
    /// use schnorrkel::{MiniSecretKey, SecretKey};
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let mini_secret_key: MiniSecretKey = MiniSecretKey::generate(&mut csprng);
    /// let secret_key: SecretKey = SecretKey::from(&mini_secret_key);
    /// # }
    /// ```
    fn from(msk: &MiniSecretKey) -> SecretKey {
        msk.expand()
    }
}

impl SecretKey {
    const DESCRIPTION : &'static str = "An ed25519-like expanded secret key as 64 bytes, as specified in RFC8032.";

    /// Convert this `SecretKey` into an array of 64 bytes with.
    ///
    /// Returns an array of 64 bytes, with the first 32 bytes being
    /// the secret scalar represented cannonically, and the last
    /// 32 bytes being the seed for nonces.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate sha2;
    /// # extern crate schnorrkel;
    /// #
    /// # fn main() {
    /// use rand::{Rng, rngs::OsRng};
    /// use sha2::Sha512;
    /// use schnorrkel::{MiniSecretKey, SecretKey};
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let mini_secret_key: MiniSecretKey = MiniSecretKey::generate(&mut csprng);
    /// let secret_key: SecretKey = SecretKey::from(&mini_secret_key);
    /// let secret_key_bytes: [u8; 64] = secret_key.to_bytes();
    ///
    /// assert!(&secret_key_bytes[..] != &[0u8; 64][..]);
    /// # }
    /// ```
    #[inline]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        let mut bytes: [u8; 64] = [0u8; 64];
        bytes[..32].copy_from_slice(&self.key.to_bytes()[..]);
        bytes[32..].copy_from_slice(&self.nonce[..]);
        bytes
    }

    /// Construct an `SecretKey` from a slice of bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate sha2;
    /// # extern crate schnorrkel;
    /// #
    /// use schnorrkel::{MiniSecretKey, SecretKey, SignatureError};
    /// use rand::{Rng, rngs::OsRng};
    /// # fn do_test() -> Result<SecretKey, SignatureError> {
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let mini_secret_key: MiniSecretKey = MiniSecretKey::generate(&mut csprng);
    /// let secret_key: SecretKey = SecretKey::from(&mini_secret_key);
    /// let bytes: [u8; 64] = secret_key.to_bytes();
    /// let secret_key_again = SecretKey::from_bytes(&bytes) ?;
    /// #
    /// # Ok(secret_key_again)
    /// # }
    /// #
    /// # fn main() {
    /// #     let result = do_test();
    /// #     assert!(result.is_ok());
    /// # }
    /// ```
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<SecretKey> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(SignatureError::BytesLengthError{
                name: "SecretKey",
                description: SecretKey::DESCRIPTION,
                length: SECRET_KEY_LENGTH,
            });
        }

        let mut key: [u8; 32] = [0u8; 32];
        key.copy_from_slice(&bytes[00..32]);
        let key = Scalar::from_canonical_bytes(key).ok_or(SignatureError::ScalarFormatError) ?;
        
        let mut nonce: [u8; 32] = [0u8; 32];
        nonce.copy_from_slice(&bytes[32..64]);

        Ok(SecretKey{ key, nonce })
    }

    /// Convert this `SecretKey` into an array of 64 bytes, corresponding to
    /// an Ed25519 expanded secreyt key.
    ///
    /// Returns an array of 64 bytes, with the first 32 bytes being
    /// the secret scalar shifted ed25519 style, and the last 32 bytes
    /// being the seed for nonces.
    #[inline]
    pub fn to_ed25519_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        let mut bytes: [u8; 64] = [0u8; 64];
        let mut key = self.key.to_bytes();
        // We multiply by the cofactor to improve ed25519 compatability,
        // while our internally using a scalar mod l.
        scalars::multiply_scalar_bytes_by_cofactor(&mut key);
        bytes[..32].copy_from_slice(&key[..]);
        bytes[32..].copy_from_slice(&self.nonce[..]);
        bytes
    }

    /// Convert this `SecretKey` into an Ed25519 expanded secreyt key.
    pub fn to_ed25519_expanded_secret_key(&self) -> ::ed25519_dalek::ExpandedSecretKey {
        ::ed25519_dalek::ExpandedSecretKey::from_bytes(&self.to_ed25519_bytes()[..])
        .expect("Improper serialisation of Ed25519 secret key!")
    }

    /// Construct an `SecretKey` from a slice of bytes, corresponding to
    /// an Ed25519 expanded secret key.
    #[inline]
    pub fn from_ed25519_bytes(bytes: &[u8]) -> SignatureResult<SecretKey> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(SignatureError::BytesLengthError{
                name: "SecretKey",
                description: SecretKey::DESCRIPTION,
                length: SECRET_KEY_LENGTH,
            });
        }

        let mut key: [u8; 32] = [0u8; 32];
        key.copy_from_slice(&bytes[00..32]);
        // TODO:  We should consider making sure the scalar is valid,
        // maybe by zering the high bit, or preferably by checking < l.
        // key[31] &= 0b0111_1111;
        // We devide by the cofactor to internally keep a clean
        // representation mod l.
        scalars::divide_scalar_bytes_by_cofactor(&mut key);
        let key = Scalar::from_bits(key);

        let mut nonce: [u8; 32] = [0u8; 32];
        nonce.copy_from_slice(&bytes[32..64]);

        Ok(SecretKey{ key, nonce })
    }

    /// Generate an "unbiased" `SecretKey` directly, bypassing the
    /// `MiniSecretKey` Ed25519 compatability layer.
    ///
    /// As we generate a `SecretKey` directly bypassing `MiniSecretKey`,
    /// so our secret keys do not satisfy the high bit "clamping"
    /// impoised on Ed25519 keys.
    pub fn generate<R>(mut csprng: R) -> SecretKey
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
        PublicKey::from_point(&self.key * &constants::RISTRETTO_BASEPOINT_TABLE)
    }

    /// Derive the `PublicKey` corresponding to this `SecretKey`.
    pub fn to_keypair(self) -> Keypair {
        let public = self.to_public();
        Keypair { secret: self, public }
    }
}

serde_boilerplate!(SecretKey);


/// A Ristretto Schnorr public key.
///
/// Internally, these are represented as a `RistrettoPoint`, meaning
/// an Edwards point with a static guarantee to be 2-torsion free.
///
/// At present, we decompress `PublicKey`s into this representation
/// during deserialization, which improves error handling, but costs
/// a compression during signing and verifiaction.
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey(pub (crate) RistrettoBoth);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "PublicKey( {:?} )", self.0)
    }
}

// We should imho drop this impl but it benifits users who start with ring.
impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_compressed().as_bytes()
    }
}

impl PublicKey {
    const DESCRIPTION : &'static str = "A Ristretto Schnorr public key represented as a 32-byte Ristretto compressed point";

    /// Access the compressed Ristretto form
    pub fn as_compressed(&self) -> &CompressedRistretto { &self.0.as_compressed() }

    /// Extract the compressed Ristretto form
    pub fn into_compressed(self) -> CompressedRistretto { self.0.into_compressed() }

    /// Access the point form
    pub fn as_point(&self) -> &RistrettoPoint { &self.0.as_point() }

    /// Extract the point form
    pub fn into_point(self) -> RistrettoPoint { self.0.into_point() }

    /// Decompress into the `PublicKey` format that also retains the
    /// compressed form.
    pub fn from_compressed(compressed: CompressedRistretto) -> SignatureResult<PublicKey> {
        Ok(PublicKey(RistrettoBoth::from_compressed(compressed) ?))
    }

    /// Compress into the `PublicKey` format that also retains the
    /// uncompressed form.
    pub fn from_point(point: RistrettoPoint) -> PublicKey {
        PublicKey(RistrettoBoth::from_point(point))
    }

    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.as_compressed().to_bytes()
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
    /// # extern crate schnorrkel;
    /// #
    /// use schnorrkel::PublicKey;
    /// use schnorrkel::PUBLIC_KEY_LENGTH;
    /// use schnorrkel::SignatureError;
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
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<PublicKey> {
        Ok(PublicKey(RistrettoBoth::from_bytes_ser("PublicKey",PublicKey::DESCRIPTION,bytes) ?))
    }
}

impl From<SecretKey> for PublicKey {
    fn from(source: SecretKey) -> PublicKey {
        source.to_public()
    }
}

serde_boilerplate!(PublicKey);


/// A Ristretto Schnorr keypair.
#[derive(Debug, Default)] // we derive Default in order to use the clear() method in Drop
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
    const DESCRIPTION : &'static str = "A 96 bytes Ristretto Schnorr keypair";
    /*
    const DESCRIPTION_LONG : &'static str =
        "An ristretto schnorr keypair, 96 bytes in total, where the \
        first 64 bytes contains the secret key represented as an \
        ed25519 expanded secret key, as specified in RFC8032, and \
        the subsequent 32 bytes gives the public key as a compressed \
        ristretto point.";
    */

    /// Convert this keypair to bytes.
    ///
    /// # Returns
    ///
    /// An array of bytes, `[u8; KEYPAIR_LENGTH]`.  The first
    /// `SECRET_KEY_LENGTH` of bytes is the serialized `SecretKey`, and the
    /// next `PUBLIC_KEY_LENGTH` bytes is the `PublicKey` (the same as other
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
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<Keypair> {
        if bytes.len() != KEYPAIR_LENGTH {
            return Err(SignatureError::BytesLengthError {
                name: "Keypair",
                description: Keypair::DESCRIPTION,
                length: KEYPAIR_LENGTH
            });
        }
        let secret = SecretKey::from_bytes(&bytes[..SECRET_KEY_LENGTH]) ?;
        let public = PublicKey::from_bytes(&bytes[SECRET_KEY_LENGTH..]) ?;

        Ok(Keypair{ secret: secret, public: public })
    }

    /// Generate a Ristretto Schnorr keypair.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate rand;
    /// extern crate schnorrkel;
    ///
    /// # fn main() {
    ///
    /// use rand::{Rng, rngs::OsRng};
    /// use schnorrkel::Keypair;
    /// use schnorrkel::Signature;
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let keypair: Keypair = Keypair::generate(&mut csprng);
    ///
    /// # }
    /// ```
    ///
    /// # Input
    ///
    /// A CSPRNG with a `fill_bytes()` method, e.g. `rand_chacha::ChaChaRng`.
    ///
    /// We generate a `SecretKey` directly bypassing `MiniSecretKey`,
    /// so our secret keys do not satisfy the high bit "clamping"
    /// impoised on Ed25519 keys.
    pub fn generate<R>(csprng: R) -> Keypair
    where R: CryptoRng + Rng,
    {
        let secret: SecretKey = SecretKey::generate(csprng);
        let public: PublicKey = secret.to_public();

        Keypair{ public, secret }
    }
}

serde_boilerplate!(Keypair);


#[cfg(test)]
mod test {
    // use std::vec::Vec;
    // use hex::FromHex;
    use rand::prelude::*; // ThreadRng,thread_rng
    use super::*;

    /*
	TODO: Use some Ristretto point to do this test correctly.
    use curve25519_dalek::edwards::{CompressedEdwardsY};  // EdwardsPoint
    #[test]
    fn public_key_from_bytes() {
        static ED25519_PUBLIC_KEY : CompressedEdwardsY = CompressedEdwardsY([
            215, 090, 152, 001, 130, 177, 010, 183,
            213, 075, 254, 211, 201, 100, 007, 058,
            014, 225, 114, 243, 218, 166, 035, 037,
            175, 002, 026, 104, 247, 007, 081, 026, ]);
        let pk = ED25519_PUBLIC_KEY.decompress().unwrap();
        // let pk = unsafe { ::std::mem::transmute::<EdwardsPoint,RistrettoPoint>(pk) };
        let point = super::super::ed25519::edwards_to_ristretto(pk).unwrap();
        let ristretto_public_key = PublicKey::from_point(point);

        assert_eq!(
            ristretto_public_key.to_ed25519_public_key_bytes(),
            pk.mul_by_cofactor().compress().0
        );

        // Make another function so that we can test the ? operator.
        fn do_the_test(s: &[u8]) -> Result<PublicKey, SignatureError> {
            let public_key = PublicKey::from_bytes(s) ?;
            Ok(public_key)
        }
        assert_eq!(
            do_the_test(ristretto_public_key.as_ref()),
            Ok(ristretto_public_key)
        );
        assert_eq!(
            do_the_test(&ED25519_PUBLIC_KEY.0),  // Not a Ristretto public key
            Err(SignatureError::PointDecompressionError)
        );
    }
	*/

    #[test]
    fn derives_from_core() {
        let pk_d = PublicKey::default();
        debug_assert_eq!(
            pk_d.as_point().compress(),
            CompressedRistretto::default()
        );
        debug_assert_eq!(
            pk_d.as_compressed().decompress().unwrap(),
            RistrettoPoint::default()
        );
    }

    #[test]
    fn keypair_clear_on_drop() {
        let mut keypair: Keypair = Keypair::generate(&mut thread_rng());

        // TODO: Replace with Zeroize but ClearOnDrop does not work with std
        #[cfg(any(feature = "std"))]
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
        let secret: SecretKey = mini_secret.expand();
        let public_from_mini_secret: PublicKey = mini_secret.expand_to_public();
        let public_from_secret: PublicKey = secret.to_public();

        assert!(public_from_mini_secret == public_from_secret);
    }
}
