use core::iter;
use alloc::vec::Vec;
use aead::{generic_array::GenericArray, KeyInit, KeySizeUser};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Nonce};
use curve25519_dalek::{traits::Identity, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use crate::{context::SigningTranscript, PublicKey, SecretKey};
use super::{
    data_structures::ENCRYPTION_NONCE_LENGTH,
    errors::{DKGError, DKGResult},
    GENERATOR,
};

pub(crate) fn generate_identifier(recipients_hash: &[u8; 16], index: u16) -> Scalar {
    let mut pos = merlin::Transcript::new(b"Identifier");
    pos.append_message(b"RecipientsHash", recipients_hash);
    pos.append_message(b"i", &index.to_le_bytes()[..]);
    pos.challenge_scalar(b"evaluation position")
}

/// Evaluate the polynomial with the given coefficients (constant term first)
/// at the point x=identifier using Horner's method.
pub(crate) fn evaluate_polynomial(identifier: &Scalar, coefficients: &[Scalar]) -> Scalar {
    let mut value = Scalar::ZERO;

    let ell_scalar = identifier;
    for coeff in coefficients.iter().skip(1).rev() {
        value += *coeff;
        value *= ell_scalar;
    }
    value += *coefficients.first().expect("coefficients must have at least one element");
    value
}

/// Return a vector of randomly generated polynomial coefficients ([`Scalar`]s).
pub(crate) fn generate_coefficients<R: RngCore + CryptoRng>(
    size: usize,
    rng: &mut R,
) -> Vec<Scalar> {
    let mut coefficients = Vec::with_capacity(size);

    // Ensure the first coefficient is not zero
    let mut first = Scalar::random(rng);
    while first == Scalar::ZERO {
        first = Scalar::random(rng);
    }
    coefficients.push(first);

    // Generate the remaining coefficients
    coefficients.extend(iter::repeat_with(|| Scalar::random(rng)).take(size - 1));

    coefficients
}

pub(crate) fn derive_secret_key_from_secret<R: RngCore + CryptoRng>(
    secret: &Scalar,
    mut rng: R,
) -> SecretKey {
    let mut bytes = [0u8; 64];
    let mut nonce: [u8; 32] = [0u8; 32];

    rng.fill_bytes(&mut nonce);
    let secret_bytes = secret.to_bytes();

    bytes[..32].copy_from_slice(&secret_bytes[..]);
    bytes[32..].copy_from_slice(&nonce[..]);

    SecretKey::from_bytes(&bytes[..])
        .expect("This never fails because bytes has length 64 and the key is a scalar")
}

pub(crate) fn evaluate_polynomial_commitment(
    identifier: &Scalar,
    commitment: &[RistrettoPoint],
) -> RistrettoPoint {
    let i = identifier;

    let (_, result) = commitment
        .iter()
        .fold((Scalar::ONE, RistrettoPoint::identity()), |(i_to_the_k, sum_so_far), comm_k| {
            (i * i_to_the_k, sum_so_far + comm_k * i_to_the_k)
        });
    result
}

pub(crate) fn sum_commitments(
    commitments: &[&Vec<RistrettoPoint>],
) -> Result<Vec<RistrettoPoint>, DKGError> {
    let mut group_commitment =
        vec![
            RistrettoPoint::identity();
            commitments.first().ok_or(DKGError::IncorrectNumberOfCommitments)?.len()
        ];
    for commitment in commitments {
        for (i, c) in group_commitment.iter_mut().enumerate() {
            *c += commitment.get(i).ok_or(DKGError::IncorrectNumberOfCommitments)?;
        }
    }
    Ok(group_commitment)
}

pub(crate) fn encrypt<T: SigningTranscript>(
    scalar_evaluation: &Scalar,
    ephemeral_key: &Scalar,
    mut transcript: T,
    recipient: &PublicKey,
    nonce: &[u8; ENCRYPTION_NONCE_LENGTH],
    i: usize,
) -> DKGResult<Vec<u8>> {
    transcript.commit_bytes(b"i", &i.to_le_bytes());
    transcript.commit_point(b"contributor", &(ephemeral_key * GENERATOR).compress());
    transcript.commit_point(b"recipient", recipient.as_compressed());

    transcript.commit_bytes(b"nonce", nonce);
    transcript.commit_point(b"key exchange", &(ephemeral_key * recipient.as_point()).compress());

    let mut key: GenericArray<u8, <chacha20poly1305::ChaCha20Poly1305 as KeySizeUser>::KeySize> =
        Default::default();

    transcript.challenge_bytes(b"", key.as_mut_slice());

    let cipher = ChaCha20Poly1305::new(&key);

    let nonce = Nonce::from_slice(&nonce[..]);

    let ciphertext: Vec<u8> = cipher
        .encrypt(nonce, &scalar_evaluation.to_bytes()[..])
        .map_err(DKGError::EncryptionError)?;

    Ok(ciphertext)
}

pub(crate) fn decrypt<T: SigningTranscript>(
    mut transcript: T,
    contributor: &PublicKey,
    recipient: &PublicKey,
    key_exchange: &RistrettoPoint,
    encrypted_scalar: &[u8],
    nonce: &[u8; ENCRYPTION_NONCE_LENGTH],
    i: usize,
) -> DKGResult<Scalar> {
    transcript.commit_bytes(b"i", &i.to_le_bytes());
    transcript.commit_point(b"contributor", contributor.as_compressed());
    transcript.commit_point(b"recipient", recipient.as_compressed());
    transcript.commit_bytes(b"nonce", nonce);
    transcript.commit_point(b"key exchange", &key_exchange.compress());

    let mut key: GenericArray<u8, <chacha20poly1305::ChaCha20Poly1305 as KeySizeUser>::KeySize> =
        Default::default();

    transcript.challenge_bytes(b"", key.as_mut_slice());

    let cipher = ChaCha20Poly1305::new(&key);

    let nonce = Nonce::from_slice(&nonce[..]);

    let plaintext = cipher.decrypt(nonce, encrypted_scalar).map_err(DKGError::DecryptionError)?;

    let mut bytes = [0; 32];
    bytes.copy_from_slice(&plaintext);

    Ok(Scalar::from_bytes_mod_order(bytes))
}
