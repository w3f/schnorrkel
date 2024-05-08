use core::iter;
use alloc::vec::Vec;
use curve25519_dalek::{traits::Identity, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use crate::{context::SigningTranscript, SecretKey};
use super::errors::DKGError;

pub(super) fn generate_identifier(recipients_hash: &[u8; 16], index: u16) -> Scalar {
    let mut pos = merlin::Transcript::new(b"Identifier");
    pos.append_message(b"RecipientsHash", recipients_hash);
    pos.append_message(b"i", &index.to_le_bytes()[..]);
    pos.challenge_scalar(b"evaluation position")
}

/// Evaluate the polynomial with the given coefficients (constant term first)
/// at the point x=identifier using Horner's method.
pub(super) fn evaluate_polynomial(identifier: &Scalar, coefficients: &[Scalar]) -> Scalar {
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
pub(super) fn generate_coefficients<R: RngCore + CryptoRng>(
    size: usize,
    rng: &mut R,
) -> Vec<Scalar> {
    let mut coefficients = Vec::with_capacity(size);

    let mut first = Scalar::random(rng);
    while first == Scalar::ZERO {
        first = Scalar::random(rng);
    }

    coefficients.push(first);
    coefficients.extend(iter::repeat_with(|| Scalar::random(rng)).take(size - 1));

    coefficients
}

pub(super) fn derive_secret_key_from_scalar<R: RngCore + CryptoRng>(
    scalar: &Scalar,
    mut rng: R,
) -> SecretKey {
    let mut bytes = [0u8; 64];
    let mut nonce: [u8; 32] = [0u8; 32];

    rng.fill_bytes(&mut nonce);
    let secret_bytes = scalar.to_bytes();

    bytes[..32].copy_from_slice(&secret_bytes[..]);
    bytes[32..].copy_from_slice(&nonce[..]);

    SecretKey::from_bytes(&bytes[..])
        .expect("This never fails because bytes has length 64 and the key is a scalar")
}

pub(super) fn evaluate_polynomial_commitment(
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

pub(super) fn sum_commitments(
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
