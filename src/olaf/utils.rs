use curve25519_dalek::Scalar;
use rand_core::{CryptoRng, RngCore};
use crate::{context::SigningTranscript, SecretKey};

pub(super) fn generate_identifier(recipients_hash: &[u8; 16], index: u16) -> Scalar {
    let mut pos = merlin::Transcript::new(b"Identifier");
    pos.append_message(b"RecipientsHash", recipients_hash);
    pos.append_message(b"i", &index.to_le_bytes()[..]);
    pos.challenge_scalar(b"evaluation position")
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
