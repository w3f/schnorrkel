//! Implementation of the Olaf protocol (<https://eprint.iacr.org/2023/899>), which is composed of the Distributed
//! Key Generation (DKG) protocol SimplPedPoP and the Threshold Signing protocol FROST.

/// Implementation of the SimplPedPoP protocol.
pub mod simplpedpop;
/// Implementation of the FROST protocol.
pub mod frost;

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use merlin::Transcript;
use zeroize::ZeroizeOnDrop;
use crate::{context::SigningTranscript, Keypair, PublicKey};

pub(super) const MINIMUM_THRESHOLD: u16 = 2;
pub(super) const GENERATOR: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
pub(super) const COMPRESSED_RISTRETTO_LENGTH: usize = 32;
pub(crate) const SCALAR_LENGTH: usize = 32;

/// The threshold public key generated in the SimplPedPoP protocol, used to validate the threshold signatures of the FROST protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ThresholdPublicKey(pub(crate) PublicKey);

/// The verifying share of a participant generated in the SimplPedPoP protocol, used to verify its signatures shares in the FROST protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VerifyingShare(pub(crate) PublicKey);

/// The signing keypair of a participant generated in the SimplPedPoP protocol, used to produce its signatures shares in the FROST protocol.
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct SigningKeypair(pub(crate) Keypair);

/// The identifier of a participant, which must be the same in the SimplPedPoP protocol and in the FROST protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Identifier(pub(crate) Scalar);

impl Identifier {
    pub(super) fn generate(recipients_hash: &[u8; 16], index: u16) -> Identifier {
        let mut pos = Transcript::new(b"Identifier");
        pos.append_message(b"RecipientsHash", recipients_hash);
        pos.append_message(b"i", &index.to_le_bytes()[..]);

        Identifier(pos.challenge_scalar(b"evaluation position"))
    }
}
