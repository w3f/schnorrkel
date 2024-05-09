//! Implementation of the Olaf protocol (<https://eprint.iacr.org/2023/899>), which is composed of the Distributed
//! Key Generation (DKG) protocol SimplPedPoP and the Threshold Signing protocol FROST.

mod simplpedpop;
mod frost;

use core::cmp::Ordering;

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use merlin::Transcript;

use crate::{context::SigningTranscript, Keypair, PublicKey};

pub(super) const MINIMUM_THRESHOLD: u16 = 2;
pub(super) const GENERATOR: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// The group public key used by the Olaf protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GroupPublicKey(pub(crate) PublicKey);

/// The verifying share of a participant in the Olaf protocol, used to verify its signature share.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VerifyingShare(pub(crate) PublicKey);

/// The signing keypair of a participant in the Olaf protocol, used to produce its signature share.
#[derive(Clone, Debug)]
pub struct SigningKeyPair(pub(crate) Keypair);

/// The identifier of a participant in the Olaf protocol.
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

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> Ordering {
        let serialized_self = self.0.as_bytes();
        let serialized_other = other.0.as_bytes();

        // The default cmp uses lexicographic order; so we need the elements in big endian
        serialized_self
            .as_ref()
            .iter()
            .rev()
            .cmp(serialized_other.as_ref().iter().rev())
    }
}
