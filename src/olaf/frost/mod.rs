//! Implementation of the FROST protocol (<https://eprint.iacr.org/2020/852>).

pub mod errors;
mod data_structures;

use alloc::vec::Vec;
use curve25519_dalek::Scalar;
use crate::{Keypair, PublicKey};
use self::{
    data_structures::{SigningCommitments, SigningNonces},
    errors::FROSTResult,
};

impl Keypair {
    /// Done once by each participant, to generate _their_ nonces and commitments
    /// that are then used during signing.
    ///
    /// This is only needed if pre-processing is needed (for 1-round FROST). For
    /// regular 2-round FROST, use [`commit`].
    ///
    /// When performing signing using two rounds, num_nonces would equal 1, to
    /// perform the first round. Batching entails generating more than one
    /// nonce/commitment pair at a time.  Nonces should be stored in secret storage
    /// for later use, whereas the commitments are published.
    pub fn preprocess(&self, num_nonces: u8) -> (Vec<SigningNonces>, Vec<SigningCommitments>) {
        let mut rng = crate::getrandom_or_panic();

        let mut signing_nonces: Vec<SigningNonces> = Vec::with_capacity(num_nonces as usize);

        let mut signing_commitments: Vec<SigningCommitments> =
            Vec::with_capacity(num_nonces as usize);

        for _ in 0..num_nonces {
            let nonces = SigningNonces::new(&self.secret.key, &mut rng);
            signing_commitments.push(SigningCommitments::from(&nonces));
            signing_nonces.push(nonces);
        }

        (signing_nonces, signing_commitments)
    }
}
