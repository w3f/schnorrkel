//! Implementation of the Olaf protocol (<https://eprint.iacr.org/2023/899>), which is composed of the Distributed
//! Key Generation (DKG) protocol SimplPedPoP and the Threshold Signing protocol FROST.

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint};

pub mod errors;
pub mod simplpedpop;
mod tests;
pub mod data_structures;
mod utils;

const MINIMUM_THRESHOLD: u16 = 2;
const GENERATOR: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
