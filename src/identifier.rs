//! The identifier of a participant in a multiparty protocol.

use core::cmp::Ordering;

use crate::errors::DKGError;
use curve25519_dalek::Scalar;

/// The identifier is represented by a scalar.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Identifier(pub(crate) Scalar);

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

impl TryFrom<u16> for Identifier {
    type Error = DKGError;

    fn try_from(n: u16) -> Result<Identifier, Self::Error> {
        if n == 0 {
            Err(DKGError::InvalidIdentifier)
        } else {
            // Classic left-to-right double-and-add algorithm that skips the first bit 1 (since
            // identifiers are never zero, there is always a bit 1), thus `sum` starts with 1 too.
            let one = Scalar::ONE;
            let mut sum = Scalar::ONE;

            let bits = (n.to_be_bytes().len() as u32) * 8;
            for i in (0..(bits - n.leading_zeros() - 1)).rev() {
                sum = sum + sum;
                if n & (1 << i) != 0 {
                    sum += one;
                }
            }
            Ok(Self(sum))
        }
    }
}

impl TryFrom<Scalar> for Identifier {
    type Error = DKGError;

    fn try_from(value: Scalar) -> Result<Self, Self::Error> {
        Ok(Self(value))
    }
}
