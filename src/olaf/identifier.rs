//! The identifier of a participant in the Olaf protocol.

use super::errors::DKGError;
use core::cmp::Ordering;
#[cfg(feature = "serde")]
use core::fmt;
use curve25519_dalek::Scalar;
#[cfg(feature = "serde")]
use serde::de::{self, Visitor};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The identifier is represented by a Scalar.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Identifier(pub(crate) Scalar);

#[cfg(feature = "serde")]
impl Serialize for Identifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let scalar_bytes = self.0.to_bytes();
        let scalar_hex = hex::encode(scalar_bytes);
        serializer.serialize_str(&scalar_hex)
    }
}

#[cfg(feature = "serde")]
struct IdentifierVisitor;

#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for IdentifierVisitor {
    type Value = Identifier;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a hexadecimal string representing a Scalar")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let bytes = match hex::decode(value) {
            Ok(b) => b,
            Err(_) => return Err(E::custom("Invalid hexadecimal string")),
        };
        if bytes.len() != 32 {
            return Err(E::custom(
                "Hexadecimal string must be exactly 32 bytes long",
            ));
        }
        let mut bytes_array = [0u8; 32];
        bytes_array.copy_from_slice(&bytes);

        let scalar = Scalar::from_canonical_bytes(bytes_array);
        if scalar.is_some().unwrap_u8() == 1 {
            Ok(Identifier(scalar.unwrap()))
        } else {
            Err(E::custom("Invalid bytes for a Scalar"))
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Identifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(IdentifierVisitor)
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

#[cfg(test)]
#[cfg(feature = "serde")]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_serialize_deserialize_random_identifier() {
        // Create a random Identifier
        let random_scalar = Scalar::random(&mut OsRng);
        let identifier = Identifier(random_scalar);

        // Serialize the Identifier
        let serialized = serde_json::to_string(&identifier).expect("Failed to serialize");

        // Deserialize the serialized string back into an Identifier
        let deserialized: Result<Identifier, _> = serde_json::from_str(&serialized);

        // Check if the deserialized Identifier matches the original
        assert!(deserialized.is_ok());
        assert_eq!(identifier, deserialized.unwrap());
    }

    #[test]
    fn test_deserialize_invalid_hex_identifier() {
        // Hexadecimal string with invalid characters (not valid hex)
        let invalid_hex_scalar =
            "\"g1c4c8a8ff4d21243af23e5ef23fea223b7cdde1baf31e56af77f872a8cc8402\"";
        let result: Result<Identifier, _> = serde_json::from_str(invalid_hex_scalar);

        // Assert that the deserialization fails
        assert!(
            result.is_err(),
            "Deserialization should fail for invalid hex characters"
        );
    }

    #[test]
    fn test_deserialize_invalid_length_identifier() {
        // Incorrect length hexadecimal string (not 64 characters long)
        let invalid_length_hex = "\"1c4c8a8ff4d21243af23e5ef23fea223b7cd\"";
        let result: Result<Identifier, _> = serde_json::from_str(invalid_length_hex);

        // Assert that the deserialization fails due to length mismatch
        assert!(
            result.is_err(),
            "Deserialization should fail for incorrect hex length"
        );
    }
}
