//! Implementation of a polynomial and related operations.

use crate::olaf::simplpedpop::GENERATOR;
use alloc::vec;
use alloc::vec::Vec;
use curve25519_dalek::{traits::Identity, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

pub(crate) type Coefficient = Scalar;
pub(crate) type Value = Scalar;
pub(crate) type ValueCommitment = RistrettoPoint;
pub(crate) type CoefficientCommitment = RistrettoPoint;

/// A polynomial.
#[derive(Debug, Clone, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Polynomial {
    pub(crate) coefficients: Vec<Coefficient>,
}

impl Polynomial {
    pub(crate) fn generate<R: RngCore + CryptoRng>(rng: &mut R, degree: u16) -> Self {
        let mut coefficients = Vec::new();

        for _ in 0..(degree as usize + 1) {
            coefficients.push(Scalar::random(rng));
        }

        Self { coefficients }
    }

    pub(crate) fn evaluate(&self, x: &Value) -> Value {
        let mut value =
            *self.coefficients.last().expect("coefficients must have at least one element");

        // Process all coefficients except the last one, using Horner's method
        for coeff in self.coefficients.iter().rev().skip(1) {
            value = value * x + coeff;
        }

        value
    }
}

/// A polynomial commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PolynomialCommitment {
    pub(crate) coefficients_commitments: Vec<CoefficientCommitment>,
}

impl PolynomialCommitment {
    pub(crate) fn commit(polynomial: &Polynomial) -> Self {
        let coefficients_commitments = polynomial
            .coefficients
            .iter()
            .map(|coefficient| GENERATOR * coefficient)
            .collect();

        Self { coefficients_commitments }
    }

    pub(crate) fn evaluate(&self, identifier: &Value) -> ValueCommitment {
        let i = identifier;

        let (_, result) = self
            .coefficients_commitments
            .iter()
            .fold((Scalar::ONE, RistrettoPoint::identity()), |(i_to_the_k, sum_so_far), comm_k| {
                (i * i_to_the_k, sum_so_far + comm_k * i_to_the_k)
            });
        result
    }

    pub(crate) fn sum_polynomial_commitments(
        polynomials_commitments: &[&PolynomialCommitment],
    ) -> PolynomialCommitment {
        let max_length = polynomials_commitments
            .iter()
            .map(|c| c.coefficients_commitments.len())
            .max()
            .unwrap_or(0);

        let mut total_commitment = vec![RistrettoPoint::identity(); max_length];

        for polynomial_commitment in polynomials_commitments {
            for (i, coeff_commitment) in
                polynomial_commitment.coefficients_commitments.iter().enumerate()
            {
                total_commitment[i] += coeff_commitment;
            }
        }

        PolynomialCommitment { coefficients_commitments: total_commitment }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        olaf::polynomial::{Coefficient, Polynomial, PolynomialCommitment},
        olaf::simplpedpop::GENERATOR,
    };

    use alloc::vec::Vec;
    use curve25519_dalek::Scalar;
    use rand::rngs::OsRng;

    #[test]
    fn test_generate_polynomial_commitment_valid() {
        let degree = 3;

        let polynomial = Polynomial::generate(&mut OsRng, degree);

        let polynomial_commitment = PolynomialCommitment::commit(&polynomial);

        assert_eq!(polynomial.coefficients.len(), degree as usize + 1);

        assert_eq!(polynomial_commitment.coefficients_commitments.len(), degree as usize + 1);
    }

    #[test]
    fn test_evaluate_polynomial() {
        let coefficients: Vec<Coefficient> =
            vec![Scalar::from(3u64), Scalar::from(2u64), Scalar::from(1u64)]; // Polynomial x^2 + 2x + 3

        let polynomial = Polynomial { coefficients };

        let value = Scalar::from(5u64); // x = 5

        let result = polynomial.evaluate(&value);

        assert_eq!(result, Scalar::from(38u64)); // 5^2 + 2*5 + 3
    }

    #[test]
    fn test_sum_secret_polynomial_commitments() {
        let polynomial_commitment1 = PolynomialCommitment {
            coefficients_commitments: vec![
                GENERATOR * Scalar::from(1u64), // Constant
                GENERATOR * Scalar::from(2u64), // Linear
                GENERATOR * Scalar::from(3u64), // Quadratic
            ],
        };

        let polynomial_commitment2 = PolynomialCommitment {
            coefficients_commitments: vec![
                GENERATOR * Scalar::from(4u64), // Constant
                GENERATOR * Scalar::from(5u64), // Linear
                GENERATOR * Scalar::from(6u64), // Quadratic
            ],
        };

        let summed_polynomial_commitments = PolynomialCommitment::sum_polynomial_commitments(&[
            &polynomial_commitment1,
            &polynomial_commitment2,
        ]);

        let expected_coefficients_commitments = vec![
            GENERATOR * Scalar::from(5u64), // 1 + 4 = 5
            GENERATOR * Scalar::from(7u64), // 2 + 5 = 7
            GENERATOR * Scalar::from(9u64), // 3 + 6 = 9
        ];

        assert_eq!(
            summed_polynomial_commitments.coefficients_commitments,
            expected_coefficients_commitments,
            "Coefficient commitments do not match"
        );
    }

    #[test]
    fn test_evaluate_polynomial_commitment() {
        // f(x) = 3 + 2x + x^2
        let constant_coefficient_commitment = Scalar::from(3u64) * GENERATOR;
        let linear_commitment = Scalar::from(2u64) * GENERATOR;
        let quadratic_commitment = Scalar::from(1u64) * GENERATOR;

        // Note the order and inclusion of the constant term
        let coefficients_commitments =
            vec![constant_coefficient_commitment, linear_commitment, quadratic_commitment];

        let polynomial_commitment = PolynomialCommitment { coefficients_commitments };

        let value = Scalar::from(2u64);

        // f(2) = 11
        let expected = Scalar::from(11u64) * GENERATOR;

        let result = polynomial_commitment.evaluate(&value);

        assert_eq!(result, expected, "The evaluated commitment does not match the expected result");
    }
}
