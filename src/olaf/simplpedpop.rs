//! Implementation of a modified version of SimplPedPoP (<https://eprint.iacr.org/2023/899>), a DKG based on PedPoP, which in turn is based
//! on Pedersen's DKG. All of them have as the fundamental building block the Shamir's Secret Sharing scheme.
//!
//! The modification consists of each participant sending the secret shares of the other participants only in round 2
//! instead of in round 1. The reason for this is we use the secret commitments (the evaluations of the secret polynomial
//! commitments at zero) of round 1 to assign the identifiers of all the participants in round 2, which will then be
//! used to compute the corresponding secret shares. Finally, we encrypt and authenticate the secret shares with
//! Chacha20Poly1305, meaning they can be distributed to the participants by an untrusted coordinator instead of sending
//! them directly.
//!
//! The protocol is divided into three rounds. In each round some data and some messages are produced and some messages
//! are verified (if received from a previous round). Data is divided into public and private because in a given round we
//! want to pass a reference to the public data (performance reasons) and the private data itself so that it is zeroized
//! after getting out of scope (security reasons). Public messages are destined to all the other participants, while private
//! messages are destined to a single participant.

use crate::{aead::make_aead, context::SigningTranscript, SecretKey, Signature};
use alloc::{collections::BTreeSet, vec::Vec};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Nonce};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use derive_getters::Getters;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use super::{
    errors::{DKGError, DKGResult},
    identifier::Identifier,
    polynomial::{Coefficient, CoefficientCommitment, Polynomial, PolynomialCommitment},
};

pub(crate) const GENERATOR: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

pub(crate) type SecretPolynomialCommitment = PolynomialCommitment;
pub(crate) type SecretPolynomial = Polynomial;
pub(crate) type TotalSecretShare = SecretShare;
pub(crate) type SecretCommitment = CoefficientCommitment;
pub(crate) type Certificate = Signature;
pub(crate) type ProofOfPossession = Signature;
pub(crate) type Secret = Coefficient;

/// The parameters of a given execution of the SimplPedPoP protocol.
#[derive(Debug, Clone, Getters)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Parameters {
    pub(crate) participants: u16,
    pub(crate) threshold: u16,
}

impl Parameters {
    /// Create new parameters.
    pub fn new(participants: u16, threshold: u16) -> Parameters {
        Parameters {
            participants,
            threshold,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), DKGError> {
        if self.threshold < 2 {
            return Err(DKGError::InsufficientThreshold);
        }

        if self.participants < 2 {
            return Err(DKGError::InvalidNumberOfParticipants);
        }

        if self.threshold > self.participants {
            return Err(DKGError::ExcessiveThreshold);
        }

        Ok(())
    }
}

/// The participants of a given execution of the SimplPedPoP protocol.
#[derive(Debug, Clone, Getters)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Identifiers {
    pub(crate) own_identifier: Identifier,
    pub(crate) others_identifiers: BTreeSet<Identifier>,
}

impl Identifiers {
    /// Create new participants.
    pub fn new(
        own_identifier: Identifier,
        others_identifiers: BTreeSet<Identifier>,
    ) -> Identifiers {
        Identifiers {
            own_identifier,
            others_identifiers,
        }
    }

    pub(crate) fn validate(&self, participants: u16) -> Result<(), DKGError> {
        if self.own_identifier.0 == Scalar::ZERO {
            return Err(DKGError::InvalidIdentifier);
        }

        for other_identifier in &self.others_identifiers {
            if other_identifier.0 == Scalar::ZERO {
                return Err(DKGError::InvalidIdentifier);
            }
        }

        if self.others_identifiers.len() != participants as usize - 1 {
            return Err(DKGError::IncorrectNumberOfIdentifiers {
                expected: participants as usize,
                actual: self.others_identifiers.len() + 1,
            });
        }

        Ok(())
    }
}

fn derive_secret_key_from_secret<R: RngCore + CryptoRng>(secret: &Secret, mut rng: R) -> SecretKey {
    let mut bytes = [0u8; 64];
    let mut nonce: [u8; 32] = [0u8; 32];

    rng.fill_bytes(&mut nonce);
    let secret_bytes = secret.to_bytes();

    bytes[..32].copy_from_slice(&secret_bytes[..]);
    bytes[32..].copy_from_slice(&nonce[..]);

    SecretKey::from_bytes(&bytes[..]).unwrap() // This never fails because bytes has length 64 and the key is a scalar
}

/// A secret share, which corresponds to an evaluation of a value that identifies a participant in a secret polynomial.
#[derive(Debug, Clone, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SecretShare(pub(crate) Scalar);

impl SecretShare {
    pub(crate) fn encrypt(
        &self,
        decryption_key: &Scalar,
        encryption_key: &RistrettoPoint,
        context: &[u8],
    ) -> EncryptedSecretShare {
        let shared_secret = decryption_key * encryption_key;

        let mut transcript = Transcript::new(b"encryption");
        transcript.commit_point(b"shared secret", &shared_secret.compress());
        transcript.append_message(b"context", context);

        let mut bytes = [0; 12];
        transcript.challenge_bytes(b"nonce", &mut bytes);

        let cipher: ChaCha20Poly1305 = make_aead::<Transcript, ChaCha20Poly1305>(transcript);
        let nonce = Nonce::from_slice(&bytes[..]);

        let ciphertext: Vec<u8> = cipher.encrypt(nonce, &self.0.as_bytes()[..]).unwrap();

        EncryptedSecretShare(ciphertext)
    }
}

/// An encrypted secret share, which can be sent directly to the intended participant or through an untrusted coordinator.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EncryptedSecretShare(pub(crate) Vec<u8>);

impl EncryptedSecretShare {
    pub(crate) fn decrypt(
        &self,
        decryption_key: &Scalar,
        encryption_key: &RistrettoPoint,
        context: &[u8],
    ) -> DKGResult<SecretShare> {
        let shared_secret = decryption_key * encryption_key;

        let mut transcript = Transcript::new(b"encryption");
        transcript.commit_point(b"shared secret", &shared_secret.compress());
        transcript.append_message(b"context", context);

        let mut bytes = [0; 12];
        transcript.challenge_bytes(b"nonce", &mut bytes);

        let cipher: ChaCha20Poly1305 = make_aead::<Transcript, ChaCha20Poly1305>(transcript);
        let nonce = Nonce::from_slice(&bytes[..]);

        let plaintext = cipher
            .decrypt(nonce, &self.0[..])
            .map_err(DKGError::DecryptionError)?;

        let mut bytes = [0; 32];
        bytes.copy_from_slice(&plaintext);

        Ok(SecretShare(Scalar::from_bytes_mod_order(bytes)))
    }
}

/// SimplPedPoP round 1.
///
/// The participant commits to a secret polynomial f(x) of degree t-1, where t is the threshold of the DKG, by commiting
/// to each one of the t coefficients of the secret polynomial.
///
/// It derives a secret key from the secret of the polynomial f(0) and uses it to generate a Proof of Possession of that
/// secret by signing a message with the secret key.
pub mod round1 {
    use super::{
        derive_secret_key_from_secret, Parameters, ProofOfPossession, SecretPolynomial,
        SecretPolynomialCommitment,
    };
    use crate::{
        olaf::errors::DKGResult,
        olaf::polynomial::{Polynomial, PolynomialCommitment},
        PublicKey, SecretKey,
    };
    use core::cmp::Ordering;
    use curve25519_dalek::Scalar;
    use merlin::Transcript;
    use rand_core::{CryptoRng, RngCore};

    /// The private data generated by the participant in round 1.
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PrivateData {
        pub(crate) secret_key: SecretKey,
        pub(crate) secret_polynomial: SecretPolynomial,
    }

    /// The public data generated by the participant in round 1.
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PublicData {
        pub(crate) parameters: Parameters,
        pub(crate) secret_polynomial_commitment: SecretPolynomialCommitment,
        pub(crate) proof_of_possession: ProofOfPossession,
    }

    /// Public message to be sent by the participant to all the other participants or to the coordinator in round 1.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PublicMessage {
        pub(crate) secret_polynomial_commitment: SecretPolynomialCommitment,
        pub(crate) proof_of_possession: ProofOfPossession,
    }

    impl PublicMessage {
        /// Creates a new public message.
        pub fn new(public_data: &PublicData) -> PublicMessage {
            PublicMessage {
                secret_polynomial_commitment: public_data.secret_polynomial_commitment.clone(),
                proof_of_possession: public_data.proof_of_possession,
            }
        }
    }

    impl PartialOrd for PublicMessage {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for PublicMessage {
        fn cmp(&self, other: &Self) -> Ordering {
            self.secret_polynomial_commitment
                .coefficients_commitments
                .first()
                .unwrap()
                .compress()
                .0
                .cmp(
                    &other
                        .secret_polynomial_commitment
                        .coefficients_commitments
                        .first()
                        .unwrap()
                        .compress()
                        .0,
                )
        }
    }

    /// Runs the round 1 of the SimplPedPoP protocol.
    pub fn run<R: RngCore + CryptoRng>(
        parameters: Parameters,
        mut rng: R,
    ) -> DKGResult<(PrivateData, PublicMessage, PublicData)> {
        parameters.validate()?;

        let (private_data, public_data) = generate_data(parameters, &mut rng);

        let public_message = PublicMessage::new(&public_data);

        Ok((private_data, public_message, public_data))
    }

    fn generate_data<R: RngCore + CryptoRng>(
        parameters: Parameters,
        mut rng: R,
    ) -> (PrivateData, PublicData) {
        let secret_polynomial = loop {
            let temp_polynomial = Polynomial::generate(&mut rng, *parameters.threshold() - 1);
            // There must be a secret, which is the constant coefficient of the secret polynomial
            if temp_polynomial.coefficients.first().unwrap() != &Scalar::ZERO {
                break temp_polynomial;
            }
        };

        let secret_polynomial_commitment = PolynomialCommitment::commit(&secret_polynomial);

        // This secret key will be used to sign the proof of possession and the certificate
        let secret_key =
            derive_secret_key_from_secret(secret_polynomial.coefficients.first().unwrap(), rng);

        let public_key = PublicKey::from_point(
            *secret_polynomial_commitment
                .coefficients_commitments
                .first()
                .unwrap(),
        );

        let proof_of_possession =
            secret_key.sign(Transcript::new(b"Proof of Possession"), &public_key);

        (
            PrivateData {
                secret_key,
                secret_polynomial,
            },
            PublicData {
                parameters,
                secret_polynomial_commitment,
                proof_of_possession,
            },
        )
    }
}

/// SimplPedPoP round 2.
///
/// The participant verifies the received messages of the other participants from round 1, the secret polynomial commitments
/// and the Proofs of Possession.
///
/// It orders the secret commitments and uses that ordering to assing random identifiers to all the participants in the
/// protocol, including its own.
///
/// It computes the secret shares of each participant based on their identifiers, encrypts and authenticates them using
/// Chacha20Poly1305 with a shared secret.
///
/// It signs a transcript of the protocol execution (certificate) with its secret key, which contains the PoPs and the
/// polynomial commitments from all the participants (including its own).
pub mod round2 {
    use super::{
        round1, Certificate, EncryptedSecretShare, Identifier, Identifiers, Parameters,
        SecretCommitment, SecretPolynomial, SecretShare,
    };
    use crate::{
        context::SigningTranscript,
        olaf::errors::{DKGError, DKGResult},
        verify_batch, PublicKey, SecretKey,
    };
    use alloc::{
        collections::{BTreeMap, BTreeSet},
        string::ToString,
        vec,
        vec::Vec,
    };
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use derive_getters::Getters;
    use merlin::Transcript;
    use sha2::{digest::Update, Digest, Sha512};

    /// The public data of round 2.
    #[derive(Debug, Clone, Getters)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PublicData {
        pub(crate) identifiers: Identifiers,
        pub(crate) round1_public_messages: BTreeMap<Identifier, round1::PublicMessage>,
        pub(crate) transcript: Scalar,
        pub(crate) public_keys: Vec<PublicKey>,
    }

    /// The public message of round 2.
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PublicMessage {
        pub(crate) certificate: Certificate,
    }

    /// Private message to sent by a participant to another participant or to the coordinator in encrypted form in round 1.
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PrivateMessage {
        pub(crate) encrypted_secret_share: EncryptedSecretShare,
    }

    impl PrivateMessage {
        /// Creates a new private message.
        pub fn new(
            secret_share: SecretShare,
            deckey: Scalar,
            enckey: RistrettoPoint,
            context: &[u8],
        ) -> PrivateMessage {
            let encrypted_secret_share = secret_share.encrypt(&deckey, &enckey, context);

            PrivateMessage {
                encrypted_secret_share,
            }
        }
    }

    /// The messages to be sent by the participant in round 2.
    #[derive(Debug, Clone, Getters)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Messages {
        // The identifier is the intended recipient of the private message.
        private_messages: BTreeMap<Identifier, PrivateMessage>,
        public_message: PublicMessage,
    }

    fn validate_messages(
        parameters: &Parameters,
        round1_public_messages: &BTreeSet<round1::PublicMessage>,
    ) -> DKGResult<()> {
        if round1_public_messages.len() != *parameters.participants() as usize - 1 {
            return Err(DKGError::IncorrectNumberOfRound1PublicMessages {
                expected: *parameters.participants() as usize - 1,
                actual: round1_public_messages.len(),
            });
        }

        for round1_public_message in round1_public_messages {
            if round1_public_message
                .secret_polynomial_commitment
                .coefficients_commitments
                .len()
                != *parameters.threshold() as usize
            {
                return Err(DKGError::InvalidSecretPolynomialCommitment {
                    expected: *parameters.threshold() as usize,
                    actual: round1_public_message
                        .secret_polynomial_commitment
                        .coefficients_commitments
                        .len(),
                });
            }
        }

        Ok(())
    }

    /// Runs the round 2 of a SimplPedPoP protocol.
    pub fn run<T: SigningTranscript + Clone>(
        round1_private_data: round1::PrivateData,
        round1_public_data: &round1::PublicData,
        round1_public_messages: BTreeSet<round1::PublicMessage>,
        transcript: T,
    ) -> DKGResult<(PublicData, Messages)> {
        round1_public_data.parameters.validate()?;

        validate_messages(&round1_public_data.parameters, &round1_public_messages)?;

        let public_keys = verify_round1_messages(&round1_public_messages)?;

        let public_data = generate_public_data(
            round1_public_messages,
            round1_public_data,
            transcript,
            public_keys,
        );

        let secret_commitment = round1_public_data
            .secret_polynomial_commitment
            .coefficients_commitments
            .first()
            .unwrap();

        let messages = generate_messages(
            &public_data,
            &round1_private_data.secret_polynomial,
            round1_private_data.secret_key,
            secret_commitment,
        );

        Ok((public_data, messages))
    }

    fn generate_public_data<T: SigningTranscript + Clone>(
        round1_public_messages: BTreeSet<round1::PublicMessage>,
        round1_public_data: &round1::PublicData,
        mut transcript: T,
        public_keys: Vec<PublicKey>,
    ) -> PublicData {
        let mut own_inserted = false;

        let own_first_coefficient_compressed = round1_public_data
            .secret_polynomial_commitment
            .coefficients_commitments
            .first()
            .unwrap()
            .compress();

        // Writes the data of all the participants in the transcript ordered by their identifiers
        for message in &round1_public_messages {
            let message_first_coefficient_compressed = message
                .secret_polynomial_commitment
                .coefficients_commitments
                .first()
                .unwrap()
                .compress();

            if own_first_coefficient_compressed.0 < message_first_coefficient_compressed.0
                && !own_inserted
            {
                // Writes own data in the transcript
                transcript.commit_point(b"SecretCommitment", &own_first_coefficient_compressed);

                for coefficient_commitment in &round1_public_data
                    .secret_polynomial_commitment
                    .coefficients_commitments
                {
                    transcript
                        .commit_point(b"CoefficientCommitment", &coefficient_commitment.compress());
                }

                transcript.commit_point(
                    b"ProofOfPossessionR",
                    &round1_public_data.proof_of_possession.R,
                );

                own_inserted = true;
            }
            // Writes the data of the other participants in the transcript
            transcript.commit_point(b"SecretCommitment", &message_first_coefficient_compressed);

            for coefficient_commitment in &message
                .secret_polynomial_commitment
                .coefficients_commitments
            {
                transcript
                    .commit_point(b"CoefficientCommitment", &coefficient_commitment.compress());
            }

            transcript.commit_point(b"ProofOfPossessionR", &message.proof_of_possession.R);
        }

        // Writes own data in the transcript if own identifier is the last one
        if !own_inserted {
            transcript.commit_point(b"SecretCommitment", &own_first_coefficient_compressed);

            for coefficient_commitment in &round1_public_data
                .secret_polynomial_commitment
                .coefficients_commitments
            {
                transcript
                    .commit_point(b"CoefficientCommitment", &coefficient_commitment.compress());
            }

            transcript.commit_point(
                b"ProofOfPossessionR",
                &round1_public_data.proof_of_possession.R,
            );
        }

        // Scalar generated from transcript used to generate random identifiers to the participants
        let scalar = transcript.challenge_scalar(b"participants");

        let (identifiers, round1_public_messages) =
            generate_identifiers(round1_public_data, round1_public_messages, &scalar);

        PublicData {
            identifiers,
            round1_public_messages,
            transcript: scalar,
            public_keys,
        }
    }

    fn generate_identifiers(
        round1_public_data: &round1::PublicData,
        round1_public_messages_set: BTreeSet<round1::PublicMessage>,
        scalar: &Scalar,
    ) -> (Identifiers, BTreeMap<Identifier, round1::PublicMessage>) {
        let mut others_identifiers: BTreeSet<Identifier> = BTreeSet::new();
        let mut round1_public_messages: BTreeMap<Identifier, round1::PublicMessage> =
            BTreeMap::new();

        let mut secret_commitments: BTreeSet<[u8; 32]> = round1_public_messages_set
            .iter()
            .map(|msg| {
                msg.secret_polynomial_commitment
                    .coefficients_commitments
                    .first()
                    .unwrap()
                    .compress()
                    .0
            })
            .collect();

        let own_secret_commitment = round1_public_data
            .secret_polynomial_commitment
            .coefficients_commitments
            .first()
            .unwrap();

        secret_commitments.insert(own_secret_commitment.compress().0);

        let mut index = 0;
        for message in &secret_commitments {
            if message == &own_secret_commitment.compress().0 {
                break;
            }
            index += 1;
        }

        for i in 0..secret_commitments.len() {
            let input = Sha512::new().chain(scalar.as_bytes()).chain(i.to_string());
            let random_scalar = Scalar::from_hash(input);
            others_identifiers.insert(Identifier(random_scalar));
        }

        let own_identifier = *others_identifiers.iter().nth(index).unwrap();
        others_identifiers.remove(&own_identifier);

        for (id, message) in others_identifiers.iter().zip(round1_public_messages_set) {
            round1_public_messages.insert(*id, message);
        }

        let identifiers = Identifiers::new(own_identifier, others_identifiers);

        (identifiers, round1_public_messages)
    }

    fn verify_round1_messages(
        round1_public_messages: &BTreeSet<round1::PublicMessage>,
    ) -> DKGResult<Vec<PublicKey>> {
        let len = round1_public_messages.len();
        let mut public_keys = Vec::with_capacity(len);
        let mut proofs_of_possession = Vec::with_capacity(len);

        // The public keys are the secret commitments of the participants
        for round1_public_message in round1_public_messages {
            let public_key = PublicKey::from_point(
                *round1_public_message
                    .secret_polynomial_commitment
                    .coefficients_commitments
                    .first()
                    .unwrap(),
            );
            public_keys.push(public_key);
            proofs_of_possession.push(round1_public_message.proof_of_possession);
        }

        verify_batch(
            vec![Transcript::new(b"Proof of Possession"); len],
            &proofs_of_possession[..],
            &public_keys[..],
            false,
        )
        .map_err(DKGError::InvalidProofOfPossession)?;

        Ok(public_keys)
    }

    fn generate_messages(
        round2_public_data: &PublicData,
        secret_polynomial: &SecretPolynomial,
        secret_key: SecretKey,
        secret_commitment: &SecretCommitment,
    ) -> Messages {
        let mut private_messages = BTreeMap::new();
        let enc_keys: Vec<RistrettoPoint> = round2_public_data
            .round1_public_messages
            .values()
            .map(|msg| {
                *msg.secret_polynomial_commitment
                    .coefficients_commitments
                    .first()
                    .unwrap()
            })
            .collect();

        for (i, identifier) in round2_public_data
            .identifiers
            .others_identifiers
            .iter()
            .enumerate()
        {
            let secret_share = secret_polynomial.evaluate(&identifier.0);
            private_messages.insert(
                *identifier,
                PrivateMessage::new(
                    SecretShare(secret_share),
                    secret_key.key,
                    enc_keys[i],
                    identifier.0.as_bytes(),
                ),
            );
        }

        let public_key = PublicKey::from_point(*secret_commitment);

        let mut transcript = Transcript::new(b"certificate");
        transcript.append_message(b"scalar", round2_public_data.transcript.as_bytes());

        let certificate = secret_key.sign(transcript, &public_key);

        let public_message = PublicMessage { certificate };

        Messages {
            private_messages,
            public_message,
        }
    }
}

/// SimplPedPoP round 3.
///
/// The participant decrypts and verifies the secret shares received from the other participants from round 2, computes
/// its own secret share and its own total secret share, which corresponds to its share of the group public key.
///
/// It verifies the certificates from all the other participants and generates the shared public
/// key and the total secret shares commitments of the other partipants.
pub mod round3 {
    use super::{
        round1, round2, Certificate, Identifier, Identifiers, Parameters, SecretPolynomial,
        SecretShare, TotalSecretShare, GENERATOR,
    };
    use crate::{
        context::SigningTranscript,
        olaf::{
            errors::{DKGError, DKGResult},
            keys::{GroupPublicKey, GroupPublicKeyShare},
            polynomial::PolynomialCommitment,
        },
        verify_batch,
    };
    use alloc::{collections::BTreeMap, vec, vec::Vec};
    use curve25519_dalek::Scalar;
    use derive_getters::Getters;
    use merlin::Transcript;
    use zeroize::ZeroizeOnDrop;

    /// The private data of round 3.
    #[derive(Debug, Clone, ZeroizeOnDrop, Getters)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PrivateData {
        pub(crate) total_secret_share: TotalSecretShare,
    }

    fn validate_messages(
        parameters: &Parameters,
        round2_public_messages: &BTreeMap<Identifier, round2::PublicMessage>,
        round1_public_messages: &BTreeMap<Identifier, round1::PublicMessage>,
        round2_private_messages: &BTreeMap<Identifier, round2::PrivateMessage>,
    ) -> DKGResult<()> {
        if round2_public_messages.len() != *parameters.participants() as usize - 1 {
            return Err(DKGError::IncorrectNumberOfRound2PublicMessages {
                expected: *parameters.participants() as usize - 1,
                actual: round2_public_messages.len(),
            });
        }

        if round1_public_messages.len() != *parameters.participants() as usize - 1 {
            return Err(DKGError::IncorrectNumberOfRound1PublicMessages {
                expected: *parameters.participants() as usize - 1,
                actual: round1_public_messages.len(),
            });
        }

        if round2_private_messages.len() != *parameters.participants() as usize - 1 {
            return Err(DKGError::IncorrectNumberOfRound2PrivateMessages {
                expected: *parameters.participants() as usize - 1,
                actual: round2_private_messages.len(),
            });
        }

        Ok(())
    }

    /// Runs the round 3 of the SimplPedPoP protocol.
    pub fn run(
        round2_public_messages: &BTreeMap<Identifier, round2::PublicMessage>,
        round2_public_data: &round2::PublicData,
        round1_public_data: &round1::PublicData,
        round1_private_data: round1::PrivateData,
        round2_private_messages: &BTreeMap<Identifier, round2::PrivateMessage>,
    ) -> DKGResult<(
        GroupPublicKey,
        BTreeMap<Identifier, GroupPublicKeyShare>,
        PrivateData,
    )> {
        round1_public_data.parameters.validate()?;

        round2_public_data
            .identifiers
            .validate(round1_public_data.parameters.participants)?;

        validate_messages(
            &round1_public_data.parameters,
            round2_public_messages,
            &round2_public_data.round1_public_messages,
            round2_private_messages,
        )?;

        let mut transcript = Transcript::new(b"certificate");
        transcript.append_message(b"scalar", round2_public_data.transcript.as_bytes());

        verify_round2_public_messages(round2_public_messages, round2_public_data, transcript)?;

        let secret_shares = verify_round2_private_messages(
            round2_public_data,
            round2_private_messages,
            &round1_private_data.secret_key.key,
        )?;

        let private_data = generate_private_data(
            &round2_public_data.identifiers,
            &secret_shares,
            &round1_private_data.secret_polynomial,
        )?;

        let (group_public_key, group_public_key_shares) =
            generate_public_data(round2_public_data, round1_public_data, &private_data)?;

        Ok((group_public_key, group_public_key_shares, private_data))
    }

    fn verify_round2_public_messages<T: SigningTranscript + Clone>(
        round2_public_messages: &BTreeMap<Identifier, round2::PublicMessage>,
        round2_public_data: &round2::PublicData,
        transcript: T,
    ) -> DKGResult<()> {
        verify_batch(
            vec![transcript.clone(); round2_public_data.identifiers.others_identifiers.len()],
            &round2_public_messages
                .iter()
                .map(|(id, msg)| {
                    if !round2_public_data
                        .identifiers
                        .others_identifiers()
                        .contains(id)
                    {
                        Err(DKGError::UnknownIdentifierRound2PublicMessages(*id))
                    } else {
                        Ok(msg.certificate)
                    }
                })
                .collect::<Result<Vec<Certificate>, DKGError>>()?,
            &round2_public_data.public_keys[..],
            false,
        )
        .map_err(DKGError::InvalidCertificate)
    }

    fn verify_round2_private_messages(
        round2_public_data: &round2::PublicData,
        round2_private_messages: &BTreeMap<Identifier, round2::PrivateMessage>,
        secret: &Scalar,
    ) -> DKGResult<BTreeMap<Identifier, SecretShare>> {
        let mut secret_shares = BTreeMap::new();

        for (i, (identifier, private_message)) in round2_private_messages.iter().enumerate() {
            if !round2_public_data
                .identifiers
                .others_identifiers
                .contains(identifier)
            {
                return Err(DKGError::UnknownIdentifierRound2PrivateMessages(
                    *identifier,
                ));
            }

            let secret_share = private_message.encrypted_secret_share.decrypt(
                secret,
                &round2_public_data.public_keys[i].into_point(),
                round2_public_data.identifiers.own_identifier.0.as_bytes(),
            )?;

            let expected_evaluation = GENERATOR * secret_share.0;

            secret_shares.insert(*identifier, secret_share);

            let evaluation = round2_public_data
                .round1_public_messages
                .get(identifier)
                .unwrap()
                .secret_polynomial_commitment
                .evaluate(&round2_public_data.identifiers.own_identifier.0);

            if !(evaluation == expected_evaluation) {
                return Err(DKGError::InvalidSecretShare(*identifier));
            }
        }

        Ok(secret_shares)
    }

    fn generate_private_data(
        identifiers: &Identifiers,
        secret_shares: &BTreeMap<Identifier, SecretShare>,
        secret_polynomial: &SecretPolynomial,
    ) -> DKGResult<PrivateData> {
        let own_secret_share = secret_polynomial.evaluate(&identifiers.own_identifier.0);

        let mut total_secret_share = Scalar::ZERO;

        for id in &identifiers.others_identifiers {
            // This never fails because we previously checked
            total_secret_share += secret_shares.get(id).unwrap().0;
        }

        total_secret_share += own_secret_share;

        let private_data = PrivateData {
            total_secret_share: SecretShare(total_secret_share),
        };

        Ok(private_data)
    }

    fn generate_public_data(
        round2_public_data: &round2::PublicData,
        round1_public_data: &round1::PublicData,
        round2_private_data: &PrivateData,
    ) -> DKGResult<(GroupPublicKey, BTreeMap<Identifier, GroupPublicKeyShare>)> {
        // Sum of the secret polynomial commitments of the other participants
        let others_secret_polynomial_commitment = PolynomialCommitment::sum_polynomial_commitments(
            &round2_public_data
                .round1_public_messages
                .values()
                .map(|msg| &msg.secret_polynomial_commitment)
                .collect::<Vec<&PolynomialCommitment>>(),
        );

        // The total secret polynomial commitment, which includes the secret polynomial commitment of the participant
        let total_secret_polynomial_commitment =
            PolynomialCommitment::sum_polynomial_commitments(&[
                &others_secret_polynomial_commitment,
                &round1_public_data.secret_polynomial_commitment,
            ]);

        // The group public key shares of all the participants, which correspond to the total secret shares commitments
        let mut group_public_key_shares = BTreeMap::new();

        for identifier in &round2_public_data.identifiers.others_identifiers {
            let group_public_key_share = total_secret_polynomial_commitment.evaluate(&identifier.0);

            group_public_key_shares.insert(*identifier, group_public_key_share);
        }

        let own_group_public_key_share = round2_private_data.total_secret_share.0 * GENERATOR;

        group_public_key_shares.insert(
            round2_public_data.identifiers.own_identifier,
            own_group_public_key_share,
        );

        let shared_public_key = GroupPublicKey::from_point(
            *total_secret_polynomial_commitment
                .coefficients_commitments
                .first()
                .unwrap(),
        );

        Ok((shared_public_key, group_public_key_shares))
    }
}
