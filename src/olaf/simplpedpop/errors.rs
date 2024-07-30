//! Errors of the SimplPedPoP protocol.

use core::array::TryFromSliceError;
use crate::{PublicKey, SignatureError};

/// A result for the SimplPedPoP protocol.
pub type SPPResult<T> = Result<T, SPPError>;

/// An error ocurred during the execution of the SimplPedPoP protocol.
#[derive(Debug)]
pub enum SPPError {
    /// Invalid parameters.
    InvalidParameters,
    /// Threshold cannot be greater than the number of participants.
    ExcessiveThreshold,
    /// Threshold must be at least 2.
    InsufficientThreshold,
    /// Number of participants is invalid.
    InvalidNumberOfParticipants,
    /// Invalid public key.
    InvalidPublicKey(SignatureError),
    /// Invalid threshold public key.
    InvalidThresholdPublicKey,
    /// Invalid signature.
    InvalidSignature(SignatureError),
    /// Error deserializing signature.
    ErrorDeserializingSignature(SignatureError),
    /// Error deserializing proof of possession.
    ErrorDeserializingProofOfPossession(SignatureError),
    /// Invalid coefficient commitment of the polynomial commitment.
    InvalidCoefficientCommitment,
    /// Invalid identifier.
    InvalidIdentifier,
    /// Invalid secret share.
    InvalidSecretShare {
        /// The sender of the invalid secret share.
        culprit: PublicKey,
    },
    /// Deserialization Error.
    DeserializationError(TryFromSliceError),
    /// The parameters of all messages must be equal.
    DifferentParameters,
    /// The recipients hash of all messages must be equal.
    DifferentRecipientsHash,
    /// The number of messages should be 2 at least, which the minimum number of participants.
    InvalidNumberOfMessages,
    /// The number of coefficient commitments of the polynomial commitment must be equal to the threshold - 1.
    IncorrectNumberOfCoefficientCommitments,
    /// The number of encrypted shares per message must be equal to the number of participants.
    IncorrectNumberOfEncryptedShares,
    /// Decryption error when decrypting an encrypted secret share.
    DecryptionError(chacha20poly1305::Error),
    /// Encryption error when encrypting the secret share.
    EncryptionError(chacha20poly1305::Error),
    /// Invalid Proof of Possession.
    InvalidProofOfPossession(SignatureError),
    /// The messages are empty.
    EmptyMessages,
}

#[cfg(test)]
mod tests {
    use crate::olaf::simplpedpop::errors::SPPError;
    use crate::olaf::simplpedpop::types::{
        AllMessage, EncryptedSecretShare, CHACHA20POLY1305_LENGTH, RECIPIENTS_HASH_LENGTH,
    };
    use crate::olaf::test_utils::generate_parameters;
    use crate::{Keypair, PublicKey};
    use alloc::vec::Vec;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::traits::Identity;
    use merlin::Transcript;

    #[test]
    fn test_invalid_number_of_messages() {
        let parameters = generate_parameters();
        let participants = parameters.participants;
        let threshold = parameters.threshold;

        let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

        let mut messages: Vec<AllMessage> = keypairs
            .iter()
            .map(|kp| kp.simplpedpop_contribute_all(threshold, public_keys.clone()).unwrap())
            .collect();

        messages.pop();

        let result = keypairs[0].simplpedpop_recipient_all(&messages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::InvalidNumberOfMessages => assert!(true),
                _ => {
                    panic!("Expected DKGError::InvalidNumberOfMessages, but got {:?}", e)
                },
            },
        }
    }

    #[test]
    fn test_different_parameters() {
        let parameters = generate_parameters();
        let participants = parameters.participants;
        let threshold = parameters.threshold;

        let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

        let mut messages: Vec<AllMessage> = Vec::new();
        for i in 0..participants {
            let message = keypairs[i as usize]
                .simplpedpop_contribute_all(threshold, public_keys.clone())
                .unwrap();
            messages.push(message);
        }

        messages[1].content.parameters.threshold += 1;

        let result = keypairs[0].simplpedpop_recipient_all(&messages);

        // Check if the result is an error
        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::DifferentParameters => assert!(true),
                _ => panic!("Expected DKGError::DifferentParameters, but got {:?}", e),
            },
        }
    }

    #[test]
    fn test_different_recipients_hash() {
        let parameters = generate_parameters();
        let participants = parameters.participants;
        let threshold = parameters.threshold;

        let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

        let mut messages: Vec<AllMessage> = keypairs
            .iter()
            .map(|kp| kp.simplpedpop_contribute_all(threshold, public_keys.clone()).unwrap())
            .collect();

        messages[1].content.recipients_hash = [1; RECIPIENTS_HASH_LENGTH];

        let result = keypairs[0].simplpedpop_recipient_all(&messages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::DifferentRecipientsHash => assert!(true),
                _ => {
                    panic!("Expected DKGError::DifferentRecipientsHash, but got {:?}", e)
                },
            },
        }
    }

    #[test]
    fn test_incorrect_number_of_commitments() {
        let parameters = generate_parameters();
        let participants = parameters.participants;
        let threshold = parameters.threshold;

        let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

        let mut messages: Vec<AllMessage> = keypairs
            .iter()
            .map(|kp| kp.simplpedpop_contribute_all(threshold, public_keys.clone()).unwrap())
            .collect();

        messages[1].content.polynomial_commitment.coefficients_commitments.pop();

        let result = keypairs[0].simplpedpop_recipient_all(&messages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::IncorrectNumberOfCoefficientCommitments => assert!(true),
                _ => panic!(
                    "Expected DKGError::IncorrectNumberOfCoefficientCommitments, but got {:?}",
                    e
                ),
            },
        }
    }

    #[test]
    fn test_incorrect_number_of_encrypted_shares() {
        let parameters = generate_parameters();
        let participants = parameters.participants;
        let threshold = parameters.threshold;

        let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

        let mut messages: Vec<AllMessage> = keypairs
            .iter()
            .map(|kp| kp.simplpedpop_contribute_all(threshold, public_keys.clone()).unwrap())
            .collect();

        messages[1].content.encrypted_secret_shares.pop();

        let result = keypairs[0].simplpedpop_recipient_all(&messages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::IncorrectNumberOfEncryptedShares => assert!(true),
                _ => panic!("Expected DKGError::IncorrectNumberOfEncryptedShares, but got {:?}", e),
            },
        }
    }

    #[test]
    fn test_invalid_secret_share() {
        let parameters = generate_parameters();
        let participants = parameters.participants;
        let threshold = parameters.threshold;

        let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

        let mut messages: Vec<AllMessage> = keypairs
            .iter()
            .map(|kp| kp.simplpedpop_contribute_all(threshold, public_keys.clone()).unwrap())
            .collect();

        messages[1].content.encrypted_secret_shares[0] =
            EncryptedSecretShare(vec![1; CHACHA20POLY1305_LENGTH]);

        let result = keypairs[0].simplpedpop_recipient_all(&messages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::InvalidSecretShare { culprit } => {
                    assert_eq!(culprit, messages[1].content.sender);
                },
                _ => panic!("Expected DKGError::InvalidSecretShare, but got {:?}", e),
            },
        }
    }

    #[test]
    fn test_invalid_signature() {
        let parameters = generate_parameters();
        let participants = parameters.participants;
        let threshold = parameters.threshold;

        let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

        let mut messages: Vec<AllMessage> = keypairs
            .iter()
            .map(|kp| kp.simplpedpop_contribute_all(threshold, public_keys.clone()).unwrap())
            .collect();

        messages[1].signature =
            keypairs[1].secret.sign(Transcript::new(b"invalid"), &keypairs[1].public);

        let result = keypairs[0].simplpedpop_recipient_all(&messages);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::InvalidSignature(_) => assert!(true),
                _ => panic!("Expected DKGError::InvalidSignature, but got {:?}", e),
            },
        }
    }

    #[test]
    fn test_invalid_threshold() {
        let keypair = Keypair::generate();
        let result = keypair.simplpedpop_contribute_all(
            1,
            vec![
                PublicKey::from_point(RistrettoPoint::identity()),
                PublicKey::from_point(RistrettoPoint::identity()),
            ],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::InsufficientThreshold => assert!(true),
                _ => panic!("Expected SPPError::InsufficientThreshold, but got {:?}", e),
            },
        }
    }

    #[test]
    fn test_invalid_participants() {
        let keypair = Keypair::generate();
        let result = keypair
            .simplpedpop_contribute_all(2, vec![PublicKey::from_point(RistrettoPoint::identity())]);

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::InvalidNumberOfParticipants => {
                    assert!(true)
                },
                _ => {
                    panic!("Expected SPPError::InvalidNumberOfParticipants, but got {:?}", e)
                },
            },
        }
    }

    #[test]
    fn test_threshold_greater_than_participants() {
        let keypair = Keypair::generate();
        let result = keypair.simplpedpop_contribute_all(
            3,
            vec![
                PublicKey::from_point(RistrettoPoint::identity()),
                PublicKey::from_point(RistrettoPoint::identity()),
            ],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => match e {
                SPPError::ExcessiveThreshold => assert!(true),
                _ => panic!("Expected SPPError::ExcessiveThreshold), but got {:?}", e),
            },
        }
    }
}
