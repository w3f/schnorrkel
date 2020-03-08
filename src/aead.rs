// -*- mode: rust; -*-
//
// This file is part of schnorrkel.
// Copyright (c) 2019 Web 3 Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Jeff Burdges <jeff@web3.foundation>

//! Encryption using schnorrkel keys


// use rand_core::{RngCore,CryptoRng};

use ::aead::{NewAead, generic_array::{GenericArray}};

use curve25519_dalek::digest::generic_array::typenum::{U32};

use curve25519_dalek::{
    ristretto::{CompressedRistretto}, // RistrettoPoint
    // scalar::Scalar,
};

use super::{SecretKey,PublicKey,Keypair,SignatureResult};
use crate::context::SigningTranscript;

use crate::cert::ECQVCertPublic;


fn make_aead<T,AEAD>(mut t: T) -> AEAD 
where T: SigningTranscript,AEAD: NewAead
{
    let mut key: GenericArray<u8, <AEAD as NewAead>::KeySize> = Default::default();
    t.challenge_bytes(b"",key.as_mut_slice());
    AEAD::new(key)
}

impl SecretKey {
    /// Commit the results of a key exchange into a transcript
    #[inline(always)]
    pub(crate) fn raw_key_exchange(&self, public: &PublicKey) -> CompressedRistretto {
        (&self.key * public.as_point()).compress()
    }

    /// Commit the results of a raw key exchange into a transcript
    pub fn commit_raw_key_exchange<T>(&self, t: &mut T, ctx: &'static [u8], public: &PublicKey) 
    where T: SigningTranscript
    {
        let p = self.raw_key_exchange(public);
        t.commit_point(ctx, &p);
    }

    /// An AEAD from a key exchange with the specified public key.
    ///
    /// Requires the AEAD have a 32 byte public key and does not support a context.
    pub fn aead32_unauthenticated<AEAD>(&self, public: &PublicKey) -> AEAD 
    where AEAD: NewAead<KeySize=U32>
    {
        let mut key: GenericArray<u8, <AEAD as NewAead>::KeySize> = Default::default();
        key.clone_from_slice( self.raw_key_exchange(public).as_bytes() );
        AEAD::new(key)
    }
}

impl PublicKey {
    /// Initalize an AEAD to the public key `self` using an ephemeral key exchange.
    ///
    /// Returns the ephemeral public key and AEAD.
    pub fn init_aead_unauthenticated<AEAD: NewAead>(&self, ctx: &[u8]) -> (CompressedRistretto,AEAD) 
    {
        let ephemeral = Keypair::generate();
        let aead = ephemeral.aead_unauthenticated(ctx,self);
        (ephemeral.public.into_compressed(), aead)
    }

    /// Initalize an AEAD to the public key `self` using an ephemeral key exchange.
    ///
    /// Returns the ephemeral public key and AEAD.
    /// Requires the AEAD have a 32 byte public key and does not support a context.
    pub fn init_aead32_unauthenticated<AEAD>(&self) -> (CompressedRistretto,AEAD) 
    where AEAD: NewAead<KeySize=U32>
    {
        let secret = SecretKey::generate();
        let aead = secret.aead32_unauthenticated(self);
        (secret.to_public().into_compressed(), aead)
    }
}

impl Keypair {
    /// Commit the results of a key exchange into a transcript
    /// including the public keys in sorted order.
    pub fn commit_key_exchange<T>(&self, t: &mut T, ctx: &'static [u8], public: &PublicKey) 
    where T: SigningTranscript
    {
        let mut pks = [self.public.as_compressed(), public.as_compressed()];
        pks.sort_unstable_by_key( |pk| pk.as_bytes() );
        for pk in &pks { t.commit_point(b"pk",pk); }
        self.secret.commit_raw_key_exchange(t,ctx,public);
    }

    /// An AEAD from a key exchange with the specified public key.
    pub fn aead_unauthenticated<AEAD: NewAead>(&self, ctx: &[u8], public: &PublicKey) -> AEAD {
        let mut t = merlin::Transcript::new(b"KEX");
        t.append_message(b"ctx",ctx);
        self.commit_key_exchange(&mut t,b"kex",public);
        make_aead(t)
    }

    /// Reciever's 2DH AEAD
    pub fn reciever_aead<T,AEAD>(
        &self,
        mut t: T,
        ephemeral_pk: &PublicKey, 
        static_pk: &PublicKey,
    ) -> AEAD
    where T: SigningTranscript, AEAD: NewAead
    {
        self.commit_key_exchange(&mut t,b"epk",ephemeral_pk);
        self.commit_key_exchange(&mut t,b"epk",static_pk);
        make_aead(t)
    }

    /// Sender's 2DH AEAD
    pub fn sender_aead<T,AEAD>(
        &self,
        mut t: T,
        public: &PublicKey,
    ) -> (CompressedRistretto,AEAD)
    where T: SigningTranscript, AEAD: NewAead
    {
        let key = t.witness_scalar(b"make_esk", &[&self.secret.nonce]);
        let ekey = SecretKey { key, nonce: self.secret.nonce.clone() }.to_keypair();
        ekey.commit_key_exchange(&mut t,b"epk",public);
        self.commit_key_exchange(&mut t,b"epk",public);
        (ekey.public.into_compressed(), make_aead(t))
    }

    /// Reciever's AEAD with ECQV certificate.
    ///
    /// Returns the AEAD constructed from an ephemeral key exchange
    /// with the public key computed form the sender's public key
    /// and their implicit ECQV certificate.
    pub fn reciever_aead_with_ecqv_cert<T,AEAD>(
        &self, 
        t: T, 
        cert_public: &ECQVCertPublic, 
        public: &PublicKey,
    ) -> SignatureResult<AEAD> 
    where T: SigningTranscript, AEAD: NewAead
    {
        let epk = public.open_ecqv_cert(t,cert_public) ?;
        Ok(self.aead_unauthenticated(b"",&epk))
    }

    /// Sender's AEAD with ECQV certificate.
    ///
    /// Along with the AEAD, we return the implicit ECQV certificate
    /// from which the reciever recreates the ephemeral public key.
    pub fn sender_aead_with_ecqv_cert<T,AEAD>(&self, t: T, public: &PublicKey) -> (ECQVCertPublic,AEAD) 
    where T: SigningTranscript+Clone, AEAD: NewAead
    {
        let (cert,secret) = self.issue_self_ecqv_cert(t);
        let aead = secret.to_keypair().aead_unauthenticated(b"",&public);
        (cert, aead)
    }
}

/*
#[cfg(test)]
mod test {
    use super::super::*;
}
*/
