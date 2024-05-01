
// It's irrelevant if we're in the recipiants or not ???


type SPPResult<T> = Result<T,???>;

pub struct Parameters {
    pub threshold: u16,
    pub participants: u16,
}

impl Parameters {
    pub fn check(&self) -> SPPResult<()> { .. }

    pub fn commit<T: SigningTranscript>(&self, t: &mut T) {
        t.commit_bytes(b"threshold", &self.threshold.to_le_bytes());
        t.commit_bytes(b"participants", &self.participants.to_le_bytes());
    }
}

/// Compute identifier aka evaluation position scalar from recipiants_hash
/// and recipiant index.
///
/// We'd ideally hash the recipiant's PublicKey here, instead, except 
pub fn identifier(recipiants_hash: &[u8; 16], index: u16) -> Scalar {
    let mut pos = merlin::Transcript::new(b"Identifier");
    pos.commit_bytes(b"RecipiantsHash", &recipiants_hash);
    pos.commit_bytes(b"i", index.to_le_bytes());
    // let i = usize::from(i);
    // e.commit_point(b"recipiant", recipiants[i].as_compressed());
    pos.challenge_scalar(b"evaluation position");
}

impl Keypair {
    pub fn simplpedpop_contribute_all(
        &self,
        threshold: u16,
        mut recipiants: Vec<PublicKey>,
    ) -> SPPResult<AllMessage>
    {
        let parameters = Parameters { threshold, participants: recipiants.len() };
        parameters.check() ?;

        // We do not  recipiants.sort() because the protocol is simpler
        // if we require that all contributions provide the list in
        // exactly the same order.
        //
        // Instead we create a kind of session id by hashing the list
        // provided, but we provide only hash to recipiants, not the
        // full recipiants list.  
        let mut t = merlin::Transcript::new(b"RecipiantsHash");
        parameters.commit(&mut t);
        for r in recipiants.iter() {
            t.commit_point(b"recipiant", r.as_compressed());
        }
        let mut recipiants_hash = [0u8; 16];
        t.challenge_bytes(b"finalize", &mut recipiants_hash);

        for i in [0..parameters.participants] {
            let mut p = t.clone
        }

        // uses identifier(recipiants_hash, i)
        let point_polynomial = ...
        let scalar_evaluations = ...

        // All this custom encrhyption mess saves 32 bytes per recipiant
        // over chacha20poly1305, so maybe not worth the trouble.

        let mut enc0 = merlin::Transcript::new(b"Encryption");
        parameters.commit(&mut enc0);
        enc0.commit_point(b"contributor", self.public.as_compressed());

        encrypton_nonce = [0u8; 16];
        super::getrandom_or_panic().fill_bytes(&mut encrypton_nonce);
        enc0.commit_bytes(b"nonce", &encrypton_nonce);

        let mut ciphertexts = scalar_evaluations;
        for i in [0..parameters.participants] {
            let mut e = enc0.clone();
            // We tweak by i too since encrypton_nonce is not truly a nonce.
            e.commit_bytes(b"i", &i.to_le_bytes());
            let i = usize::from(i);

            e.commit_point(b"recipiant", recipiants[i].as_compressed());
            keypair.secret.commit_raw_key_exchange(&mut e, b"kex", r);

            // Afaik redundant for merlin, but attacks get better.
            e.commit_bytes(b"nonce", &encrypton_nonce);

            // As this is encryption, we require similar security properties
            // as from witness_bytes here, but without randomness, and
            // challenge_scalar is imeplemented close enough.
            ciphertexts[i] += e.challenge_scalar(b"encryption scalar");
        }

        let sender = self.public.to_bytesd();
        Ok(Message { sender, encrypton_nonce, parameters, recipiants_hash, point_polynomial, ciphertexts, })
    }
}

/// AllMessage packs together messages for all participants.
///
/// We'd save bandwidth by having seperate messages for each 
/// participant, but typical thresholds lie between 1/2 and 2/3,
/// so this doubles or tripples bandwidth usage.
pub struct AllMessage {
    sender: PublicKey,
    encrypton_nonce: [u8; 16], 
    parameters: Parameters,
    recipiants_hash: [u8; 16],
    point_polynomial: Vec<RistrettoPoint>,
    ciphertexts: Vec<Scalar>,
    signature: Signature,
}

impl AllMessage {
    pub fn to_bytes(self) -> Vec<u8> { ... }
    pub fn from_bytes(&[u8]) -> SPPResult<Message> { ... }
}

impl Keypair {
    pub fn simplpedpop_recipiant_all(
        &self,
        index: u16,
        messages: &[AllMessage],
    ) -> >???
    {
        ;
    }
)

