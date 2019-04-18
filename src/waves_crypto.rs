use base58::*;
use curve25519_dalek::constants;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::*;
use ed25519_dalek::{PublicKey as EDXPUB, Signature as EDSIG};
use std::vec::*;

fn keccak256(message: &[u8]) -> Vec<u8> {
    use sha3::{Digest, Keccak256};

    let mut hasher = Keccak256::new();

    hasher.input(message);

    hasher.result().to_vec()
}

fn blake2b256(message: &[u8]) -> Vec<u8> {
    use blake2::digest::{Input, VariableOutput};
    use blake2::VarBlake2b;

    let mut hasher = VarBlake2b::new(32).unwrap();

    hasher.input(message);

    hasher.vec_result()
}

pub fn fast_hash(message: &[u8]) -> Vec<u8> {
    blake2b256(message)
}

pub fn secure_hash(message: &[u8]) -> Vec<u8> {
    keccak256(blake2b256(message).as_slice())
}

pub struct Address([u8; 26]);

impl Address {
    pub fn bytes(&self) -> [u8; 26] {
        self.0
    }
}

impl ToBase58 for Address {
    fn to_base58(&self) -> String {
        self.0.to_base58()
    }
}

pub struct Signature([u8; 64]);

impl Signature {
    pub fn new(bytes: [u8; 64]) -> Signature {
        Signature(bytes)
    }
}

impl ToBase58 for Signature {
    fn to_base58(&self) -> String {
        self.0.to_base58()
    }
}

pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn to_address(&self, chain_id: u8) -> Address {
        let mut buf = [0u8; 26];
        buf[0] = 1;
        buf[1] = chain_id;
        buf[2..22].copy_from_slice(&secure_hash(&self.0)[..20]);
        let checksum = &secure_hash(&buf[..22])[..4];
        buf[22..].copy_from_slice(checksum);
        Address(buf)
    }

    pub fn bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn verify(&self, signature: &Signature, message: &[u8]) -> bool {
        _verify(&self, signature, message)
    }
}

impl ToBase58 for PublicKey {
    fn to_base58(&self) -> String {
        self.0.to_base58()
    }
}

pub struct PrivateKey([u8; 32]);

impl ToBase58 for PrivateKey {
    fn to_base58(&self) -> String {
        self.0.to_base58()
    }
}

impl PrivateKey {
    pub fn sign(&self, message: &[u8]) -> Signature {
        _sign(&self, message)
    }
}

pub struct KeyPair(PrivateKey, PublicKey);

impl KeyPair {
    pub fn public_key(&self) -> &PublicKey {
        &self.1
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.0
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        _sign(&self.0, message)
    }

    pub fn verify(&self, signature: &Signature, message: &[u8]) -> bool {
        _verify(&self.1, signature, message)
    }

    pub fn from_seed(seed: &str, nonce: u32) -> KeyPair {
        let seed_phrase_bytes = seed.as_bytes();

        let mut nonced = nonce.to_be_bytes().to_vec();

        nonced.extend(seed_phrase_bytes.to_vec());

        let account_seed = secure_hash(&nonced.as_slice());

        KeyPair::new(&account_seed)
    }

    pub fn new(bytes: &[u8]) -> KeyPair {
        use sha2::{Digest, Sha256};

        let mut sk = [0u8; 32];

        sk.copy_from_slice(&Sha256::digest(bytes));

        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;

        let ed_pk = &Scalar::from_bits(sk) * &constants::ED25519_BASEPOINT_TABLE;
        let pk = ed_pk.to_montgomery().to_bytes();

        KeyPair(PrivateKey(sk), PublicKey(pk))
    }
}

fn _verify(public_key: &PublicKey, signature: &Signature, message: &[u8]) -> bool {
    use sha2::Sha512;

    let sign = signature.0[63] & 0x80;
    let mut sig = [0u8; SIGNATURE_LENGTH];

    sig.copy_from_slice(&signature.0);
    sig[63] &= 0x7f;

    let mut ed_pubkey = MontgomeryPoint(public_key.0)
        .to_edwards(sign)
        .unwrap()
        .compress()
        .to_bytes();

    ed_pubkey[31] &= 0x7F; // should be zero already, but just in case
    ed_pubkey[31] |= sign;

    EDXPUB::from_bytes(&ed_pubkey)
        .unwrap()
        .verify::<Sha512>(message, &EDSIG::from_bytes(&sig).unwrap())
        .is_ok()
}

static INITBUF: [u8; 32] = [
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

fn _sign(private_key: &PrivateKey, message: &[u8]) -> Signature {
    use rand::*;
    use sha2::{Digest, Sha512};

    let mut hash = Sha512::default();
    hash.input(&INITBUF);

    hash.input(private_key.0);
    hash.input(message);

    let mut rand = rand::thread_rng();
    let mut rndbuf: Vec<u8> = vec![0; 64];
    (0..63).for_each(|i| rndbuf[i] = rand.gen::<u8>());
    hash.input(&rndbuf);

    let rsc = Scalar::from_hash(hash);
    let r = (&rsc * &constants::ED25519_BASEPOINT_TABLE)
        .compress()
        .to_bytes();

    let ed_pubkey = &constants::ED25519_BASEPOINT_POINT * &Scalar::from_bits(private_key.0);
    let pubkey = ed_pubkey.compress().to_bytes();

    hash = Sha512::default();
    hash.input(&r);
    hash.input(&pubkey);
    hash.input(message);
    let s = &(&Scalar::from_hash(hash) * &Scalar::from_bits(private_key.0)) + &rsc;

    let sign = pubkey[31] & 0x80;
    let mut result = [0; SIGNATURE_LENGTH];
    result[..32].copy_from_slice(&r);
    result[32..].copy_from_slice(&s.to_bytes());
    result[63] &= 0x7F; // should be zero already, but just in case
    result[63] |= sign;
    Signature(result)
}
