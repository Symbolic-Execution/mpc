use crate::aad::{Aad, EnclaveAadV1, ReaderAadV1, SourceAad, decode_source_aad, encode_aad};
use crate::error::MpcError;
use crate::types::{
    Attestation, AttestationDigest, EnclaveCiphertextV1, FixedBytes, KeyId, PayloadBytes,
    ReaderCiphertextV1, ReaderId, SystemCiphertextV1, X25519PublicKey,
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use ciborium::value::Value;
use hpke::rand_core::{CryptoRng as HpkeCryptoRng, RngCore as HpkeRngCore};
use hpke::{
    Deserializable, Kem as _, OpModeR, OpModeS, Serializable, setup_receiver, setup_sender,
};
use rand::{RngCore, rngs::OsRng as RandOsRng};
use sha3::{Digest, Keccak256};

type HpkeAead = hpke::aead::AesGcm256;
type HpkeKdf = hpke::kdf::HkdfSha256;
type HpkeKem = hpke::kem::X25519HkdfSha256;

const HPKE_INFO: &[u8] = b"mpc-hpke-v1";

struct HpkeOsRng(RandOsRng);

impl HpkeRngCore for HpkeOsRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.fill_bytes(dst);
    }
}

impl HpkeCryptoRng for HpkeOsRng {}

pub struct HpkeKeypair {
    pub public_key: X25519PublicKey,
    secret_key: <HpkeKem as hpke::Kem>::PrivateKey,
}

pub struct OpenedSystemCiphertext {
    pub source_aad: SourceAad,
    pub plaintext: Vec<u8>,
}

impl HpkeKeypair {
    pub fn generate() -> Self {
        let mut rng = HpkeOsRng(RandOsRng);
        let (secret_key, public_key) = HpkeKem::gen_keypair(&mut rng);

        Self {
            public_key: X25519PublicKey(public_key.to_bytes().into()),
            secret_key,
        }
    }

    pub fn from_seed_for_tests(seed: [u8; 32]) -> Self {
        let (secret_key, public_key) = HpkeKem::derive_keypair(&seed);

        Self {
            public_key: X25519PublicKey(public_key.to_bytes().into()),
            secret_key,
        }
    }
}

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

pub fn reader_id(reader_pubkey: X25519PublicKey) -> ReaderId {
    ReaderId(keccak256(&reader_pubkey.0))
}

pub fn attestation_digest(attestation: &Attestation) -> AttestationDigest {
    AttestationDigest(keccak256(&attestation.0))
}

pub fn hpke_seal(
    recipient: X25519PublicKey,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), MpcError> {
    let public_key = <HpkeKem as hpke::Kem>::PublicKey::from_bytes(&recipient.0)
        .map_err(|_| unprocessable("invalid recipient public key"))?;
    let mut rng = HpkeOsRng(RandOsRng);
    let (enc, mut sender) = setup_sender::<HpkeAead, HpkeKdf, HpkeKem, _>(
        &OpModeS::Base,
        &public_key,
        HPKE_INFO,
        &mut rng,
    )
    .map_err(|_| unprocessable("failed to set up hpke sender"))?;
    let ciphertext = sender
        .seal(plaintext, aad)
        .map_err(|_| unprocessable("failed to seal hpke ciphertext"))?;

    Ok((enc.to_bytes().to_vec(), ciphertext))
}

pub fn hpke_open(
    keypair: &HpkeKeypair,
    enc: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, MpcError> {
    let encapped_key = <HpkeKem as hpke::Kem>::EncappedKey::from_bytes(enc)
        .map_err(|_| unprocessable("invalid hpke encapped key"))?;
    let mut receiver = setup_receiver::<HpkeAead, HpkeKdf, HpkeKem>(
        &OpModeR::Base,
        &keypair.secret_key,
        &encapped_key,
        HPKE_INFO,
    )
    .map_err(|_| unprocessable("failed to set up hpke receiver"))?;

    receiver
        .open(ciphertext, aad)
        .map_err(|_| unprocessable("failed to open hpke ciphertext"))
}

pub fn seal_system_ciphertext(
    mpc_public_key: &X25519PublicKey,
    key_id: KeyId,
    aad: &Aad,
    plaintext: &[u8],
) -> Result<SystemCiphertextV1, MpcError> {
    let encoded_aad = encode_aad(aad)?;
    let mut dek = [0u8; 32];
    let mut nonce = [0u8; 12];
    RandOsRng.fill_bytes(&mut dek);
    RandOsRng.fill_bytes(&mut nonce);

    let ciphertext = aes_gcm_encrypt(&dek, &nonce, &encoded_aad, plaintext)?;
    let (enc, wrapped_key) = hpke_seal(*mpc_public_key, &encoded_aad, &dek)?;

    Ok(SystemCiphertextV1 {
        key_id,
        enc: PayloadBytes(enc),
        wrapped_key: PayloadBytes(wrapped_key),
        nonce: FixedBytes(nonce),
        ciphertext: PayloadBytes(ciphertext),
        aad: PayloadBytes(encoded_aad),
    })
}

pub fn open_system_ciphertext(
    keypair: &HpkeKeypair,
    ciphertext: &SystemCiphertextV1,
) -> Result<OpenedSystemCiphertext, MpcError> {
    let dek = hpke_open(
        keypair,
        &ciphertext.enc.0,
        &ciphertext.aad.0,
        &ciphertext.wrapped_key.0,
    )?;
    let dek: [u8; 32] = dek
        .as_slice()
        .try_into()
        .map_err(|_| unprocessable("opened data encryption key must be 32 bytes"))?;
    let plaintext = aes_gcm_decrypt(
        &dek,
        &ciphertext.nonce.0,
        &ciphertext.aad.0,
        &ciphertext.ciphertext.0,
    )?;
    let source_aad = decode_source_aad(&ciphertext.aad.0)?;

    Ok(OpenedSystemCiphertext {
        source_aad,
        plaintext,
    })
}

pub fn seal_reader_ciphertext(
    reader_pubkey: X25519PublicKey,
    key_id: KeyId,
    aad: ReaderAadV1,
    plaintext: &[u8],
) -> Result<ReaderCiphertextV1, MpcError> {
    let encoded_aad = encode_aad(&Aad::Reader(aad))?;
    let (enc, ciphertext) = hpke_seal(reader_pubkey, &encoded_aad, plaintext)?;

    Ok(ReaderCiphertextV1 {
        key_id,
        enc: PayloadBytes(enc),
        ciphertext: PayloadBytes(ciphertext),
        aad: PayloadBytes(encoded_aad),
    })
}

pub fn seal_enclave_ciphertext(
    enclave_pubkey: X25519PublicKey,
    key_id: KeyId,
    aad: EnclaveAadV1,
    plaintext: &[u8],
) -> Result<EnclaveCiphertextV1, MpcError> {
    let encoded_aad = encode_aad(&Aad::Enclave(aad))?;
    let (enc, ciphertext) = hpke_seal(enclave_pubkey, &encoded_aad, plaintext)?;

    Ok(EnclaveCiphertextV1 {
        key_id,
        enc: PayloadBytes(enc),
        ciphertext: PayloadBytes(ciphertext),
        aad: PayloadBytes(encoded_aad),
    })
}

pub fn open_reader_ciphertext_for_tests(
    reader_keypair: &HpkeKeypair,
    ciphertext: &ReaderCiphertextV1,
) -> Result<Vec<u8>, MpcError> {
    hpke_open(
        reader_keypair,
        &ciphertext.enc.0,
        &ciphertext.aad.0,
        &ciphertext.ciphertext.0,
    )
}

pub fn open_enclave_ciphertext_for_tests(
    enclave_keypair: &HpkeKeypair,
    ciphertext: &EnclaveCiphertextV1,
) -> Result<Vec<u8>, MpcError> {
    hpke_open(
        enclave_keypair,
        &ciphertext.enc.0,
        &ciphertext.aad.0,
        &ciphertext.ciphertext.0,
    )
}

pub fn encode_plaintext_suint256(value: [u8; 32]) -> Result<Vec<u8>, MpcError> {
    encode_plaintext_bytes(value)
}

pub fn encode_plaintext_sbool(value: bool) -> Result<Vec<u8>, MpcError> {
    encode_plaintext_bytes([u8::from(value)])
}

fn aes_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, MpcError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| unprocessable("invalid aes-gcm key length"))?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| unprocessable("failed to encrypt aes-gcm payload"))
}

fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, MpcError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| unprocessable("invalid aes-gcm key length"))?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| unprocessable("failed to decrypt aes-gcm payload"))
}

fn encode_plaintext_bytes<const N: usize>(bytes: [u8; N]) -> Result<Vec<u8>, MpcError> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&Value::Bytes(bytes.to_vec()), &mut encoded)
        .map_err(|err| unprocessable(format!("failed to encode plaintext: {err}")))?;
    Ok(encoded)
}

fn unprocessable(message: impl Into<String>) -> MpcError {
    MpcError::Unprocessable(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aad::{Aad, AadKind, EnclaveAadV1, ReaderAadV1, SystemHandleAadV1, encode_aad};
    use crate::types::{
        Attestation, AttestationDigest, DomainId, HandleId, KeyId, ReaderId, RequestId,
        X25519PublicKey,
    };
    use sha3::{Digest, Keccak256};

    #[test]
    fn reader_id_is_keccak256_of_public_key() {
        let public_key = X25519PublicKey([0x42; 32]);
        let id = reader_id(public_key);
        assert_eq!(id.0.len(), 32);
        assert_ne!(id, ReaderId([0x42; 32]));
    }

    #[test]
    fn attestation_digest_is_keccak256_of_attestation_bytes() {
        let attestation = Attestation(vec![0x12, 0x34, 0xab, 0xcd]);
        let mut hasher = Keccak256::new();
        hasher.update(&attestation.0);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(
            attestation_digest(&attestation),
            AttestationDigest(expected)
        );
    }

    #[test]
    fn system_ciphertext_opens_with_mpc_key() {
        let keypair = HpkeKeypair::from_seed_for_tests([7u8; 32]);
        let aad = Aad::SystemHandle(SystemHandleAadV1 {
            version: 1,
            kind: AadKind::SystemHandle,
            chain_id: 31337,
            domain_id: DomainId([1; 32]),
            handle_id: HandleId([2; 32]),
            type_tag: "suint256".to_string(),
            key_id: KeyId([3; 32]),
        });
        let plaintext = encode_plaintext_suint256([9u8; 32]).unwrap();
        let ciphertext =
            seal_system_ciphertext(&keypair.public_key, KeyId([3; 32]), &aad, &plaintext).unwrap();
        let opened = open_system_ciphertext(&keypair, &ciphertext).unwrap();
        assert_eq!(opened.plaintext, plaintext);
    }

    #[test]
    fn reader_ciphertext_opens_with_matching_key_and_rejects_wrong_key() {
        let reader_keypair = HpkeKeypair::from_seed_for_tests([8u8; 32]);
        let wrong_keypair = HpkeKeypair::from_seed_for_tests([9u8; 32]);
        let aad = ReaderAadV1 {
            version: 1,
            kind: AadKind::Reader,
            chain_id: 31337,
            domain_id: DomainId([1; 32]),
            request_id: RequestId([2; 32]),
            handle_id: HandleId([3; 32]),
            reader_id: reader_id(reader_keypair.public_key),
            type_tag: "sbool".to_string(),
            key_id: KeyId([4; 32]),
        };
        let plaintext = encode_plaintext_sbool(true).unwrap();

        let ciphertext =
            seal_reader_ciphertext(reader_keypair.public_key, KeyId([4; 32]), aad, &plaintext)
                .unwrap();

        assert_eq!(
            open_reader_ciphertext_for_tests(&reader_keypair, &ciphertext).unwrap(),
            plaintext
        );
        assert!(open_reader_ciphertext_for_tests(&wrong_keypair, &ciphertext).is_err());
    }

    #[test]
    fn enclave_ciphertext_opens_with_matching_key_and_rejects_wrong_key() {
        let enclave_keypair = HpkeKeypair::from_seed_for_tests([10u8; 32]);
        let wrong_keypair = HpkeKeypair::from_seed_for_tests([11u8; 32]);
        let aad = EnclaveAadV1 {
            version: 1,
            kind: AadKind::Enclave,
            chain_id: 31337,
            domain_id: DomainId([1; 32]),
            request_id: RequestId([2; 32]),
            handle_id: HandleId([3; 32]),
            type_tag: "suint256".to_string(),
            attestation_digest: AttestationDigest([4; 32]),
            key_id: KeyId([5; 32]),
        };
        let plaintext = encode_plaintext_suint256([6u8; 32]).unwrap();

        let ciphertext =
            seal_enclave_ciphertext(enclave_keypair.public_key, KeyId([5; 32]), aad, &plaintext)
                .unwrap();

        assert_eq!(
            open_enclave_ciphertext_for_tests(&enclave_keypair, &ciphertext).unwrap(),
            plaintext
        );
        assert!(open_enclave_ciphertext_for_tests(&wrong_keypair, &ciphertext).is_err());
    }

    #[test]
    fn recipient_ciphertext_helpers_store_encoded_aad() {
        let reader_keypair = HpkeKeypair::from_seed_for_tests([12u8; 32]);
        let aad = ReaderAadV1 {
            version: 1,
            kind: AadKind::Reader,
            chain_id: 31337,
            domain_id: DomainId([1; 32]),
            request_id: RequestId([2; 32]),
            handle_id: HandleId([3; 32]),
            reader_id: reader_id(reader_keypair.public_key),
            type_tag: "sbool".to_string(),
            key_id: KeyId([4; 32]),
        };
        let expected_aad = encode_aad(&Aad::Reader(aad.clone())).unwrap();

        let ciphertext = seal_reader_ciphertext(
            reader_keypair.public_key,
            KeyId([4; 32]),
            aad,
            &encode_plaintext_sbool(false).unwrap(),
        )
        .unwrap();

        assert_eq!(ciphertext.aad.0, expected_aad);
    }

    #[test]
    fn plaintext_helpers_encode_canonical_cbor_byte_strings() {
        assert_eq!(
            encode_plaintext_suint256([0x7a; 32]).unwrap(),
            [vec![0x58, 0x20], vec![0x7a; 32]].concat()
        );
        assert_eq!(encode_plaintext_sbool(true).unwrap(), vec![0x41, 0x01]);
        assert_eq!(encode_plaintext_sbool(false).unwrap(), vec![0x41, 0x00]);
    }
}
