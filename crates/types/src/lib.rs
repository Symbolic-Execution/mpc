use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FixedBytes<const N: usize>(pub [u8; N]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Address(pub [u8; 20]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Bytes32(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DomainId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReaderId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HandleId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EnclaveMeasurement(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AttestationDigest(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct X25519PublicKey(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation(pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadBytes(pub Vec<u8>);

fn serialize_fixed_bytes<const N: usize, S>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut encoded = String::with_capacity(2 + (N * 2));
    encoded.push_str("0x");
    encoded.push_str(&hex::encode(bytes));
    serializer.serialize_str(&encoded)
}

fn deserialize_fixed_bytes<'de, const N: usize, D>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    struct FixedBytesVisitor<const N: usize>;

    impl<const N: usize> de::Visitor<'_> for FixedBytesVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a 0x-prefixed hex string with {N} bytes")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let hex = value
                .strip_prefix("0x")
                .ok_or_else(|| E::custom("missing 0x prefix"))?;
            if hex.len() != N * 2 {
                return Err(E::custom(format!("expected {} hex characters", N * 2)));
            }

            let mut bytes = [0; N];
            hex::decode_to_slice(hex, &mut bytes).map_err(E::custom)?;
            Ok(bytes)
        }
    }

    deserializer.deserialize_str(FixedBytesVisitor::<N>)
}

impl<const N: usize> Serialize for FixedBytes<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_fixed_bytes(&self.0, serializer)
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedBytes<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_fixed_bytes(deserializer).map(Self)
    }
}

macro_rules! fixed_bytes_newtype_serde {
    ($name:ident, $len:literal) => {
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serialize_fixed_bytes(&self.0, serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserialize_fixed_bytes::<$len, D>(deserializer).map(Self)
            }
        }
    };
}

fixed_bytes_newtype_serde!(Address, 20);
fixed_bytes_newtype_serde!(Bytes32, 32);
fixed_bytes_newtype_serde!(DomainId, 32);
fixed_bytes_newtype_serde!(KeyId, 32);
fixed_bytes_newtype_serde!(RequestId, 32);
fixed_bytes_newtype_serde!(ReaderId, 32);
fixed_bytes_newtype_serde!(HandleId, 32);
fixed_bytes_newtype_serde!(EnclaveMeasurement, 32);
fixed_bytes_newtype_serde!(AttestationDigest, 32);
fixed_bytes_newtype_serde!(X25519PublicKey, 32);

fn serialize_base64url<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
}

fn deserialize_base64url<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    URL_SAFE_NO_PAD.decode(encoded).map_err(de::Error::custom)
}

impl Serialize for PayloadBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_base64url(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for PayloadBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_base64url(deserializer).map(Self)
    }
}

impl Serialize for Attestation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_base64url(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Attestation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_base64url(deserializer).map(Self)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ReaderKeyAlgorithm {
    X25519,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum CiphertextSuite {
    HpkeX25519HkdfSha256Aes256Gcm,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct MpcConfigResponse {
    pub version: u16,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub key_id: KeyId,
    pub hpke_public_key: X25519PublicKey,
    pub reader_key_algorithm: ReaderKeyAlgorithm,
    pub ciphertext_suite: CiphertextSuite,
    pub approved_enclave_measurement: EnclaveMeasurement,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PutReaderRequest {
    pub reader_pubkey: X25519PublicKey,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PutReaderResponse {
    pub reader_id: ReaderId,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SystemCiphertextV1 {
    pub key_id: KeyId,
    pub enc: PayloadBytes,
    pub wrapped_key: PayloadBytes,
    pub nonce: FixedBytes<12>,
    pub ciphertext: PayloadBytes,
    pub aad: PayloadBytes,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EnclaveCiphertextV1 {
    pub key_id: KeyId,
    pub enc: PayloadBytes,
    pub ciphertext: PayloadBytes,
    pub aad: PayloadBytes,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ReaderCiphertextV1 {
    pub key_id: KeyId,
    pub enc: PayloadBytes,
    pub ciphertext: PayloadBytes,
    pub aad: PayloadBytes,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ToEnclaveRequest {
    pub request_id: RequestId,
    pub chain_id: u64,
    pub handle_id: HandleId,
    pub enclave_pubkey: X25519PublicKey,
    pub measurement: EnclaveMeasurement,
    pub attestation: Attestation,
    pub system_ciphertext: SystemCiphertextV1,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ToEnclaveResponse {
    pub ciphertext: EnclaveCiphertextV1,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ToReaderRequest {
    pub request_id: RequestId,
    pub chain_id: u64,
    pub handle_id: HandleId,
    pub reader_id: ReaderId,
    pub system_ciphertext: SystemCiphertextV1,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ToReaderResponse {
    pub ciphertext: ReaderCiphertextV1,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes32_json_uses_lowercase_0x_hex() {
        let value = Bytes32([0xab; 32]);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(
            json,
            "\"0xabababababababababababababababababababababababababababababababab\""
        );
        let decoded: Bytes32 = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn payload_bytes_json_use_base64url_without_padding() {
        let value = PayloadBytes(vec![0xde, 0xad, 0xbe, 0xef]);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, "\"3q2-7w\"");
        let decoded: PayloadBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn fixed_bytes_json_rejects_missing_0x_prefix() {
        let err = serde_json::from_str::<Bytes32>(
            "\"abababababababababababababababababababababababababababababababab\"",
        )
        .unwrap_err();
        assert!(err.to_string().contains("missing 0x prefix"));
    }

    #[test]
    fn fixed_bytes_json_rejects_wrong_length() {
        let err = serde_json::from_str::<Bytes32>("\"0xabab\"").unwrap_err();
        assert!(err.to_string().contains("expected 64 hex characters"));
    }

    #[test]
    fn fixed_bytes_json_rejects_invalid_hex() {
        let err = serde_json::from_str::<Bytes32>(
            "\"0xgggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg\"",
        )
        .unwrap_err();
        assert!(err.to_string().contains("Invalid character"));
    }

    #[test]
    fn payload_bytes_json_rejects_invalid_base64url() {
        assert!(serde_json::from_str::<PayloadBytes>("\"****\"").is_err());
    }

    #[test]
    fn payload_bytes_json_rejects_padded_base64() {
        let err = serde_json::from_str::<PayloadBytes>("\"3q2-7w==\"").unwrap_err();
        assert!(err.to_string().contains("Invalid padding"));
    }
}
