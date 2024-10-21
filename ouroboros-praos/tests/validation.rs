use std::{collections::HashMap, fs::File, io::BufReader};

use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use pallas_crypto::key::ed25519::SecretKey;
use pallas_crypto::vrf::VrfSecretKey;
use pallas_crypto::{hash::Hash, vrf::VrfSecretKeyBytes};
use pallas_crypto::{kes::KesSecretKey, vrf::VRF_SECRET_KEY_SIZE};
use pallas_traverse::MultiEraHeader;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Deserialize)]
struct GeneratorContext {
    #[serde(rename = "praosSlotsPerKESPeriod")]
    praos_slots_per_kes_period: u64,
    #[serde(rename = "praosMaxKESEvo")]
    praos_max_kes_evolution: u64,
    #[serde(rename = "kesSignKey", deserialize_with = "deserialize_secret_kes_key")]
    kes_secret_key: KesKeyWrapper,
    #[serde(
        rename = "coldSignKey",
        deserialize_with = "deserialize_secret_ed25519_key"
    )]
    cold_secret_key: SecretKey,
    #[serde(rename = "vrfSignKey", deserialize_with = "deserialize_secret_vrf_key")]
    vrf_secret_key: VrfSecretKey,
    #[serde(deserialize_with = "deserialize_nonce")]
    nonce: [u8; 32],
    #[serde(rename = "ocertCounters")]
    operational_certificate_counters: HashMap<Hash<28>, u64>,
}

impl std::fmt::Debug for GeneratorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratorContext")
            .field(
                "praos_slots_per_kes_period",
                &self.praos_slots_per_kes_period,
            )
            .field("praos_max_kes_evolution", &self.praos_max_kes_evolution)
            .field("kes_secret_key", &self.kes_secret_key)
            .field("cold_secret_key", &self.cold_secret_key)
            .field("nonce", &self.nonce)
            .field(
                "operational_certificate_counters",
                &self.operational_certificate_counters,
            )
            .finish()
    }
}

#[derive(Debug)]
struct KesKeyWrapper {
    bytes: Vec<u8>,
}

impl KesKeyWrapper {
    fn get_kes_secret_key<'a>(&'a mut self) -> Result<KesSecretKey<'a>, ()> {
        KesSecretKey::from_bytes(&mut self.bytes).map_err(|_| ())
    }
}

fn deserialize_secret_kes_key<'de, D>(deserializer: D) -> Result<KesKeyWrapper, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = <String>::deserialize(deserializer)?;
    let bytes = general_purpose::STANDARD
        .decode(buf)
        .map_err(serde::de::Error::custom)?;
    Ok(KesKeyWrapper { bytes })
}

fn deserialize_secret_ed25519_key<'de, D>(deserializer: D) -> Result<SecretKey, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = <String>::deserialize(deserializer)?;
    let decoded = general_purpose::STANDARD
        .decode(buf)
        .map_err(serde::de::Error::custom)?;
    let bytes: [u8; SecretKey::SIZE] = decoded.try_into().map_err(|e| {
        serde::de::Error::custom(format!("cannot convert vector to secret key: {:?}", e))
    })?;
    Ok(bytes.into())
}

fn deserialize_secret_vrf_key<'de, D>(deserializer: D) -> Result<VrfSecretKey, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = <String>::deserialize(deserializer)?;
    let decoded = general_purpose::STANDARD
        .decode(buf)
        .map_err(serde::de::Error::custom)?;
    let num_bytes = decoded.len();
    let bytes: VrfSecretKeyBytes = decoded.try_into().map_err(|e| {
        serde::de::Error::custom(format!(
            "cannot convert vector to secret vrf key (len = {}, expected = {}): {:?}",
            num_bytes, VRF_SECRET_KEY_SIZE, e
        ))
    })?;
    Ok((&bytes).into())
}

fn deserialize_nonce<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let buf = <String>::deserialize(deserializer)?;
    let decoded = general_purpose::STANDARD
        .decode(buf)
        .map_err(serde::de::Error::custom)?;
    decoded
        .try_into()
        .map_err(|e| serde::de::Error::custom(format!("cannot convert vector to nonce: {:?}", e)))
}

#[derive(Debug, Deserialize)]
struct MutatedHeader {
    #[serde(deserialize_with = "deserialize_header")]
    header: HeaderWrapper,
    mutation: Mutation,
}

#[derive(Debug)]
struct HeaderWrapper {
    bytes: Vec<u8>,
}

impl HeaderWrapper {
    fn get_header<'a>(&'a mut self) -> Result<MultiEraHeader<'a>, ()> {
        let conway_block_tag: u8 = 6;
        MultiEraHeader::decode(conway_block_tag, None, self.bytes.as_slice()).map_err(|_| ())
    }
}

fn deserialize_header<'de, D>(deserializer: D) -> Result<HeaderWrapper, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = <&str>::deserialize(deserializer)?;
    let bytes = general_purpose::STANDARD
        .decode(buf)
        .map_err(serde::de::Error::custom)?;
    Ok(HeaderWrapper { bytes })
}

#[derive(Debug, Serialize, Deserialize)]
enum Mutation {
    NoMutation,
    MutateKESKey,
    MutateColdKey,
    MutateKESPeriod,
    MutateKESPeriodBefore,
    MutateCounterOver1,
    MutateCounterUnder,
}

#[test]
fn can_read_and_write_json_test_vectors() {
    let file = File::open("tests/data/test-vector.json").unwrap();
    let result: Result<Vec<(GeneratorContext, MutatedHeader)>, serde_json::Error> =
        serde_json::from_reader(BufReader::new(file));
    println!("result {:?}", result);
    assert!(result.is_ok());
}

#[test]
fn validation_conforms_to_test_vectors() {}
