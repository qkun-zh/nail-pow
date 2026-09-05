#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use ascon_xof128::{AsconCxof128, ExtendableOutput, TryCustomizedInit, Update, XofReader};
use pso_vdf::{
    minroot::{MinRootProof, MinRootVdf},
    types::{VdfInput, VdfOutput},
    Vdf,
};
use thiserror::Error;

pub const DEFAULT_MAX_DIFFICULTY: u64 = 160_000;
pub const DEFAULT_HASH_MULTIPLIER: u64 = 64;
const VDF_OUTPUT_BYTES: usize = 48;
const VDF_PROOF_BYTES: usize = 48;
pub const SOLUTION_BYTES: usize = VDF_OUTPUT_BYTES + VDF_PROOF_BYTES; // 96

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Challenge {
    #[cfg_attr(feature = "uuid", serde(default))]
    pub id: ChallengeId,
    pub difficulty: u64,
}

#[cfg(feature = "uuid")]
pub type ChallengeId = uuid::Uuid;
#[cfg(not(feature = "uuid"))]
pub type ChallengeId = [u8; 16];

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Pow {
    pub challenge: Challenge,
    /// raw 96 bytes; hex encoding is via `solution_hex()` when feature enabled
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes_compat",))]
    pub solution: Vec<u8>,
    pub nonce: u64,
}

#[cfg(feature = "serde")]
mod serde_bytes_compat {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        v.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(d)
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub max_difficulty: u64,
    pub hash_multiplier: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            max_difficulty: DEFAULT_MAX_DIFFICULTY,
            hash_multiplier: DEFAULT_HASH_MULTIPLIER,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PowError {
    #[error("difficulty must be > 0")]
    ZeroDifficulty,
    #[error("difficulty {0} exceeds max {1}")]
    DifficultyTooHigh(u64, u64),
    #[error("cxof init failed: {0}")]
    Cxof(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("difficulty mismatch: expected {expected}, got {got}")]
    DifficultyMismatch { expected: u64, got: u64 },
    #[error("difficulty {0} out of range")]
    DifficultyOutOfRange(u64),
    #[error("invalid solution length {0}")]
    BadLength(usize),
    #[error("hash target not met")]
    TargetNotMet,
    #[error("vdf verification failed")]
    VdfFailed,
    #[error("cxof error: {0}")]
    Cxof(String),
}

fn hash_meets_target(bytes: &[u8; 32], difficulty: u64, multiplier: u64) -> bool {
    if difficulty == 0 {
        return true;
    }
    let scalar = u128::from(difficulty) * u128::from(multiplier);
    let hash_prefix = u128::from_be_bytes(bytes[0..16].try_into().unwrap());
    hash_prefix < u128::MAX / scalar
}

fn cxof_bytes(id: &ChallengeId, nonce: u64) -> Result<[u8; 32], String> {
    #[cfg(feature = "uuid")]
    let customize = id.as_bytes();
    #[cfg(not(feature = "uuid"))]
    let customize: &[u8] = id;
    let mut cxof = AsconCxof128::try_new_customized(customize).map_err(|e| e.to_string())?;
    cxof.update(&nonce.to_le_bytes());
    let mut out = [0u8; 32];
    cxof.finalize_xof().read(&mut out);
    Ok(out)
}

fn vdf_prove(input: [u8; 32], difficulty: u64) -> (Vec<u8>, Vec<u8>) {
    let (o, p) = MinRootVdf::eval(&VdfInput::from_bytes(input), difficulty);
    (o.0, p.inner)
}
fn vdf_verify(input: [u8; 32], difficulty: u64, output: &[u8], proof: &[u8]) -> bool {
    if output.len() != VDF_OUTPUT_BYTES || proof.len() != VDF_PROOF_BYTES {
        return false;
    }
    MinRootVdf::verify(
        &VdfInput::from_bytes(input),
        &VdfOutput(output.to_vec()),
        &MinRootProof {
            inner: proof.to_vec(),
        },
        difficulty,
    )
}

#[must_use]
#[cfg(feature = "uuid")]
pub fn issue_challenge(difficulty: u64) -> Challenge {
    Challenge {
        id: uuid::Uuid::now_v7(),
        difficulty,
    }
}

pub fn prove(challenge: &Challenge) -> Result<Pow, PowError> {
    prove_with_config(challenge, &Config::default())
}

pub fn prove_with_config(challenge: &Challenge, cfg: &Config) -> Result<Pow, PowError> {
    if challenge.difficulty == 0 {
        return Err(PowError::ZeroDifficulty);
    }
    if challenge.difficulty > cfg.max_difficulty {
        return Err(PowError::DifficultyTooHigh(
            challenge.difficulty,
            cfg.max_difficulty,
        ));
    }
    let mut nonce = 0u64;
    let input = loop {
        let c = cxof_bytes(&challenge.id, nonce).map_err(PowError::Cxof)?;
        if hash_meets_target(&c, challenge.difficulty, cfg.hash_multiplier) {
            break c;
        }
        nonce = nonce.wrapping_add(1);
    };
    let (out, proof) = vdf_prove(input, challenge.difficulty);
    let mut sol = Vec::with_capacity(SOLUTION_BYTES);
    sol.extend_from_slice(&out);
    sol.extend_from_slice(&proof);
    Ok(Pow {
        challenge: challenge.clone(),
        solution: sol,
        nonce,
    })
}

pub fn verify(pow: &Pow, expected_difficulty: u64) -> Result<(), VerifyError> {
    verify_with_config(pow, expected_difficulty, &Config::default())
}

pub fn verify_with_config(
    pow: &Pow,
    expected_difficulty: u64,
    cfg: &Config,
) -> Result<(), VerifyError> {
    if pow.challenge.difficulty != expected_difficulty {
        return Err(VerifyError::DifficultyMismatch {
            expected: expected_difficulty,
            got: pow.challenge.difficulty,
        });
    }
    if expected_difficulty == 0 || expected_difficulty > cfg.max_difficulty {
        return Err(VerifyError::DifficultyOutOfRange(expected_difficulty));
    }
    if pow.solution.len() != SOLUTION_BYTES {
        return Err(VerifyError::BadLength(pow.solution.len()));
    }
    let input = cxof_bytes(&pow.challenge.id, pow.nonce).map_err(VerifyError::Cxof)?;
    if !hash_meets_target(&input, expected_difficulty, cfg.hash_multiplier) {
        return Err(VerifyError::TargetNotMet);
    }
    if !vdf_verify(
        input,
        expected_difficulty,
        &pow.solution[..48],
        &pow.solution[48..],
    ) {
        return Err(VerifyError::VdfFailed);
    }
    Ok(())
}

// hex helpers
#[cfg(feature = "hex-encode")]
impl Pow {
    pub fn solution_hex(&self) -> String {
        hex::encode(&self.solution)
    }
    pub fn from_hex(challenge: Challenge, hex_str: &str, nonce: u64) -> Result<Self, String> {
        Ok(Self {
            challenge,
            solution: hex::decode(hex_str).map_err(|e| e.to_string())?,
            nonce,
        })
    }
}
