#![forbid(unsafe_code)]
#![allow(missing_docs)]
#![allow(clippy::doc_markdown)]
#![deny(rustdoc::broken_intra_doc_links)]
#![doc = include_str!("../README.md")]

use ascon_xof128::{AsconCxof128, ExtendableOutput, TryCustomizedInit, Update, XofReader};
use pso_vdf::{
    minroot::{MinRootProof, MinRootVdf},
    types::{VdfInput, VdfOutput},
    Vdf,
};
use thiserror::Error;

/// Default upper bound — matches `nail` `MAX_DIFFICULTY`.
pub const DEFAULT_MAX_DIFFICULTY: u64 = 160_000;
/// Hash trials ≈ `difficulty * multiplier`.
pub const DEFAULT_HASH_MULTIPLIER: u64 = 64;

const VDF_OUTPUT_BYTES: usize = 48;
const VDF_PROOF_BYTES: usize = 48;
/// Raw solution length (output || proof).
pub const SOLUTION_BYTES: usize = VDF_OUTPUT_BYTES + VDF_PROOF_BYTES; // 96
/// Hex-encoded length.
pub const SOLUTION_HEX_LEN: usize = SOLUTION_BYTES * 2; // 192

// ── types ──────────────────────────────────────────────────────────────

/// Challenge identifier — `Uuid` when `uuid` feature is enabled.
#[cfg(feature = "uuid")]
pub type ChallengeId = uuid::Uuid;
/// Challenge identifier — raw 16 bytes when `uuid` feature is disabled.
#[cfg(not(feature = "uuid"))]
pub type ChallengeId = [u8; 16];

/// Server-issued challenge. `id` must be unguessable & single-use server-side.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Challenge {
    pub id: ChallengeId,
    pub difficulty: u64,
}

impl Challenge {
    /// Create a challenge with an explicit identifier.
    #[must_use]
    pub fn new(id: ChallengeId, difficulty: u64) -> Self {
        Self { id, difficulty }
    }
    /// Prove this challenge using the default [`Config`].
    pub fn prove(&self) -> Result<Pow, PowError> {
        prove(self)
    }
    /// Prove this challenge with an explicit [`Config`].
    pub fn prove_with(&self, cfg: &Config) -> Result<Pow, PowError> {
        prove_with_config(self, cfg)
    }
    /// Generate a fresh challenge with a random `v7` UUID (requires `uuid` feature).
    #[cfg(feature = "uuid")]
    #[must_use]
    pub fn generate(difficulty: u64) -> Self {
        issue_challenge(difficulty)
    }
}

/// Proof. `solution` is raw 96 bytes; on the wire it is hex-encoded to stay
/// compatible with `nail` `common::pow` (`solution: String`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Pow {
    pub challenge: Challenge,
    #[cfg_attr(feature = "serde", serde(with = "serde_hex"))]
    solution: Vec<u8>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub nonce: u64,
}

impl Pow {
    /// Raw 96 bytes.
    #[must_use]
    pub fn solution(&self) -> &[u8] {
        &self.solution
    }
    /// Verify against `expected_difficulty` (method form of [`verify`]).
    /// Verify this proof (method form of [`verify`]).
    pub fn verify(&self, expected_difficulty: u64) -> Result<(), VerifyError> {
        verify(self, expected_difficulty)
    }
    /// Verify with explicit [`Config`].
    pub fn verify_with(&self, expected_difficulty: u64, cfg: &Config) -> Result<(), VerifyError> {
        verify_with_config(self, expected_difficulty, cfg)
    }
}

#[cfg(feature = "serde")]
mod serde_hex {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("hex string (192 chars) or byte array")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                hex::decode(v).map_err(serde::de::Error::custom)
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                hex::decode(&v).map_err(serde::de::Error::custom)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(96));
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_any(V)
    }
}

/// Tunable parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Maximum accepted difficulty.
    pub max_difficulty: u64,
    /// Hash trial multiplier.
    pub hash_multiplier: u64,
}
impl Config {
    #[must_use]
    pub fn new(max_difficulty: u64, hash_multiplier: u64) -> Self {
        Self {
            max_difficulty,
            hash_multiplier,
        }
    }
}
impl Default for Config {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_DIFFICULTY, DEFAULT_HASH_MULTIPLIER)
    }
}

// ── errors ─────────────────────────────────────────────────────────────

/// Errors from [`prove`] / [`prove_with_config`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PowError {
    /// Difficulty is zero.
    #[error("difficulty must be > 0")]
    ZeroDifficulty,
    /// Difficulty exceeds `max_difficulty`.
    #[error("difficulty {0} exceeds max {1}")]
    DifficultyTooHigh(u64, u64),
    /// CXOF initialization failed.
    #[error("cxof init failed: {0}")]
    Cxof(String),
}

/// Errors from [`verify`] / [`verify_with_config`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    /// Expected difficulty does not match challenge.
    #[error("difficulty mismatch: expected {expected}, got {got}")]
    DifficultyMismatch { expected: u64, got: u64 },
    /// Difficulty is zero or above `max_difficulty`.
    #[error("difficulty {0} out of range")]
    DifficultyOutOfRange(u64),
    /// Solution has wrong length.
    #[error("invalid solution length {0}, expected {expected}", expected = SOLUTION_BYTES)]
    BadLength(usize),
    /// Hex decoding failed.
    #[error("invalid hex: {0}")]
    BadHex(String),
    /// Hash does not meet the target.
    #[error("hash target not met")]
    TargetNotMet,
    /// VDF proof is invalid.
    #[error("vdf verification failed")]
    VdfFailed,
    /// CXOF error during verification.
    #[error("cxof error: {0}")]
    Cxof(String),
}

// ── internals ──────────────────────────────────────────────────────────

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
    let customize: &[u8] = id.as_bytes();
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

// ── public API ─────────────────────────────────────────────────────────

/// Issue a fresh challenge with a `v7` UUID (requires `uuid` feature).
#[must_use]
#[cfg(feature = "uuid")]
pub fn issue_challenge(difficulty: u64) -> Challenge {
    Challenge::new(uuid::Uuid::now_v7(), difficulty)
}

/// Prove `challenge` with the default [`Config`].
///
/// # Errors
/// Returns [`PowError`] if difficulty is zero or exceeds `max_difficulty`.
pub fn prove(challenge: &Challenge) -> Result<Pow, PowError> {
    prove_with_config(challenge, &Config::default())
}

/// Prove `challenge` with an explicit [`Config`].
///
/// # Errors
/// Returns [`PowError`] on invalid difficulty or CXOF failure.
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
    debug_assert_eq!(sol.len(), SOLUTION_BYTES);
    Ok(Pow {
        challenge: challenge.clone(),
        solution: sol,
        nonce,
    })
}

/// Verify `pow` against `expected_difficulty` using the default [`Config`].
///
/// # Errors
/// Returns [`VerifyError`] on mismatch, bad length, target miss or VDF failure.
pub fn verify(pow: &Pow, expected_difficulty: u64) -> Result<(), VerifyError> {
    verify_with_config(pow, expected_difficulty, &Config::default())
}

/// Verify `pow` against `expected_difficulty` with an explicit [`Config`].
///
/// # Errors
/// Returns [`VerifyError`] on any check failure.
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
        &pow.solution[..VDF_OUTPUT_BYTES],
        &pow.solution[VDF_OUTPUT_BYTES..],
    ) {
        return Err(VerifyError::VdfFailed);
    }
    Ok(())
}

#[cfg(feature = "hex-encode")]
impl Pow {
    /// Hex-encoded solution (`192` chars).
    #[must_use]
    pub fn solution_hex(&self) -> String {
        hex::encode(&self.solution)
    }
    /// Build from a hex-encoded solution.
    ///
    /// # Errors
    /// Returns [`VerifyError::BadHex`] or [`VerifyError::BadLength`].
    pub fn from_hex(challenge: Challenge, hex_str: &str, nonce: u64) -> Result<Self, VerifyError> {
        let bytes = hex::decode(hex_str).map_err(|e| VerifyError::BadHex(e.to_string()))?;
        if bytes.len() != SOLUTION_BYTES {
            return Err(VerifyError::BadLength(bytes.len()));
        }
        Ok(Self {
            challenge,
            solution: bytes,
            nonce,
        })
    }
}
