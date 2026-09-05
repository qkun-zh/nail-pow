# nail-pow

[![Crates.io](https://img.shields.io/crates/v/nail-pow)](https://crates.io/crates/nail-pow) [![Docs.rs](https://img.shields.io/docsrs/nail-pow)](https://docs.rs/nail-pow) [![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

Production proof-of-work crate extracted from [nail](https://github.com/qkun-zh/nail): **Ascon-CXOF128** hash-target + **MinRoot VDF (Wesolowski)** sequential delay.

Prevents spam / brute-force with a tunable cost that is cheap to verify and expensive to forge.

## Why

- **Hash-target** (`Ascon-CXOF(id, nonce) < 2¹²⁸ / difficulty*64`) — parallel-search friendly, tunable.
- **VDF** (`MinRoot` over BLS12-381, `difficulty` iterations) — forces sequential work, fast verify.
- `VDF` iterations are bound to `difficulty` alone; `HASH_MULTIPLIER` only tunes the search layer.

## Install

```toml
[dependencies]
nail-pow = "0.1"
```

Features: `default = ["std","hex-encode","uuid","serde"]` · `uuid` for `Uuid::now_v7` challenges · `hex-encode` for `solution_hex()` · `serde` for wire types.

## Usage

```rust
use nail_pow::{issue_challenge, prove, verify};

let challenge = issue_challenge(100); // server issues
let pow = prove(&challenge).unwrap(); // client proves
verify(&pow, 100).unwrap();            // server verifies
```

Custom config / no-uuid:

```rust,ignore
use nail_pow::{Challenge, Config, prove_with_config, verify_with_config};

let cfg = Config { max_difficulty: 50_000, hash_multiplier: 64 };
let ch = Challenge { id: *b"0123456789abcdef", difficulty: 500 };
let pow = prove_with_config(&ch, &cfg).unwrap();
verify_with_config(&pow, 500, &cfg).unwrap();
```

Hex wire (compat with `common::pow`):

```rust,ignore
let hex = pow.solution_hex(); // 192-char hex for 96 bytes
let pow2 = nail_pow::Pow::from_hex(challenge, &hex, pow.nonce).unwrap();
```

## API

- `issue_challenge(difficulty) -> Challenge` (requires `uuid` feature)
- `prove(&Challenge) -> Result<Pow, PowError>` / `prove_with_config`
- `verify(&Pow, expected_difficulty) -> Result<(), VerifyError>` / `verify_with_config`
- `Config { max_difficulty, hash_multiplier }` · `SOLUTION_BYTES = 96`

Errors are typed (`thiserror`): `ZeroDifficulty`, `DifficultyTooHigh`, `TargetNotMet`, `VdfFailed`, `BadLength`, etc. — no `anyhow`.

## Performance

`cargo bench` (`criterion 0.5`, release, x86-64) — `prove` scales with `difficulty` (sequential VDF), `verify` is O(1) Wesolowski:

| difficulty | prove | verify |
| --- | --- | --- |
| 1 | ~0.90 ms | ~0.86 ms |
| 10 | ~1.0–1.9 ms | ~0.48–1.35 ms |
| 100 | ~16.3 ms | ~1.85 ms |
| 500 | ~34.7 ms | ~1.41 ms |
| 1000 | ~65 ms* | ~1.5 ms* |

\* interpolated. Run `cargo bench --bench pow` for your hardware. `VDF` dominates at high difficulty; hash-target (`Ascon-CXOF` trials ≈ `difficulty*64`) adds jitter at low difficulty.

## Security notes

- `difficulty = 0` is rejected; `> max_difficulty` rejected.
- `verify` checks difficulty match, solution length (96 bytes), hash target, then VDF proof.
- Challenge `id` must be unguessable (use `Uuid::now_v7` or random 16 bytes) and single-use on server side.

## License

MIT OR Apache-2.0
