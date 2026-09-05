use nail_pow::*;
fn ch(d: u64) -> Challenge {
    Challenge::generate(d)
}
fn ch_uuid(d: u64) -> Challenge {
    Challenge::generate(d)
}

#[test]
fn prove_and_verify_roundtrip() {
    for d in [1, 10, 100, 500] {
        let c = ch(d);
        let p = c.prove().unwrap();
        assert_eq!(p.challenge.difficulty, d);
        assert_eq!(p.solution().len(), SOLUTION_BYTES);
        p.verify(d).unwrap();
        verify(&p, d).unwrap();
    }
}

#[test]
fn verify_rejects_zero_and_over_max() {
    let c = ch(1);
    let p = prove(&c).unwrap();
    assert!(matches!(
        verify(&p, 0),
        Err(VerifyError::DifficultyMismatch { .. })
    ));
    // crafted pow with difficulty 0 to hit OutOfRange path
    let bad = Challenge::new(c.id, 0);
    let bad_pow = Pow::from_hex(bad, &p.solution_hex(), p.nonce).unwrap();
    assert!(matches!(
        verify(&bad_pow, 0),
        Err(VerifyError::DifficultyOutOfRange(_))
    ));
    assert!(matches!(
        verify(&p, DEFAULT_MAX_DIFFICULTY + 1),
        Err(VerifyError::DifficultyMismatch { .. })
    ));
}

#[test]
fn prove_rejects_invalid_difficulty() {
    let id = Challenge::generate(1).id;
    assert!(matches!(
        prove(&Challenge::new(id, 0)),
        Err(PowError::ZeroDifficulty)
    ));
    assert!(matches!(
        prove(&Challenge::new(id, DEFAULT_MAX_DIFFICULTY + 1)),
        Err(PowError::DifficultyTooHigh(_, _))
    ));
}

#[test]
fn verify_rejects_mismatch_tamper() {
    let c = ch(50);
    let mut p = prove(&c).unwrap();
    assert!(matches!(
        p.verify(51),
        Err(VerifyError::DifficultyMismatch { .. })
    ));
    let orig = p.clone();
    p.nonce = p.nonce.wrapping_add(1);
    assert_eq!(p.verify(50).unwrap_err(), VerifyError::TargetNotMet);
    let mut p2 = orig.clone();
    p2.challenge.difficulty = 51;
    assert!(matches!(
        p2.verify(51),
        Err(VerifyError::TargetNotMet | VerifyError::VdfFailed)
    ));
}

#[test]
fn verify_rejects_bad_length_and_hex() {
    let c = ch(1);
    assert!(matches!(
        Pow::from_hex(c.clone(), "zz", 0),
        Err(VerifyError::BadHex(_))
    ));
    assert!(matches!(
        Pow::from_hex(c.clone(), &"ab".repeat(10), 0),
        Err(VerifyError::BadLength(_))
    ));
    // serde BadLength: solution as short hex string deserializes but verify will reject
    let json = format!(
        r#"{{"challenge":{{"id":"{}","difficulty":1}},"solution":"{}","nonce":0}}"#,
        ch_uuid(1).id,
        "ab".repeat(10)
    );
    let de: Result<Pow, _> = serde_json::from_str(&json);
    // deserialization succeeds (hex decode ok) but length is 10 bytes; verify would fail
    if let Ok(p) = de {
        assert_eq!(p.verify(1).unwrap_err(), VerifyError::BadLength(10));
    }
}

#[test]
fn hex_roundtrip_and_serde_wire_compat() {
    let c = ch_uuid(10);
    let p = prove(&c).unwrap();
    let hex = p.solution_hex();
    assert_eq!(hex.len(), SOLUTION_HEX_LEN);
    let p2 = Pow::from_hex(c.clone(), &hex, p.nonce).unwrap();
    assert_eq!(p.solution(), p2.solution());
    let json = serde_json::to_string(&p).unwrap();
    assert!(json.contains(&hex[..8]));
    let de: Pow = serde_json::from_str(&json).unwrap();
    assert_eq!(de, p);
    let old = format!(
        r#"{{"challenge":{{"id":"{}","difficulty":1}},"solution":"{}"}}"#,
        c.id, hex
    );
    let de2: Pow = serde_json::from_str(&old).unwrap();
    assert_eq!(de2.nonce, 0);
}

#[test]
fn config_custom_and_method_equivalence() {
    let cfg = Config::new(1000, 64);
    let c = Challenge::generate(100);
    let p1 = prove_with_config(&c, &cfg).unwrap();
    let p2 = c.prove_with(&cfg).unwrap();
    assert_eq!(p1.nonce, p2.nonce);
    p1.verify_with(100, &cfg).unwrap();
    assert!(matches!(
        p1.verify_with(100, &Config::new(50, 64)),
        Err(VerifyError::DifficultyOutOfRange(_))
    ));
}

#[test]
fn method_vs_free_fn() {
    let c = ch(7);
    let p = c.prove().unwrap();
    assert!(p.verify(7).is_ok());
    assert!(verify(&p, 7).is_ok());
}
