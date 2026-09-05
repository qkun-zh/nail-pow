# nail-pow

Production PoW crate extracted from [nail](https://github.com/qkun-zh/nail) – Ascon-CXOF hash-target + MinRoot VDF.

```rust
use nail_pow::{issue_challenge, prove, verify};
let ch = issue_challenge(100);
let pow = prove(&ch).unwrap();
verify(&pow, 100).unwrap();
```
