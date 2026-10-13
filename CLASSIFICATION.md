# Classification rules (specification)

`qraf.cbom_lite.classify` must implement these rules. The tests in
`tests/test_classify.py` check them. Sources to read before you start:
NIST FIPS 203, 204 and 205 (August 2024), NIST IR 8547 (initial public draft,
November 2024), and the CycloneDX CBOM guide.

## 1. Normalizing names (`normalize_algorithm`)

Scanners and certificates report the same algorithm under many names. Return a
`(family, parameter)` pair. Matching is case-insensitive and ignores `-` and `_`.

| Input examples | Family | Parameter |
| --- | --- | --- |
| `ML-KEM-768`, `mlkem768`, `MLKEM_768` | `ML-KEM` | `768` |
| `ML-DSA-65`, `mldsa65` | `ML-DSA` | `65` |
| `SLH-DSA-SHA2-128s` | `SLH-DSA` | `SHA2-128s` |
| `rsaEncryption`, `RSA` | `RSA` | (empty) |
| `X25519MLKEM768`, `SecP256r1MLKEM768` | the input, unchanged (hybrid group name) | (empty) |
| anything not recognized | the input, unchanged | (empty) |

## 2. Categories (`classify(family, parameter)`)

| Family | Category | NIST quantum level | classical_weak |
| --- | --- | --- | --- |
| RSA, DSA, DH, ECDSA, ECDH, EdDSA, Ed25519, Ed448, X25519, X448 | quantum-vulnerable | 0 | True if RSA/DSA/DH parameter is a number below 2048 |
| ML-KEM 512 / 768 / 1024 | quantum-resistant | 1 / 3 / 5 | False |
| ML-DSA 44 / 65 / 87 | quantum-resistant | 2 / 3 / 5 | False |
| SLH-DSA, parameter containing 128 / 192 / 256 | quantum-resistant | 1 / 3 / 5 | False |
| Hybrid groups (name contains MLKEM and a classical group) | hybrid | level of the ML-KEM part | False |
| AES-256, ChaCha20, SHA-256, SHA-384, SHA-512, SHA3-* | symmetric-adequate | None | False |
| AES-128 | symmetric-review | None | False |
| 3DES, RC4, MD5, SHA-1 | symmetric-review | None | True |
| anything else | unknown | None | False |

Notes you should be able to explain:

* Shor's algorithm breaks RSA, DH and elliptic-curve schemes, which is why
  every one of them gets level 0 regardless of key size.
* Grover's algorithm only weakens symmetric ciphers and hashes, so AES-256 and
  SHA-256 stay adequate. AES-128 is flagged for review, not as vulnerable.
* A hybrid group stays secure as long as either of its two parts holds.
