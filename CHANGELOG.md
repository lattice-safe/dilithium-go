# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-18

### Added
- **Pure Go Implementation**: Full, CGO-free Go port of the CRYSTALS-Dilithium signature scheme.
- **FIPS 204 Compliance**: Support for both pure ML-DSA and HashML-DSA variants.
- **Security Levels**: Full support for ML-DSA-44, ML-DSA-65, and ML-DSA-87 (`Dilithium2`, `Dilithium3`, `Dilithium5`).
- **NIST KAT Vectors**: Verified bit-exact parity with official C and Rust test vectors.
- **Fuzzing**: Native Go fuzz targets for Unpacking and Signature Verification.
- **Benchmarks**: Full `testing.B` suite to measure Key Generation, Signing, and Verification performance.
- **AVX2 Framework**: Added runtime dispatch and architectural stubs for future `avo` AVX2/NEON optimizations (`ntt_dispatch.go`).

### Changed
- Refactored `ntt.go` to provide a clean scalar fallback (`nttScalar`, `invNTTScalar`).

### Security
- **Constant Time**: Montgomery reductions, Barrett reductions, and signature challenge comparison are fully constant-time to resist side-channels.
- **Zeroization**: Sensitive arrays (`seedbuf`, `rhoprime`, `key`, `expanded`) are explicitly wiped from memory after their use.
