# dilithium-go

A high-performance, FIPS 204 (ML-DSA) compatible, pure Go implementation of the CRYSTALS-Dilithium signature scheme. 
Ported directly from the [lattice-safe/dilithium-rs](https://github.com/lattice-safe/dilithium-rs) implementation, achieving byte-for-byte parity with the reference test vectors.

## Features

- **Pure Go**: No CGO dependencies, memory-safe by default.
- **FIPS 204 Compliant**: Supports both pure **ML-DSA** and **HashML-DSA** variants.
- **Security Levels**: Fully supports ML-DSA-44 (Level 2), ML-DSA-65 (Level 3), and ML-DSA-87 (Level 5).
- **Constant Time**: Reductions, rounding, and signature verification challenge comparisons are designed to resist timing side channels.
- **Bit-Exact Parity**: Verified against NIST KAT (Known Answer Test) vectors, ensuring absolute compatibility with official C and Rust reference implementations.

## Installation

```bash
go get github.com/lattice-safe/dilithium-go
```

## Quick Start

```go
package main

import (
	"fmt"
	"log"

	"github.com/lattice-safe/dilithium-go"
)

func main() {
	// Generate a new ML-DSA-44 keypair (NIST Security Level 2)
	keypair, err := dilithium.Generate(dilithium.Dilithium2)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("Hello, post-quantum world!")
	ctx := []byte("") // Optional context string

	// Sign the message
	sig, err := keypair.Sign(msg, ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Verify the signature
	valid := dilithium.VerifySignature(keypair.PublicKey(), sig, msg, ctx, dilithium.Dilithium2)
	if valid {
		fmt.Println("Signature successfully verified!")
	} else {
		fmt.Println("Signature verification failed.")
	}
}
```

## Security Modes

| FIPS 204 Name | Constant               | NIST Level | Public Key | Secret Key | Signature |
|---------------|------------------------|------------|------------|------------|-----------|
| ML-DSA-44     | `dilithium.Dilithium2` | 2          | 1312 B     | 2560 B     | 2420 B    |
| ML-DSA-65     | `dilithium.Dilithium3` | 3          | 1952 B     | 4032 B     | 3309 B    |
| ML-DSA-87     | `dilithium.Dilithium5` | 5          | 2592 B     | 4896 B     | 4627 B    |

## Testing

Run the full test suite, which includes round-trip signing/verification tests and deterministic NIST KAT vector validation:

```bash
go test -v ./...
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
