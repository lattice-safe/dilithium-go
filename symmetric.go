package dilithium

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// Stream128 represents SHAKE128 stream state.
type Stream128 struct {
	hasher sha3.ShakeHash
}

// NewStream128 initializes SHAKE128 stream: absorb seed || le16(nonce).
func NewStream128(seed *[SEEDBYTES]byte, nonce uint16) *Stream128 {
	hasher := sha3.NewShake128()
	_, _ = hasher.Write(seed[:])
	var nonceBytes [2]byte
	binary.LittleEndian.PutUint16(nonceBytes[:], nonce)
	_, _ = hasher.Write(nonceBytes[:])
	return &Stream128{hasher: hasher}
}

// Squeeze squeezes bytes from the stream.
func (s *Stream128) Squeeze(out []byte) {
	_, _ = s.hasher.Read(out)
}

// Stream256 represents SHAKE256 stream state.
type Stream256 struct {
	hasher sha3.ShakeHash
}

// NewStream256 initializes SHAKE256 stream: absorb seed || le16(nonce).
func NewStream256(seed *[CRHBYTES]byte, nonce uint16) *Stream256 {
	hasher := sha3.NewShake256()
	_, _ = hasher.Write(seed[:])
	var nonceBytes [2]byte
	binary.LittleEndian.PutUint16(nonceBytes[:], nonce)
	_, _ = hasher.Write(nonceBytes[:])
	return &Stream256{hasher: hasher}
}

// Squeeze squeezes bytes from the stream.
func (s *Stream256) Squeeze(out []byte) {
	_, _ = s.hasher.Read(out)
}

// Shake256 computes SHAKE256(input) and writes to output.
func Shake256(output []byte, input []byte) {
	hasher := sha3.NewShake256()
	_, _ = hasher.Write(input)
	_, _ = hasher.Read(output)
}

// Shake256State represents incremental SHAKE256 state for multi-absorb patterns.
type Shake256State struct {
	hasher sha3.ShakeHash
}

// Shake256Reader represents SHAKE256 XOF reader after finalization.
type Shake256Reader struct {
	hasher sha3.ShakeHash
}

// NewShake256State creates new SHAKE256 state.
func NewShake256State() *Shake256State {
	return &Shake256State{
		hasher: sha3.NewShake256(),
	}
}

// Absorb absorbs data.
func (s *Shake256State) Absorb(data []byte) {
	_, _ = s.hasher.Write(data)
}

// Finalize returns reader for squeezing.
func (s *Shake256State) Finalize() *Shake256Reader {
	return &Shake256Reader{
		hasher: s.hasher,
	}
}

// Squeeze squeezes bytes.
func (r *Shake256Reader) Squeeze(out []byte) {
	_, _ = r.hasher.Read(out)
}

func Shake256Multi(output []byte, inputs [][]byte) {
	hasher := sha3.NewShake256()
	for _, input := range inputs {
		_, _ = hasher.Write(input)
	}
	_, _ = hasher.Read(output)
}
