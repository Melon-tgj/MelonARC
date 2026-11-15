package outbound

// BLAKE3, needed by the 2022 AEAD family: it derives the per-session subkey
// with BLAKE3's derive-key mode, and the Go standard library has no BLAKE3.
//
// The primitive used to live here as a ~230 line implementation, because the
// module proxy was unreachable when the 2022 family was written. It is now
// taken from lukechampine.com/blake3: the same published vectors pass, the
// derived subkeys were compared byte for byte against the old implementation
// before the switch (see blake3_test.go), and a hand-written compression
// function is not something this project should keep maintaining.
//
// The three functions below keep their names and signatures so that the call
// sites do not move and the difference stays in one file.

import "lukechampine.com/blake3"

// b3OutLen is the length of every value derived here: BLAKE3's default output.
const b3OutLen = 32

// blake3Hash is the default (unkeyed) hash.
func blake3Hash(data []byte) [b3OutLen]byte {
	return blake3.Sum256(data)
}

// blake3Keyed hashes data with a 32-byte key.
func blake3Keyed(key [b3OutLen]byte, data []byte) [b3OutLen]byte {
	h := blake3.New(b3OutLen, key[:])
	h.Write(data)
	var out [b3OutLen]byte
	copy(out[:], h.Sum(nil))
	return out
}

// blake3DeriveKey is BLAKE3's key derivation mode: the context is hashed with
// the derive-key-context flag, and its output becomes the key of a
// derive-key-material hash over the key material. The 2022 AEAD family calls
// this with the context "shadowsocks 2022 session subkey".
func blake3DeriveKey(context string, material []byte) [b3OutLen]byte {
	var out [b3OutLen]byte
	blake3.DeriveKey(out[:], context, material)
	return out
}
