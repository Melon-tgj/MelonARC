package outbound

import (
	"encoding/binary"
	"math/bits"
)

// blake3.go is a small, self-contained implementation of the BLAKE3 hash. It
// exists because the 2022 AEAD cipher family derives its per-session subkey
// with BLAKE3's derive-key mode, and the Go standard library has no BLAKE3.
// Keeping the primitive here (rather than adding another module) also keeps the
// dependency list short: the compression function is ~100 lines and every byte
// of it is exercised by the published BLAKE3 test vectors in blake3_test.go.
//
// The hasher buffers its input and computes the tree at finalisation. All the
// inputs this project feeds it are short (a pre-shared key, a salt, a context
// string), so buffering is cheaper than a streaming chunk state and much
// easier to verify. The implementation is otherwise general: chunk chaining,
// parent nodes, extendable root output and all four domain-separation modes are
// covered by the vectors, including multi-chunk (tree) inputs.

const (
	b3BlockLen = 64
	b3ChunkLen = 1024
	b3OutLen   = 32
)

// BLAKE3 domain separation flags.
const (
	b3ChunkStart uint32 = 1 << iota
	b3ChunkEnd
	b3Parent
	b3Root
	b3KeyedHash
	b3DeriveKeyContext
	b3DeriveKeyMaterial
)

var b3IV = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

// b3MessagePermutation is the word schedule of the compression function.
var b3MessagePermutation = [16]int{
	2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
}

func b3Mix(v *[16]uint32, a, b, c, d int, x, y uint32) {
	v[a] += v[b] + x
	v[d] = bits.RotateLeft32(v[d]^v[a], -16)
	v[c] += v[d]
	v[b] = bits.RotateLeft32(v[b]^v[c], -12)
	v[a] += v[b] + y
	v[d] = bits.RotateLeft32(v[d]^v[a], -8)
	v[c] += v[d]
	v[b] = bits.RotateLeft32(v[b]^v[c], -7)
}

// b3Compress is one BLAKE3 block compression. block must be exactly 64 bytes.
// The first eight output words are the chaining value; all sixteen are the
// extendable root output block.
func b3Compress(cv [8]uint32, block []byte, counter uint64, blockLen, flags uint32) [16]uint32 {
	var m [16]uint32
	for i := range m {
		m[i] = binary.LittleEndian.Uint32(block[i*4:])
	}
	var v [16]uint32
	copy(v[:8], cv[:])
	copy(v[8:12], b3IV[:4])
	v[12] = uint32(counter)
	v[13] = uint32(counter >> 32)
	v[14] = blockLen
	v[15] = flags

	for round := 0; round < 7; round++ {
		b3Mix(&v, 0, 4, 8, 12, m[0], m[1])
		b3Mix(&v, 1, 5, 9, 13, m[2], m[3])
		b3Mix(&v, 2, 6, 10, 14, m[4], m[5])
		b3Mix(&v, 3, 7, 11, 15, m[6], m[7])
		b3Mix(&v, 0, 5, 10, 15, m[8], m[9])
		b3Mix(&v, 1, 6, 11, 12, m[10], m[11])
		b3Mix(&v, 2, 7, 8, 13, m[12], m[13])
		b3Mix(&v, 3, 4, 9, 14, m[14], m[15])
		if round < 6 {
			var p [16]uint32
			for i := range m {
				p[i] = m[b3MessagePermutation[i]]
			}
			m = p
		}
	}
	var out [16]uint32
	for i := 0; i < 8; i++ {
		out[i] = v[i] ^ v[i+8]
		out[i+8] = v[i+8] ^ cv[i]
	}
	return out
}

// b3Output is a node whose final block has not been compressed yet. The same
// node yields either a chaining value (to be folded into a parent) or the root
// output (with the ROOT flag), which is what makes BLAKE3 a tree hash.
type b3Output struct {
	inputCV  [8]uint32
	block    [b3BlockLen]byte
	blockLen uint32
	counter  uint64
	flags    uint32
}

func (o b3Output) chainingValue() [8]uint32 {
	out := b3Compress(o.inputCV, o.block[:], o.counter, o.blockLen, o.flags)
	var cv [8]uint32
	copy(cv[:], out[:8])
	return cv
}

func (o b3Output) rootBytes() [b3OutLen]byte {
	out := b3Compress(o.inputCV, o.block[:], o.counter, o.blockLen, o.flags|b3Root)
	var b [b3OutLen]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(b[i*4:], out[i])
	}
	return b
}

type b3Hasher struct {
	key   [8]uint32
	flags uint32
	buf   []byte
}

func b3KeyWords(key []byte) [8]uint32 {
	var words [8]uint32
	for i := range words {
		words[i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	return words
}

func b3ParentNode(left, right [8]uint32, key [8]uint32, flags uint32) b3Output {
	var block [b3BlockLen]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(block[i*4:], left[i])
		binary.LittleEndian.PutUint32(block[32+i*4:], right[i])
	}
	return b3Output{inputCV: key, block: block, blockLen: b3BlockLen, flags: flags | b3Parent}
}

// chunkOutput folds every full block of a chunk into the chaining value and
// leaves the last (possibly empty) block for the output node.
func (h *b3Hasher) chunkOutput(chunk []byte, counter uint64) b3Output {
	cv := h.key
	compressed := 0
	for len(chunk) > b3BlockLen {
		flags := h.flags
		if compressed == 0 {
			flags |= b3ChunkStart
		}
		out := b3Compress(cv, chunk[:b3BlockLen], counter, b3BlockLen, flags)
		copy(cv[:], out[:8])
		chunk = chunk[b3BlockLen:]
		compressed++
	}
	var block [b3BlockLen]byte
	copy(block[:], chunk)
	flags := h.flags | b3ChunkEnd
	if compressed == 0 {
		flags |= b3ChunkStart
	}
	return b3Output{
		inputCV: cv, block: block,
		blockLen: uint32(len(chunk)), counter: counter, flags: flags,
	}
}

func (h *b3Hasher) sum32() [b3OutLen]byte {
	var stack [][8]uint32
	var last b3Output
	haveLast := false
	for start := 0; start < len(h.buf); start += b3ChunkLen {
		end := start + b3ChunkLen
		if end > len(h.buf) {
			end = len(h.buf)
		}
		out := h.chunkOutput(h.buf[start:end], uint64(start/b3ChunkLen))
		if end == len(h.buf) {
			last, haveLast = out, true
			break
		}
		cv := out.chainingValue()
		for total := uint64(start/b3ChunkLen + 1); total%2 == 0; total /= 2 {
			left := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			cv = b3ParentNode(left, cv, h.key, h.flags).chainingValue()
		}
		stack = append(stack, cv)
	}
	if !haveLast {
		last = h.chunkOutput(nil, 0)
	}
	out := last
	for i := len(stack) - 1; i >= 0; i-- {
		out = b3ParentNode(stack[i], out.chainingValue(), h.key, h.flags)
	}
	return out.rootBytes()
}

// blake3Hash is the default (unkeyed) hash.
func blake3Hash(data []byte) [b3OutLen]byte {
	h := b3Hasher{key: b3IV, buf: data}
	return h.sum32()
}

// blake3Keyed hashes data with a 32-byte key.
func blake3Keyed(key [b3OutLen]byte, data []byte) [b3OutLen]byte {
	h := b3Hasher{key: b3KeyWords(key[:]), flags: b3KeyedHash, buf: data}
	return h.sum32()
}

// blake3DeriveKey is BLAKE3's key derivation mode: the context is hashed with
// the DERIVE_KEY_CONTEXT domain, and its output becomes the key of a
// DERIVE_KEY_MATERIAL hash over the key material. The 2022 AEAD family calls
// this with the context "shadowsocks 2022 session subkey".
func blake3DeriveKey(context string, material []byte) [b3OutLen]byte {
	ctx := b3Hasher{key: b3IV, flags: b3DeriveKeyContext, buf: []byte(context)}
	contextKey := ctx.sum32()
	h := b3Hasher{key: b3KeyWords(contextKey[:]), flags: b3DeriveKeyMaterial, buf: material}
	return h.sum32()
}
