package outbound

import (
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// BLAKE3 test vectors. The first table is the published set from the BLAKE3
// reference repository (test_vectors.json): the input of length n is
// byte(i % 251) for i in [0, n), and the keyed and derive-key columns use the
// key and context below. Only the first 32 bytes of each extended output are
// compared, which is the default-length output this project uses.
//
// The lengths cover the block edge (63/64/65), the chunk edge (1023/1024/1025),
// several chunks (2048) and deep trees (31744, 100000), so a change in chunk
// chaining, parent folding or the root output is caught here.
const (
	b3VectorContext = "BLAKE3 2019-12-27 16:29:52 test vectors context"
	b3VectorKey     = "whats the Elvish word for friend"
)

// b3VectorInput is the input the published vectors are defined over.
func b3VectorInput(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func b3Check(t *testing.T, name, wantHex string, got [b3OutLen]byte) {
	t.Helper()
	if h := hex.EncodeToString(got[:]); h != wantHex {
		t.Errorf("%s: got %s, want %s", name, h, wantHex)
	}
}

// b3OfficialVectors is the published table, first 32 bytes of every column.
var b3OfficialVectors = []struct {
	length int
	hash   string
	keyed  string
	derive string
}{
	{0,
		"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
		"92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
		"2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"},
	{1,
		"2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
		"6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
		"b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"},
	{1023,
		"10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
		"c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e",
		"74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5"},
	{1024,
		"42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
		"75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4",
		"7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"},
	{1025,
		"d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
		"357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69",
		"effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb"},
	{2048,
		"e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
		"879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd1",
		"7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23"},
	{31744,
		"62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47",
		"efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a419",
		"39772aef80e0ebe60596361e45b061e8f417429d529171b6764468c22928e28e"},
	{100000,
		"d93c23eedaf165a7e0be908ba86f1a7a520d568d2d13cde787c8580c5c72cc54",
		"74c836d008247adebbc032d1bced2e71d19050b5c39fa03c43d4160ad8d17073",
		"039c0c0d76eacefea9c8d042698bd012d3cef4091ed5c5a7e32a30e4d5171893"},
}

func TestBlake3OfficialHashVectors(t *testing.T) {
	for _, tc := range b3OfficialVectors {
		t.Run("len_"+strconv.Itoa(tc.length), func(t *testing.T) {
			b3Check(t, "hash", tc.hash, blake3Hash(b3VectorInput(tc.length)))
		})
	}
}

func TestBlake3OfficialKeyedVectors(t *testing.T) {
	var key [b3OutLen]byte
	copy(key[:], b3VectorKey)
	for _, tc := range b3OfficialVectors {
		t.Run("len_"+strconv.Itoa(tc.length), func(t *testing.T) {
			b3Check(t, "keyed_hash", tc.keyed, blake3Keyed(key, b3VectorInput(tc.length)))
		})
	}
}

func TestBlake3OfficialDeriveKeyVectors(t *testing.T) {
	for _, tc := range b3OfficialVectors {
		t.Run("len_"+strconv.Itoa(tc.length), func(t *testing.T) {
			b3Check(t, "derive_key", tc.derive, blake3DeriveKey(b3VectorContext, b3VectorInput(tc.length)))
		})
	}
}

// The published set has no 5000- and no 102400-byte case. These four values
// were produced by the implementation this package used before the switch and
// confirmed byte for byte against the module that replaced it (stage 19), so
// they pin the multi-chunk and 100-chunk paths the published lengths do not
// reach exactly.
func TestBlake3CrossCheckedHashAndKeyed(t *testing.T) {
	var key [b3OutLen]byte
	copy(key[:], b3VectorKey)
	cases := []struct {
		length int
		hash   string
		keyed  string
	}{
		{5000,
			"ee78d92070de3df1c57c37002abf0a6b1a6589acdeef4d8ffac7cf3d9e8f2836",
			"27dc394fb01f055606c3aedde3a8c3694c34a8c514cc61a27279f1417cc385e0"},
		{102400,
			"bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085",
			"1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7"},
	}
	for _, tc := range cases {
		input := b3VectorInput(tc.length)
		b3Check(t, "hash of "+strconv.Itoa(tc.length), tc.hash, blake3Hash(input))
		b3Check(t, "keyed_hash of "+strconv.Itoa(tc.length), tc.keyed, blake3Keyed(key, input))
	}
}

// TestBlake3SessionSubkeyIsStable pins the value the 2022 AEAD family actually
// uses: derive-key with the session-subkey context. The constants come from the
// differential run described above; a later change of BLAKE3 provider that moved
// any of them would silently break every 2022 connection, and this test says so
// before the wire does.
func TestBlake3SessionSubkeyIsStable(t *testing.T) {
	const context = "shadowsocks 2022 session subkey"
	cases := []struct {
		material int
		want     string
	}{
		{0, "afb6139d93ec751ab7bd04bf0a2a396e1bf7dce0a45ee37a5e98d7cb8154f3e1"},
		{32, "bc32fb8d5205f7b84f9691dfb9f04ff344ce477c416be1d79c419b9e2c04c3e9"},
		{64, "374fca03e4dae7f998fd7e59c1edfcc8e3197f4db1c19ca1671be3b66a92ddda"},
		{100, "3b04b1e1f972e772648e3223690eab76f58c7899d90f66f002c312904f18e114"},
		{1024, "33dcf4aa9e340f529954dd9c2796325f4b471a9a1c59e3a15e8af8e061ba69c0"},
		{5000, "277a99a6dab68f7a49a433fe7d06633a85b31edb637396c57bd6264230528a21"},
		{102400, "b046826c3d5cff64c41e3418733c48ab1732cbbdfb4344ec96dcc54115386693"},
		{102401, "ea311f49efafcf2af202669129558e6969602e76eb3fe6539237887308e772be"},
	}
	for _, tc := range cases {
		got := blake3DeriveKey(context, b3VectorInput(tc.material))
		if h := hex.EncodeToString(got[:]); h != tc.want {
			t.Errorf("session subkey for %d bytes of material: got %s, want %s", tc.material, h, tc.want)
		}
	}
}

func TestBlake3DeriveKeyContextIsDomainSeparated(t *testing.T) {
	// Two different contexts must not produce the same subkey for the same
	// material. This is the property the 2022 session subkey relies on.
	a := blake3DeriveKey("shadowsocks 2022 session subkey", []byte("material"))
	b := blake3DeriveKey("some other context", []byte("material"))
	if a == b {
		t.Fatal("derive_key ignored its context")
	}
	if strings.Repeat("0", 2*b3OutLen) == hex.EncodeToString(a[:]) {
		t.Fatal("derive_key returned an all-zero key")
	}
}
