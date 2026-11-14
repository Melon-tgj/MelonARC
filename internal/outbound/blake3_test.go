package outbound

import (
	"encoding/hex"
	"strings"
	"testing"
)

// These are the published BLAKE3 test vectors (test_vectors.json from the BLAKE3
// reference repository). The input of length n is byte(i % 251) for i in
// [0, n); the "keyed_hash" and "derive_key" columns use the context string and
// key below. Only the first 32 bytes of each extended output are compared,
// which is exactly the default-length output this project uses.
const (
	b3VectorContext = "BLAKE3 2019-12-27 16:29:52 test vectors context"
	b3VectorKey     = "whats the Elvish word for friend"
)

func b3VectorInput(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func b3Check(t *testing.T, name, wantHex string, got [b3OutLen]byte) {
	t.Helper()
	want := wantHex[:2*b3OutLen]
	if h := hex.EncodeToString(got[:]); h != want {
		t.Errorf("%s: got %s, want %s", name, h, want)
	}
}

func TestBlake3OfficialHashVectors(t *testing.T) {
	cases := []struct {
		length int
		want   string
	}{
		{0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
		{1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"},
		{2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"},
		{3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"},
		{4, "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f328f6"},
		{64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98fc9"},
		{65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee0"},
		{1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af71cf8"},
		{1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444f4"},
		{2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a9a"},
		{31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c478"},
	}
	for _, tc := range cases {
		t.Run("len_"+itoa(tc.length), func(t *testing.T) {
			b3Check(t, "hash", tc.want, blake3Hash(b3VectorInput(tc.length)))
		})
	}
}

func TestBlake3OfficialKeyedAndDeriveKeyVectors(t *testing.T) {
	var key [b3OutLen]byte
	copy(key[:], b3VectorKey)
	cases := []struct {
		length    int
		keyed     string
		deriveKey string
	}{
		{0,
			"92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
			"2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"},
		{1,
			"6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
			"b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"},
		{2,
			"5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a",
			"1f166565a7df0098ee65922d7fea425fb18b9943f19d6161e2d17939356168e6"},
		{3,
			"39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9",
			"440aba35cb006b61fc17c0529255de438efc06a8c9ebf3f2ddac3b5a86705797"},
		{64,
			"ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e682",
			"a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e"},
		{1024,
			"75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4a",
			"7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"},
	}
	for _, tc := range cases {
		t.Run("len_"+itoa(tc.length), func(t *testing.T) {
			input := b3VectorInput(tc.length)
			b3Check(t, "keyed_hash", tc.keyed, blake3Keyed(key, input))
			b3Check(t, "derive_key", tc.deriveKey, blake3DeriveKey(b3VectorContext, input))
		})
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

// itoa keeps the vector table readable without pulling strconv into the file.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
