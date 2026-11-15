package subscription

import (
	"encoding/base64"
	"testing"
)

// FuzzParseBody feeds hostile subscription bodies to the importer.
//
// A body is whatever a provider's HTTP endpoint returned, so it may be base64,
// wrapped base64, plain text with a byte order mark, a list with comments, or
// none of those. parseBody decodes it, splits it, and hands each line to the link
// importer; the failure this target looks for is a panic in that decoding and
// splitting, which runs before any per-link validation can report something
// sensible.
//
// The seeds are the two shapes subscription_test.go uses: the base64 body wrapped
// at 76 columns, and the plain-text body with a byte order mark, blank lines and
// a comment. Both are fed through decodeSubscription, so the two paths of that
// function start the corpus already populated.
func FuzzParseBody(f *testing.F) {
	// The link the test file uses for both shapes.
	link := testLink

	wrapped := base64.StdEncoding.EncodeToString([]byte(link + "\n" + link + "\n"))
	var folded string
	for i := 0; i < len(wrapped); i += 76 {
		end := i + 76
		if end > len(wrapped) {
			end = len(wrapped)
		}
		folded += wrapped[i:end] + "\n"
	}

	seeds := []string{
		link,
		link + "\n" + link + "\n",
		wrapped,
		folded,
		"\ufeff" + link + "\r\n\r\n// provider notice\r\n  \r\n" + link + "\r\n",
		"# only a comment\n",
		"",
		base64.StdEncoding.EncodeToString([]byte("not a link\n")),
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		proxies, err := parseBody(body)
		if err != nil {
			return
		}
		if len(proxies) == 0 {
			t.Fatal("parseBody reported success with no proxy")
		}
		for _, proxy := range proxies {
			if proxy.Type == "" || proxy.Server == "" || proxy.Port < 1 || proxy.Port > 65535 {
				t.Fatalf("parseBody accepted an entry that cannot be dialled: %+v", proxy)
			}
		}
	})
}
