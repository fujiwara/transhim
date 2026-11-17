package transhim

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	tests := []WrappedKey{
		{KeyRef: "", Version: 1, Blob: nil},
		{KeyRef: "h1", Version: 1, Blob: []byte("blob")},
		{KeyRef: "arn:aws:kms:ap-northeast-1:123456789012:key/0000", Version: 12, Blob: bytes.Repeat([]byte{0xff}, 300)},
		{KeyRef: strings.Repeat("r", 200), Version: 1, Blob: []byte{0}},
	}
	for _, want := range tests {
		s := encodeEnvelope(want)
		got, err := decodeEnvelope(s)
		if err != nil {
			t.Errorf("decode %q: %v", s, err)
			continue
		}
		if got.KeyRef != want.KeyRef || got.Version != want.Version || !bytes.Equal(got.Blob, want.Blob) {
			t.Errorf("round trip of %+v gave %+v", want, got)
		}
	}
}

func TestEnvelopeVersionAtLeastOne(t *testing.T) {
	for _, v := range []int{-1, 0, 1} {
		s := encodeEnvelope(WrappedKey{Version: v, Blob: []byte("x")})
		if !strings.HasPrefix(s, "vault:v1:") {
			t.Errorf("version %d encoded as %q", v, s)
		}
	}
	if s := encodeEnvelope(WrappedKey{Version: 3}); !strings.HasPrefix(s, "vault:v3:") {
		t.Errorf("version 3 encoded as %q", s)
	}
}

func TestDecodeEnvelopeErrors(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	valid := []byte{0x01, 0x00, 0x01, 'k', 0x01, 'b'}
	tests := map[string]string{
		"empty":              "",
		"no prefix":          b64(valid),
		"other prefix":       "bao:v1:" + b64(valid),
		"no version":         "vault:v:" + b64(valid),
		"version zero":       "vault:v0:" + b64(valid),
		"negative version":   "vault:v-1:" + b64(valid),
		"signed version":     "vault:v+1:" + b64(valid),
		"leading zero":       "vault:v01:" + b64(valid),
		"no payload part":    "vault:v1",
		"bad base64":         "vault:v1:!!!",
		"url base64":         "vault:v1:" + base64.URLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01, 0xff, 0x01, 0xfe}),
		"empty payload":      "vault:v1:",
		"short payload":      "vault:v1:" + b64([]byte{0x01}),
		"format version":     "vault:v1:" + b64([]byte{0x02, 0x00, 0x01, 'k', 0x01, 'b'}),
		"flags set":          "vault:v1:" + b64([]byte{0x01, 0x01, 0x01, 'k', 0x01, 'b'}),
		"keyRef too long":    "vault:v1:" + b64([]byte{0x01, 0x00, 0x09, 'k'}),
		"missing blob":       "vault:v1:" + b64([]byte{0x01, 0x00, 0x01, 'k'}),
		"blob too long":      "vault:v1:" + b64([]byte{0x01, 0x00, 0x01, 'k', 0x02, 'b'}),
		"trailing bytes":     "vault:v1:" + b64(append(bytes.Clone(valid), 0x00)),
		"huge length":        "vault:v1:" + b64([]byte{0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}),
		"overflowing varint": "vault:v1:" + b64([]byte{0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}),
		"non-minimal varint": "vault:v1:" + b64([]byte{0x01, 0x00, 0x81, 0x00, 'k', 0x01, 'b'}),
		"a real Vault one":   "vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w==",
	}
	for name, s := range tests {
		if _, err := decodeEnvelope(s); !errors.Is(err, ErrCiphertextMismatch) {
			t.Errorf("%s: err = %v, want ErrCiphertextMismatch", name, err)
		}
	}
	if _, err := decodeEnvelope("vault:v1:" + b64(valid)); err != nil {
		t.Errorf("valid envelope: %v", err)
	}
}

func FuzzDecodeEnvelope(f *testing.F) {
	f.Add(encodeEnvelope(WrappedKey{KeyRef: "h1", Version: 1, Blob: []byte("blob")}))
	f.Add("vault:v1:")
	f.Add("vault:v1:AQAB")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		wk, err := decodeEnvelope(s)
		if err != nil {
			if !errors.Is(err, ErrCiphertextMismatch) {
				t.Fatalf("unexpected error kind: %v", err)
			}
			return
		}
		// whatever decodes must encode back to the same string
		if got := encodeEnvelope(wk); got != s {
			t.Fatalf("decode(%q) re-encodes to %q", s, got)
		}
	})
}

func TestBuildAAD(t *testing.T) {
	got := buildAAD("rgw-kms", "my-key", []byte("ctx\x00bytes"))
	want := []byte("transhim/v1\x00rgw-kms\x00my-key\x00ctx\x00bytes")
	if !bytes.Equal(got, want) {
		t.Errorf("AAD = %q, want %q", got, want)
	}
	if got := buildAAD("m", "k", nil); !bytes.Equal(got, []byte("transhim/v1\x00m\x00k\x00")) {
		t.Errorf("AAD without context = %q", got)
	}
	// moving a byte between fields must change the AAD
	if bytes.Equal(buildAAD("ab", "c", nil), buildAAD("a", "bc", nil)) {
		t.Error("AAD does not separate mount ID and key name")
	}
	if bytes.Equal(buildAAD("m", "ab", nil), buildAAD("m", "a", []byte("b"))) {
		t.Error("AAD does not separate key name and context")
	}
}

func TestValidateKeyName(t *testing.T) {
	valid := []string{
		"k", "my-key", "a.b_c-d", "tenant$user", "with space", "日本語",
		"1434f035-2747-4d60-a14f-5a0efa651729.4126.2",
	}
	for _, name := range valid {
		if err := validateKeyName(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	invalid := []string{"", "a/b", "/", "a\x00b", "a\nb", "a\x7fb", "a\u0085b", "a\xffb"}
	for _, name := range invalid {
		if err := validateKeyName(name); err == nil {
			t.Errorf("%q: accepted", name)
		}
	}
}

func TestNormalizePrefix(t *testing.T) {
	tests := map[string]string{
		"/v1/transit":   "/v1/transit",
		"v1/transit":    "/v1/transit",
		"/v1/transit/":  "/v1/transit",
		"//v1/transit/": "/v1/transit",
		"/transit":      "/transit",
		"/v1/a.b-c_d~e": "/v1/a.b-c_d~e",
	}
	for in, want := range tests {
		got, err := normalizePrefix(in)
		if err != nil || got != want {
			t.Errorf("normalizePrefix(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "/", "//", "/v1//transit", "/v1/tran sit", "/v1/a%2Fb", "/v1/a?b", "/v1/a#b"} {
		if got, err := normalizePrefix(in); err == nil {
			t.Errorf("normalizePrefix(%q) = %q, want an error", in, got)
		}
	}
}
