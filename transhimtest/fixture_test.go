package transhimtest_test

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/hierarchical"
	"github.com/fujiwara/transhim/keystore/memstore"
	"github.com/fujiwara/transhim/transhimtest"
)

// The golden fixtures are the captures of docs/compat.md: what Ceph RGW
// really sent to an OpenBao Transit engine, and what it got back. The
// "-empty-key-writes" captures are used, where key create and config were
// answered with an empty 204 as transhim does.
const fixtureGlob = "../testdata/capture/*-empty-key-writes.jsonl"

// record is one line of a capture file (see tools/vaultrec).
type record struct {
	Seq     int    `json:"seq"`
	Mark    string `json:"mark"`
	Request *struct {
		Method string              `json:"method"`
		Path   string              `json:"path"`
		Header map[string][]string `json:"header"`
		Body   string              `json:"body"`
	} `json:"request"`
	Response *struct {
		Status int                 `json:"status"`
		Header map[string][]string `json:"header"`
		Body   string              `json:"body"`
	} `json:"response"`
}

// difference is a place where transhim deliberately answers a probe unlike
// OpenBao. Every other recorded exchange must be answered with the recorded
// status and, for errors, the recorded message.
type difference struct {
	status int    // 0: as recorded
	msg    string // "": as recorded
}

// otherFields lists the probes that transhim answers as OpenBao does, but
// with other fields in the data.
var otherFields = map[string]bool{
	// transhim has no derived keys: a key read never has the fields that
	// describe the derivation
	"read derived key": true,
}

// differences is keyed by the probe's label in compat/capture.sh. The reasons
// are in docs/compat.md ("Reference behavior worth knowing").
var differences = map[string]difference{
	// no exportable keys
	"create key, exportable": {400, "exportable keys are not supported"},
	// transhim has no derived keys: a context is optional, but bound whenever
	// it is given, where OpenBao ignores it for non-derived keys
	"datakey, derived key without context":          {200, ""},
	"decrypt, context added on a non-derived key":   {400, "invalid ciphertext"},
	"decrypt, context dropped on a non-derived key": {400, "invalid ciphertext"},
	// one message for everything that is wrong with a ciphertext
	"decrypt, derived key, wrong context":  {0, "invalid ciphertext"},
	"decrypt, derived key, no context":     {0, "invalid ciphertext"},
	"decrypt, wrong key":                   {0, "invalid ciphertext"},
	"decrypt, tampered ciphertext":         {0, "invalid ciphertext"},
	"decrypt, version that does not exist": {0, "invalid ciphertext"},
	"decrypt, no vault prefix":             {0, "invalid ciphertext"},
	"decrypt, payload is not base64":       {0, "invalid ciphertext"},
	// no detail from decoders in messages
	"datakey, malformed JSON":             {0, "failed to decode JSON input"},
	"encrypt, plaintext is not base64":    {0, "failed to base64-decode plaintext"},
	"datakey, GET":                        {0, "unsupported operation"},
	"unknown operation":                   {0, "unsupported path"},
	"unknown mount":                       {0, "no handler for route"},
	"encrypt, missing key (auto-create?)": {400, "encryption key not found"},
	// key deletion: the same rule (the mount has RequireDeletionAllowed) in
	// other words. The flag goes away with the key, so a second delete is
	// refused for that reason, not because the key is missing. Configuring a
	// missing key succeeds: transhim cannot tell whether a key exists.
	"delete key without deletion_allowed": {0, "deletion is not allowed for this key"},
	"delete key again (missing)":          {0, "deletion is not allowed for this key"},
	"config on a missing key":             {204, ""},
}

const fixtureToken = "fixture-token"

type replayer struct {
	t       *testing.T
	handler http.Handler
	kms     *transhimtest.FakeBackend
	// payloads maps the payload of a recorded ciphertext (the part after
	// "vault:v1:") to the payload transhim returned for the same request.
	payloads map[string]string
	// plaintexts maps a transhim ciphertext to the plaintext it wraps.
	plaintexts map[string]string
	used       map[string]bool
}

func newReplayer(t *testing.T) *replayer {
	t.Helper()
	root := transhimtest.NewFakeBackend()
	root.AddKey("rgw-sse-s3", "root")
	sse, err := hierarchical.New(root, "root", memstore.New())
	if err != nil {
		t.Fatal(err)
	}
	r := &replayer{
		t:          t,
		kms:        transhimtest.NewFakeBackend(),
		payloads:   map[string]string{},
		plaintexts: map[string]string{},
		used:       map[string]bool{},
	}
	r.handler = newServer(t,
		// the mounts of compose.yml
		transhim.Mount("/v1/transit-kms", "rgw-kms", plainBackend{r.kms}),
		transhim.Mount("/v1/transit-sse-s3", "rgw-sse-s3", sse),
		// the mount of the direct probes
		transhim.Mount("/v1/transit", "probe", transhimtest.NewFakeBackend(), transhim.RequireDeletionAllowed()),
		transhim.WithAuthorizer(transhim.StaticTokenAuthorizer(fixtureToken)),
	)
	return r
}

const vaultPrefix = "vault:v1:"

// translate replaces the recorded ciphertexts in a request body by the ones
// transhim handed out, including the variants the probes derive from them.
func (r *replayer) translate(body string) string {
	for rec, ours := range r.payloads {
		body = strings.ReplaceAll(body, rec, ours)
		// compat/capture.sh tampers by replacing the last four characters
		body = strings.ReplaceAll(body, rec[:len(rec)-4]+"AAAA", ours[:len(ours)-4]+"AAAA")
	}
	return body
}

type answer struct {
	status int
	header http.Header
	body   string
	top    map[string]json.RawMessage
	data   map[string]json.RawMessage
	errors []string
}

func parseAnswer(t *testing.T, status int, header http.Header, body string) *answer {
	t.Helper()
	a := &answer{status: status, header: header, body: body}
	if strings.TrimSpace(body) == "" {
		return a
	}
	if err := json.Unmarshal([]byte(body), &a.top); err != nil {
		t.Fatalf("answer is not JSON: %q", body)
	}
	if raw, ok := a.top["data"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &a.data); err != nil {
			t.Fatalf("data is not an object: %q", body)
		}
	}
	if raw, ok := a.top["errors"]; ok {
		json.Unmarshal(raw, &a.errors)
	}
	return a
}

func (a *answer) str(field string) string {
	var s string
	json.Unmarshal(a.data[field], &s)
	return s
}

// jsonType names the JSON type of a raw value.
func jsonType(raw json.RawMessage) string {
	switch strings.TrimSpace(string(raw))[0] {
	case '"':
		return "string"
	case '{':
		return "object"
	case '[':
		return "array"
	case 't', 'f':
		return "bool"
	case 'n':
		return "null"
	}
	return "number"
}

func keys(m map[string]json.RawMessage) []string {
	return slices.Sorted(maps.Keys(m))
}

// replay sends one recorded request to transhim and compares the answer with
// the recorded one.
func (r *replayer) replay(label string, rec record) {
	t := r.t
	t.Helper()
	where := fmt.Sprintf("seq %d (%s): %s %s", rec.Seq, label, rec.Request.Method, rec.Request.Path)
	want := parseAnswer(t, rec.Response.Status, rec.Response.Header, rec.Response.Body)

	// SSE-KMS keys are provisioned by the operator, who also removed one
	// behind RGW's back during the capture. Follow the recording.
	if name, ok := strings.CutPrefix(rec.Request.Path, "/v1/transit-kms/"); ok {
		name = name[strings.LastIndex(name, "/")+1:]
		if slices.Contains(want.errors, "encryption key not found") {
			r.kms.RemoveKey("rgw-kms", name)
		} else {
			r.kms.AddKey("rgw-kms", name)
		}
	}

	body := r.translate(rec.Request.Body)
	req := httptest.NewRequest(rec.Request.Method, rec.Request.Path, strings.NewReader(body))
	for name, values := range rec.Request.Header {
		for range values {
			switch name {
			case "Content-Length":
			case "X-Vault-Token":
				// redacted by the recorder; RGW sends it twice
				if label == "wrong token" {
					req.Header.Add(name, "wrong")
				} else {
					req.Header.Add(name, fixtureToken)
				}
			default:
				req.Header[name] = values
			}
		}
	}
	w := httptest.NewRecorder()
	r.handler.ServeHTTP(w, req)
	res := w.Result()
	raw, _ := io.ReadAll(res.Body)
	got := parseAnswer(t, res.StatusCode, res.Header, string(raw))

	wantStatus, wantErrors := want.status, want.errors
	if diff, ok := differences[label]; ok {
		r.used[label] = true
		if diff.status != 0 {
			wantStatus = diff.status
		}
		wantErrors = nil
		if diff.msg != "" {
			wantErrors = []string{diff.msg}
		}
		if wantStatus == want.status && slices.Equal(wantErrors, want.errors) {
			t.Errorf("%s: listed as a difference, but OpenBao answers the same", where)
		}
	}
	if got.status != wantStatus {
		t.Errorf("%s: got %d %q, want %d (OpenBao: %d %q)", where, got.status, got.body, wantStatus, want.status, want.body)
		return
	}
	if !slices.Equal(got.errors, wantErrors) {
		t.Errorf("%s: errors = %q, want %q", where, got.errors, wantErrors)
	}
	if got.status == http.StatusNoContent && got.body != "" {
		t.Errorf("%s: 204 with a body %q", where, got.body)
	}
	if got.body != "" {
		for _, h := range []string{"Content-Type", "Cache-Control"} {
			if rec := want.header.Get(h); rec != "" && want.body != "" && got.header.Get(h) != rec {
				t.Errorf("%s: %s = %q, OpenBao sends %q", where, h, got.header.Get(h), rec)
			}
		}
	}
	if got.status != http.StatusOK || want.status != http.StatusOK {
		return
	}

	// Both succeeded: the answers must have the same shape.
	if !slices.Equal(keys(got.top), keys(want.top)) {
		t.Errorf("%s: top-level fields %v, OpenBao sends %v", where, keys(got.top), keys(want.top))
	}
	for field, raw := range want.top {
		if field != "data" && got.top[field] != nil && jsonType(got.top[field]) != jsonType(raw) {
			t.Errorf("%s: %s is a %s, OpenBao sends a %s", where, field, jsonType(got.top[field]), jsonType(raw))
		}
	}
	if !otherFields[label] && !slices.Equal(keys(got.data), keys(want.data)) {
		t.Errorf("%s: data fields %v, OpenBao sends %v", where, keys(got.data), keys(want.data))
	}
	for field, raw := range want.data {
		if got.data[field] != nil && jsonType(got.data[field]) != jsonType(raw) {
			t.Errorf("%s: data.%s is a %s, OpenBao sends a %s", where, field, jsonType(got.data[field]), jsonType(raw))
		}
	}

	var in struct {
		Plaintext  string `json:"plaintext"`
		Ciphertext string `json:"ciphertext"`
	}
	json.Unmarshal([]byte(body), &in)
	if ct := got.str("ciphertext"); ct != "" {
		// datakey or encrypt: remember which ciphertext stands for which
		recCT := want.str("ciphertext")
		if !strings.HasPrefix(ct, vaultPrefix) || !strings.HasPrefix(recCT, vaultPrefix) {
			t.Fatalf("%s: ciphertext = %q, OpenBao sends %q", where, ct, recCT)
		}
		r.payloads[strings.TrimPrefix(recCT, vaultPrefix)] = strings.TrimPrefix(ct, vaultPrefix)
		plaintext := in.Plaintext
		if p := got.str("plaintext"); p != "" {
			plaintext = p
			gotKey, _ := base64.StdEncoding.DecodeString(p)
			wantKey, _ := base64.StdEncoding.DecodeString(want.str("plaintext"))
			if len(gotKey) != len(wantKey) || len(gotKey) == 0 {
				t.Errorf("%s: data key of %d bytes, OpenBao sends %d", where, len(gotKey), len(wantKey))
			}
		}
		r.plaintexts[ct] = plaintext
	} else if in.Ciphertext != "" {
		// decrypt: must return what was wrapped
		if wantPlain, ok := r.plaintexts[in.Ciphertext]; !ok || got.str("plaintext") != wantPlain {
			t.Errorf("%s: decrypt did not return the plaintext that was wrapped", where)
		}
	}
}

func readCapture(t *testing.T, path string) []record {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []record
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var rec record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		recs = append(recs, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return recs
}

// TestFixtures replays every captured exchange against transhim: all the
// requests Ceph RGW made for SSE-KMS and SSE-S3 over the life of several
// buckets, on three Ceph releases, and the direct probes of OpenBao.
func TestFixtures(t *testing.T) {
	files, err := filepath.Glob(fixtureGlob)
	if err != nil || len(files) == 0 {
		t.Fatalf("no capture files match %s (%v)", fixtureGlob, err)
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".jsonl"), func(t *testing.T) {
			r := newReplayer(t)
			label := ""
			counts := map[string]int{}
			for _, rec := range readCapture(t, file) {
				if rec.Mark != "" {
					label = rec.Mark
					if probe, ok := strings.CutPrefix(label, "probe: "); ok {
						label = probe
					}
					continue
				}
				if rec.Request == nil || rec.Response == nil {
					t.Fatalf("seq %d: incomplete exchange", rec.Seq)
				}
				r.replay(label, rec)
				switch {
				case strings.HasPrefix(rec.Request.Path, "/v1/transit-kms/"):
					counts["kms"]++
				case strings.HasPrefix(rec.Request.Path, "/v1/transit-sse-s3/"):
					counts["sse-s3"]++
				default:
					counts["probe"]++
				}
			}
			// guard against a capture or a filter that silently became empty
			if counts["kms"] < 10 || counts["sse-s3"] < 10 || counts["probe"] < 40 {
				t.Errorf("replayed %v exchanges: too few", counts)
			}
			for label := range differences {
				if !r.used[label] {
					t.Errorf("difference %q matches no probe in the capture", label)
				}
			}
			t.Logf("replayed %v exchanges", counts)
		})
	}
}
