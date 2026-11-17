package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func readRecords(t *testing.T, buf *bytes.Buffer) []Record {
	t.Helper()
	var recs []Record
	sc := bufio.NewScanner(buf)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("bad record %q: %v", sc.Text(), err)
		}
		recs = append(recs, r)
	}
	return recs
}

func TestRecorder(t *testing.T) {
	var gotPath, gotToken, gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		gotToken = r.Header.Get("X-Vault-Token")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"errors":["nope"]}`)
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	proxy := httptest.NewServer(newRecorder(u, &buf))
	defer proxy.Close()

	// marker: not forwarded
	resp, err := http.Post(proxy.URL+"/__mark?label=put+object", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("mark status = %d", resp.StatusCode)
	}
	if gotPath != "" {
		t.Errorf("marker was forwarded to %q", gotPath)
	}

	// exchange: forwarded untouched, recorded with the token redacted
	const reqBody = `{"context":""}`
	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/v1/transit/datakey/plaintext/a%24b", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Vault-Token", "s3cret")
	req.Header.Add("X-Vault-Token", "s3cret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest || string(body) != `{"errors":["nope"]}` {
		t.Errorf("client saw %d %q", resp.StatusCode, body)
	}
	if gotPath != "/v1/transit/datakey/plaintext/a%24b" {
		t.Errorf("upstream path = %q", gotPath)
	}
	if gotToken != "s3cret" || gotBody != reqBody {
		t.Errorf("upstream got token %q body %q", gotToken, gotBody)
	}

	recs := readRecords(t, &buf)
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if recs[0].Seq != 1 || recs[0].Mark != "put object" || recs[0].Request != nil {
		t.Errorf("marker record = %+v", recs[0])
	}
	ex := recs[1]
	if ex.Seq != 2 || ex.Request == nil || ex.Response == nil {
		t.Fatalf("exchange record = %+v", ex)
	}
	if ex.Request.Method != http.MethodPost || ex.Request.Path != "/v1/transit/datakey/plaintext/a%24b" || ex.Request.Body != reqBody {
		t.Errorf("recorded request = %+v", ex.Request)
	}
	if got := ex.Request.Header["X-Vault-Token"]; len(got) != 2 || got[0] != "REDACTED" || got[1] != "REDACTED" {
		t.Errorf("recorded token header = %q", got)
	}
	if ex.Response.Status != http.StatusBadRequest || ex.Response.Body != `{"errors":["nope"]}` {
		t.Errorf("recorded response = %+v", ex.Response)
	}
	if _, ok := ex.Response.Header["Date"]; ok {
		t.Error("Date header should be dropped from the record")
	}
	if strings.Contains(buf.String(), "s3cret") {
		t.Error("token leaked into the capture")
	}
}

func TestEmptyKeyWrites(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/missing/config") {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"errors":["no such key"]}`)
			return
		}
		io.WriteString(w, `{"data":{"name":"k"}}`)
	}))
	defer upstream.Close()
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	rec := newRecorder(u, &buf)
	rec.emptyKeyWrites = true
	proxy := httptest.NewServer(rec)
	defer proxy.Close()

	tests := []struct {
		method, path string
		wantStatus   int
		wantBody     string
	}{
		{http.MethodPost, "/v1/transit/keys/k", http.StatusNoContent, ""},
		{http.MethodPut, "/v1/transit/keys/k", http.StatusNoContent, ""},
		{http.MethodPost, "/v1/transit/keys/k/config", http.StatusNoContent, ""},
		// errors, reads and other operations pass through untouched
		{http.MethodPost, "/v1/transit/keys/missing/config", http.StatusBadRequest, `{"errors":["no such key"]}`},
		{http.MethodGet, "/v1/transit/keys/k", http.StatusOK, `{"data":{"name":"k"}}`},
		{http.MethodPost, "/v1/transit/datakey/plaintext/k", http.StatusOK, `{"data":{"name":"k"}}`},
	}
	for _, tt := range tests {
		req, err := http.NewRequest(tt.method, proxy.URL+tt.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tt.wantStatus || string(body) != tt.wantBody {
			t.Errorf("%s %s: got %d %q, want %d %q", tt.method, tt.path, resp.StatusCode, body, tt.wantStatus, tt.wantBody)
		}
	}
	recs := readRecords(t, &buf)
	if len(recs) != len(tests) {
		t.Fatalf("got %d records, want %d", len(recs), len(tests))
	}
	for i, tt := range tests {
		if got := recs[i].Response; got.Status != tt.wantStatus || got.Body != tt.wantBody {
			t.Errorf("record %d: got %d %q, want %d %q", i, got.Status, got.Body, tt.wantStatus, tt.wantBody)
		}
	}
}
