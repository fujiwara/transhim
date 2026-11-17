// Command vaultrec is a recording reverse proxy for capturing the Vault
// Transit requests a client (Ceph RGW) really makes.
//
// It forwards everything to an upstream Vault or OpenBao and appends one JSON
// line per exchange to the output file. Requests to /__mark are not forwarded:
// their "label" query parameter is written as a marker line, so the capture
// script can annotate which client operation caused the calls that follow.
//
// With -empty-key-writes, successful writes under keys/ (create, config) are
// answered with 204 and no body instead of the upstream's 200 and key
// metadata. That is the response transhim plans to give, and Ceph RGW before
// tentacle only deletes a bucket key when the config response has no body.
// The record keeps what the client actually received.
//
// This is a development tool. Recorded bodies contain plaintext data keys, so
// point it only at a throwaway dev server.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
)

// Record is one line of the capture file: either a marker or an exchange.
type Record struct {
	Seq      int       `json:"seq"`
	Mark     string    `json:"mark,omitempty"`
	Request  *Request  `json:"request,omitempty"`
	Response *Response `json:"response,omitempty"`
}

// Request is the recorded client request.
type Request struct {
	Method string `json:"method"`
	// Path is the escaped path as sent on the wire.
	Path   string              `json:"path"`
	Query  string              `json:"query,omitempty"`
	Header map[string][]string `json:"header"`
	Body   string              `json:"body,omitempty"`
}

// Response is the recorded upstream response.
type Response struct {
	Status int                 `json:"status"`
	Header map[string][]string `json:"header"`
	Body   string              `json:"body,omitempty"`
}

// redactedHeaders carry credentials. Their values are replaced, but the number
// of values is kept: RGW is known to send some headers twice.
var redactedHeaders = map[string]bool{
	"X-Vault-Token": true,
	"Authorization": true,
}

// droppedResponseHeaders vary per run and say nothing about the API.
var droppedResponseHeaders = map[string]bool{
	"Date": true,
}

type recorder struct {
	upstream *url.URL
	client   *http.Client
	// emptyKeyWrites turns successful POST/PUT responses under keys/ into 204
	emptyKeyWrites bool

	mu  sync.Mutex
	seq int
	enc *json.Encoder
}

func newRecorder(upstream *url.URL, out io.Writer) *recorder {
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	return &recorder{
		upstream: upstream,
		// no redirects, no retries: the client must see exactly what the upstream said
		client: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		enc: enc,
	}
}

func (rec *recorder) write(r Record) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.seq++
	r.Seq = rec.seq
	if err := rec.enc.Encode(r); err != nil {
		log.Printf("write record: %v", err)
	}
}

func copyHeader(h http.Header, redact, drop map[string]bool) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, vs := range h {
		if drop[k] {
			continue
		}
		c := make([]string, len(vs))
		for i, v := range vs {
			if redact[k] {
				v = "REDACTED"
			}
			c[i] = v
		}
		out[k] = c
	}
	return out
}

func (rec *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/__mark" {
		rec.write(Record{Mark: r.URL.Query().Get("label")})
		w.WriteHeader(http.StatusNoContent)
		return
	}

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// keep the path exactly as escaped by the client
	u := *rec.upstream
	basePath := strings.TrimSuffix(rec.upstream.Path, "/")
	baseEscaped := strings.TrimSuffix(rec.upstream.EscapedPath(), "/")
	u.Path = basePath + r.URL.Path
	u.RawPath = baseEscaped + r.URL.EscapedPath()
	u.RawQuery = r.URL.RawQuery

	out, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), bytes.NewReader(reqBody))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out.Header = r.Header.Clone()

	record := Record{Request: &Request{
		Method: r.Method,
		Path:   r.URL.EscapedPath(),
		Query:  r.URL.RawQuery,
		Header: copyHeader(r.Header, redactedHeaders, nil),
		Body:   string(reqBody),
	}}

	resp, err := rec.client.Do(out)
	if err != nil {
		rec.write(record)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		rec.write(record)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	status := resp.StatusCode
	if rec.emptyKeyWrites && isKeyWrite(r) && status == http.StatusOK {
		status = http.StatusNoContent
		respBody = nil
		resp.Header.Del("Content-Length")
	}
	record.Response = &Response{
		Status: status,
		Header: copyHeader(resp.Header, nil, droppedResponseHeaders),
		Body:   string(respBody),
	}
	rec.write(record)

	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range resp.Header[k] {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(status)
	if _, err := w.Write(respBody); err != nil {
		log.Printf("write response: %v", err)
	}
}

// isKeyWrite reports whether r creates or configures a Transit key:
// POST/PUT {mount}/keys/{name} or {mount}/keys/{name}/config.
func isKeyWrite(r *http.Request) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		return false
	}
	return strings.Contains(r.URL.Path, "/keys/")
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8201", "address to listen on")
	upstream := flag.String("upstream", "http://127.0.0.1:8200", "Vault or OpenBao address")
	outPath := flag.String("out", "", "capture file to append JSON lines to (required)")
	emptyKeyWrites := flag.Bool("empty-key-writes", false, "answer successful writes under keys/ with 204 and no body")
	flag.Parse()
	if *outPath == "" {
		log.Fatal("-out is required")
	}
	u, err := url.Parse(*upstream)
	if err != nil {
		log.Fatalf("parse -upstream: %v", err)
	}
	f, err := os.OpenFile(*outPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	log.Printf("recording %s -> %s into %s", *listen, u, *outPath)
	rec := newRecorder(u, f)
	rec.emptyKeyWrites = *emptyKeyWrites
	log.Fatal(http.ListenAndServe(*listen, rec))
}
