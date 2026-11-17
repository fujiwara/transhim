package transhim

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// DefaultMaxBodySize is the default limit for request bodies.
const DefaultMaxBodySize = 1 << 20

type config struct {
	mounts               []*mount
	authorizer           Authorizer
	allowUnauthenticated bool
	logger               *slog.Logger
	maxBodySize          int64
}

// Option configures a Server.
type Option func(*config) error

// WithAuthorizer sets the function that authorizes every request.
func WithAuthorizer(fn Authorizer) Option {
	return func(c *config) error {
		if fn == nil {
			return errors.New("authorizer must not be nil")
		}
		c.authorizer = fn
		return nil
	}
}

// AllowUnauthenticated lets NewServer build a server without an Authorizer.
// Such a server hands data keys to anyone who can reach it.
func AllowUnauthenticated() Option {
	return func(c *config) error {
		c.allowUnauthenticated = true
		return nil
	}
}

// WithLogger sets the logger. The default is slog.Default(). The server never
// logs plaintexts, ciphertexts, tokens, or request bodies.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) error {
		if l == nil {
			return errors.New("logger must not be nil")
		}
		c.logger = l
		return nil
	}
}

// WithMaxBodySize sets the largest accepted request body in bytes. The default
// is DefaultMaxBodySize.
func WithMaxBodySize(n int64) Option {
	return func(c *config) error {
		if n <= 0 {
			return errors.New("max body size must be positive")
		}
		c.maxBodySize = n
		return nil
	}
}

// Server is an http.Handler that serves the Vault Transit API for its mounts.
// It serves nothing outside of them.
type Server struct {
	mounts      []*mount // longest prefix first
	authorizer  Authorizer
	logger      *slog.Logger
	maxBodySize int64
}

// NewServer builds a Server. It needs at least one Mount, and either
// WithAuthorizer or an explicit AllowUnauthenticated.
func NewServer(opts ...Option) (*Server, error) {
	c := &config{maxBodySize: DefaultMaxBodySize}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, fmt.Errorf("transhim: %w", err)
		}
	}
	if len(c.mounts) == 0 {
		return nil, errors.New("transhim: at least one Mount is required")
	}
	if c.authorizer == nil && !c.allowUnauthenticated {
		return nil, errors.New("transhim: WithAuthorizer is required (or AllowUnauthenticated to serve without authorization)")
	}
	if c.authorizer != nil && c.allowUnauthenticated {
		return nil, errors.New("transhim: WithAuthorizer and AllowUnauthenticated are mutually exclusive")
	}
	if c.logger == nil {
		c.logger = slog.Default()
	}
	s := &Server{
		mounts:      c.mounts,
		authorizer:  c.authorizer,
		logger:      c.logger,
		maxBodySize: c.maxBodySize,
	}
	// A prefix may be nested in another one: the longest match wins.
	sort.SliceStable(s.mounts, func(i, j int) bool {
		return len(s.mounts[i].prefix) > len(s.mounts[j].prefix)
	})
	return s, nil
}

// route finds the mount for an escaped request path and returns the escaped
// remainder after the prefix.
func (s *Server) route(escapedPath string) (*mount, string, bool) {
	for _, m := range s.mounts {
		if rest, ok := strings.CutPrefix(escapedPath, m.prefix+"/"); ok {
			return m, rest, true
		}
	}
	return nil, "", false
}

// parseOp splits the escaped path below a mount into the operation and the
// still escaped key name.
func parseOp(rest string) (Op, string, bool) {
	for _, o := range []struct {
		prefix string
		op     Op
	}{
		{"datakey/plaintext/", OpDataKey},
		{"encrypt/", OpEncrypt},
		{"decrypt/", OpDecrypt},
	} {
		if name, ok := strings.CutPrefix(rest, o.prefix); ok {
			return o.op, name, true
		}
	}
	return "", "", false
}

// request is the state of one request being served.
type request struct {
	id      string
	op      Op
	mount   *mount
	keyName string
}

// result is a successful answer.
type result struct {
	data     any
	warnings []string
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req := &request{id: newRequestID()}
	res, err := s.serve(w, r, req)
	if err != nil {
		s.writeError(w, r, req, err)
		return
	}
	writeJSON(w, http.StatusOK, response{
		RequestID: req.id,
		Data:      res.data,
		Warnings:  res.warnings,
	})
	zeroResult(res.data)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request, req *request) (*result, error) {
	m, rest, ok := s.route(r.URL.EscapedPath())
	if !ok {
		return nil, &requestError{status: http.StatusNotFound, msg: "no handler for route"}
	}
	req.mount = m
	op, escapedName, ok := parseOp(rest)
	if !ok {
		// Worth a warning: it may be a client using an API transhim lacks.
		s.logger.WarnContext(r.Context(), "unsupported path",
			"request_id", req.id, "mount_id", m.id, "method", r.Method, "path", r.URL.Path)
		return nil, &requestError{status: http.StatusNotFound, msg: "unsupported path"}
	}
	req.op = op
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		w.Header().Set("Allow", "POST, PUT")
		return nil, &requestError{status: http.StatusMethodNotAllowed, msg: "unsupported operation"}
	}
	name, err := url.PathUnescape(escapedName)
	if err != nil {
		return nil, badRequest("invalid key name")
	}
	if err := validateKeyName(name); err != nil {
		return nil, badRequest("invalid key name: " + err.Error())
	}
	req.keyName = name

	if s.authorizer != nil {
		err := s.authorizer(r.Context(), AuthRequest{
			Op:         op,
			MountID:    m.id,
			KeyName:    name,
			Token:      r.Header.Get("X-Vault-Token"),
			Namespace:  r.Header.Get("X-Vault-Namespace"),
			TLS:        r.TLS,
			RemoteAddr: r.RemoteAddr,
		})
		if err != nil {
			return nil, err
		}
	}

	body, err := s.readBody(w, r)
	if err != nil {
		return nil, err
	}
	switch op {
	case OpDataKey:
		return s.handleDataKey(r.Context(), req, body)
	case OpEncrypt:
		return s.handleEncrypt(r.Context(), req, body)
	case OpDecrypt:
		return s.handleDecrypt(r.Context(), req, body)
	}
	return nil, fmt.Errorf("unhandled operation %q", op)
}

// readBody reads the whole request body, up to the size limit.
func (s *Server) readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxBodySize))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return nil, &requestError{status: http.StatusRequestEntityTooLarge, msg: "request body too large"}
		}
		return nil, badRequest("failed to read request body")
	}
	return body, nil
}

// decodeBody parses a request body as JSON whatever its Content-Type is (RGW
// sends none). An empty body is an empty object. Unknown fields are ignored.
func decodeBody(body []byte, v any) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, v); err != nil {
		// no detail: the decoder's messages can quote the input
		return badRequest("failed to decode JSON input")
	}
	return nil
}

// decodeContext decodes the base64 "context" field. An absent and an empty
// context are the same.
func decodeContext(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, badRequest("failed to base64-decode context")
	}
	return b, nil
}

type dataKeyBody struct {
	Context string `json:"context"`
	Bits    *int   `json:"bits"`
}

type dataKeyData struct {
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
	KeyVersion int    `json:"key_version"`
}

func (s *Server) handleDataKey(ctx context.Context, req *request, body []byte) (*result, error) {
	var in dataKeyBody
	if err := decodeBody(body, &in); err != nil {
		return nil, err
	}
	bits := 256
	if in.Bits != nil {
		bits = *in.Bits
	}
	if bits != 128 && bits != 256 && bits != 512 {
		return nil, badRequest("invalid bit length")
	}
	context, err := decodeContext(in.Context)
	if err != nil {
		return nil, err
	}
	m := req.mount
	aad := buildAAD(m.id, req.keyName, context)
	size := bits / 8

	var plaintext []byte
	var wk WrappedKey
	if gen, ok := m.backend.(DataKeyGenerator); ok {
		plaintext, wk, err = gen.GenerateDataKey(ctx, DataKeyRequest{
			MountID: m.id, KeyName: req.keyName, Bytes: size, AAD: aad,
		})
		if err == nil && len(plaintext) != size {
			clear(plaintext)
			err = fmt.Errorf("backend generated a data key of %d bytes, want %d", len(plaintext), size)
		}
	} else {
		plaintext = make([]byte, size)
		rand.Read(plaintext) // never fails
		wk, err = m.backend.Encrypt(ctx, EncryptRequest{
			MountID: m.id, KeyName: req.keyName, Plaintext: plaintext, AAD: aad,
		})
	}
	if err != nil {
		clear(plaintext)
		return nil, err
	}
	data := &dataKeyData{
		Plaintext:  base64.StdEncoding.EncodeToString(plaintext),
		Ciphertext: encodeEnvelope(wk),
		KeyVersion: keyVersion(wk),
	}
	clear(plaintext)
	return &result{data: data}, nil
}

type encryptBody struct {
	Plaintext  *string `json:"plaintext"`
	Context    string  `json:"context"`
	KeyVersion int     `json:"key_version"`
}

type encryptData struct {
	Ciphertext string `json:"ciphertext"`
	KeyVersion int    `json:"key_version"`
}

func (s *Server) handleEncrypt(ctx context.Context, req *request, body []byte) (*result, error) {
	var in encryptBody
	if err := decodeBody(body, &in); err != nil {
		return nil, err
	}
	if in.Plaintext == nil {
		return nil, badRequest("missing plaintext to encrypt")
	}
	m := req.mount
	if base64.StdEncoding.DecodedLen(len(*in.Plaintext)) > m.maxPlaintextSize+2 {
		// cheap check before decoding; the exact one follows
		return nil, badRequest("plaintext too large")
	}
	plaintext, err := base64.StdEncoding.DecodeString(*in.Plaintext)
	if err != nil {
		return nil, badRequest("failed to base64-decode plaintext")
	}
	defer clear(plaintext)
	if len(plaintext) > m.maxPlaintextSize {
		return nil, badRequest("plaintext too large")
	}
	context, err := decodeContext(in.Context)
	if err != nil {
		return nil, err
	}
	wk, err := m.backend.Encrypt(ctx, EncryptRequest{
		MountID:   m.id,
		KeyName:   req.keyName,
		Plaintext: plaintext,
		AAD:       buildAAD(m.id, req.keyName, context),
	})
	if err != nil {
		return nil, err
	}
	res := &result{data: &encryptData{Ciphertext: encodeEnvelope(wk), KeyVersion: keyVersion(wk)}}
	if in.KeyVersion != 0 {
		res.warnings = []string{"key_version is not supported and was ignored"}
	}
	return res, nil
}

type decryptBody struct {
	Ciphertext *string `json:"ciphertext"`
	Context    string  `json:"context"`
}

type decryptData struct {
	Plaintext string `json:"plaintext"`
}

func (s *Server) handleDecrypt(ctx context.Context, req *request, body []byte) (*result, error) {
	var in decryptBody
	if err := decodeBody(body, &in); err != nil {
		return nil, err
	}
	if in.Ciphertext == nil {
		return nil, badRequest("missing ciphertext to decrypt")
	}
	context, err := decodeContext(in.Context)
	if err != nil {
		return nil, err
	}
	wk, err := decodeEnvelope(*in.Ciphertext)
	if err != nil {
		return nil, err
	}
	m := req.mount
	plaintext, err := m.backend.Decrypt(ctx, DecryptRequest{
		MountID: m.id,
		KeyName: req.keyName,
		Wrapped: wk,
		AAD:     buildAAD(m.id, req.keyName, context),
	})
	if err != nil {
		return nil, err
	}
	data := &decryptData{Plaintext: base64.StdEncoding.EncodeToString(plaintext)}
	clear(plaintext)
	return &result{data: data}, nil
}

// response is Vault's response envelope. Clients only need "data"; the other
// fields are there, with zero values, because Vault always sends them.
type response struct {
	RequestID     string   `json:"request_id"`
	LeaseID       string   `json:"lease_id"`
	Renewable     bool     `json:"renewable"`
	LeaseDuration int      `json:"lease_duration"`
	Data          any      `json:"data"`
	WrapInfo      any      `json:"wrap_info"`
	Warnings      []string `json:"warnings"`
	Auth          any      `json:"auth"`
}

type errorBody struct {
	Errors []string `json:"errors"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		// cannot happen with the types used here
		status, b = http.StatusInternalServerError, []byte(`{"errors":["internal error"]}`)
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(append(b, '\n'))
	clear(b)
}

// writeError answers with a Vault-style error. Details of the error go to the
// log only.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, req *request, err error) {
	status, msg := errorResponse(err)
	level := slog.LevelDebug
	if status >= 500 {
		level = slog.LevelError
	}
	attrs := []any{"request_id", req.id, "status", status, "error", err.Error(), "remote_addr", r.RemoteAddr}
	if req.mount != nil {
		attrs = append(attrs, "mount_id", req.mount.id)
	}
	if req.op != "" {
		attrs = append(attrs, "op", string(req.op))
	}
	if req.keyName != "" {
		attrs = append(attrs, "key_name", req.keyName)
	}
	s.logger.Log(r.Context(), level, "request failed", attrs...)
	writeJSON(w, status, errorBody{Errors: []string{msg}})
}

// zeroResult clears the base64 plaintext of a response after it was written.
// This is best effort: Go strings are immutable, so only the reference is
// dropped, and copies made by encoding/json are cleared in writeJSON.
func zeroResult(data any) {
	switch d := data.(type) {
	case *dataKeyData:
		d.Plaintext = ""
	case *decryptData:
		d.Plaintext = ""
	}
}

// newRequestID returns a random UUID (version 4).
func newRequestID() string {
	var b [16]byte
	rand.Read(b[:]) // never fails
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
