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
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultMaxBodySize is the default limit for request bodies.
const DefaultMaxBodySize = 1 << 20

type config struct {
	mounts               []*mount
	authorizer           Authorizer
	allowUnauthenticated bool
	logger               *slog.Logger
	maxBodySize          int64
	cache                *DecryptCacheConfig
	auditHook            AuditHook
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

// WithDecryptCache enables the decrypt cache, which is off by default. It
// answers repeated decrypt requests for the same ciphertext, key name, and
// context without calling the backend. Concurrent requests of that kind share
// one backend call. Requests are still authorized, and failures are never
// cached.
//
// Since the backend is not called for every request, it cannot be the place
// where access is decided per request: do that in the Authorizer. See DecryptCacheConfig for what the TTL means for
// revocation.
func WithDecryptCache(cfg DecryptCacheConfig) Option {
	return func(c *config) error {
		if err := cfg.validate(); err != nil {
			return err
		}
		c.cache = &cfg
		return nil
	}
}

// WithAuditHook sets a function that is told about every request.
func WithAuditHook(fn AuditHook) Option {
	return func(c *config) error {
		if fn == nil {
			return errors.New("audit hook must not be nil")
		}
		c.auditHook = fn
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
	cache       *decryptCache // nil if disabled
	// decryptFlight merges concurrent decrypts of the same request into one
	// backend call. It is only used with the cache.
	decryptFlight singleflight.Group
	warmOnDatakey bool
	auditHook     AuditHook

	// deletionAllowed holds the keys whose config set deletion_allowed, for
	// mounts with RequireDeletionAllowed.
	mu              sync.Mutex
	deletionAllowed map[keyID]struct{}
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
		mounts:          c.mounts,
		authorizer:      c.authorizer,
		logger:          c.logger,
		maxBodySize:     c.maxBodySize,
		auditHook:       c.auditHook,
		deletionAllowed: map[keyID]struct{}{},
	}
	if c.cache != nil {
		s.cache = newDecryptCache(*c.cache)
		s.warmOnDatakey = c.cache.WarmOnDatakey
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

var errUnsupportedPath = notFound("unsupported path")

// parseOp maps the method and the escaped path below a mount to an operation
// and the still escaped key name.
func parseOp(method, rest string) (Op, string, error) {
	write := method == http.MethodPost || method == http.MethodPut
	for _, o := range []struct {
		prefix string
		op     Op
	}{
		{"datakey/plaintext/", OpDataKey},
		{"encrypt/", OpEncrypt},
		{"decrypt/", OpDecrypt},
	} {
		if name, ok := strings.CutPrefix(rest, o.prefix); ok {
			if !write {
				return o.op, "", methodNotAllowed("POST, PUT")
			}
			return o.op, name, nil
		}
	}
	name, ok := strings.CutPrefix(rest, "keys/")
	if !ok {
		return "", "", errUnsupportedPath
	}
	if base, ok := strings.CutSuffix(name, "/config"); ok && !strings.Contains(base, "/") {
		if !write {
			return OpKeyConfig, "", methodNotAllowed("POST, PUT")
		}
		return OpKeyConfig, base, nil
	}
	switch {
	case write:
		return OpKeyCreate, name, nil
	case method == http.MethodDelete:
		return OpKeyDelete, name, nil
	case method == http.MethodGet:
		// reading key metadata is not supported (DESIGN.md D7)
		return "", "", errUnsupportedPath
	}
	return "", "", methodNotAllowed("POST, PUT, DELETE")
}

// request is the state of one request being served.
type request struct {
	id       string
	op       Op
	mount    *mount
	keyName  string
	cacheHit bool
}

func (req *request) keyID() keyID { return keyID{req.mount.id, req.keyName} }

// result is a successful answer: 200 with data, or 204 without a body if data
// is nil.
type result struct {
	data     any
	warnings []string
}

// noContent is the answer of the key operations. It must stay without a body:
// Ceph RGW before tentacle treats a body in the answer to keys/{name}/config
// as a failure and then never deletes the key (docs/compat.md).
var noContent = &result{}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	req := &request{id: newRequestID()}
	res, err := s.serve(w, r, req)
	var status int
	switch {
	case err != nil:
		status = s.writeError(w, r, req, err)
	case res.data == nil:
		status = http.StatusNoContent
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
	default:
		status = http.StatusOK
		writeJSON(w, status, response{
			RequestID: req.id,
			Data:      res.data,
			Warnings:  res.warnings,
		})
		zeroResult(res.data)
	}
	if s.auditHook != nil {
		ev := AuditEvent{
			Time:       start,
			Op:         req.op,
			KeyName:    req.keyName,
			CacheHit:   req.cacheHit,
			Duration:   time.Since(start),
			Status:     status,
			Err:        err,
			RemoteAddr: r.RemoteAddr,
			RequestID:  req.id,
		}
		if req.mount != nil {
			ev.MountID = req.mount.id
		}
		s.auditHook(r.Context(), ev)
	}
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request, req *request) (*result, error) {
	m, rest, ok := s.route(r.URL.EscapedPath())
	if !ok {
		return nil, notFound("no handler for route")
	}
	req.mount = m
	op, escapedName, err := parseOp(r.Method, rest)
	req.op = op
	if err != nil {
		if err == errUnsupportedPath {
			// Worth a warning: it may be a client using an API transhim lacks.
			s.logger.WarnContext(r.Context(), "unsupported path",
				"request_id", req.id, "mount_id", m.id, "method", r.Method, "path", r.URL.Path)
		}
		return nil, err
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
	case OpKeyCreate:
		return s.handleKeyCreate(r.Context(), req, body)
	case OpKeyConfig:
		return s.handleKeyConfig(req, body)
	case OpKeyDelete:
		return s.handleKeyDelete(r.Context(), req)
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
	keyContext, err := decodeContext(in.Context)
	if err != nil {
		return nil, err
	}
	m := req.mount
	aad := buildAAD(m.id, req.keyName, keyContext)
	size := bits / 8
	var gen uint64
	if s.warmOnDatakey {
		gen = s.cache.generation()
	}

	var plaintext []byte
	var wk WrappedKey
	if g, ok := m.backend.(DataKeyGenerator); ok {
		plaintext, wk, err = g.GenerateDataKey(ctx, DataKeyRequest{
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
	if s.warmOnDatakey {
		s.cache.put(newCacheKey(m.id, req.keyName, keyContext, data.Ciphertext), req.keyID(), plaintext, gen)
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
	keyContext, err := decodeContext(in.Context)
	if err != nil {
		return nil, err
	}
	wk, err := m.backend.Encrypt(ctx, EncryptRequest{
		MountID:   m.id,
		KeyName:   req.keyName,
		Plaintext: plaintext,
		AAD:       buildAAD(m.id, req.keyName, keyContext),
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
	keyContext, err := decodeContext(in.Context)
	if err != nil {
		return nil, err
	}
	wk, err := decodeEnvelope(*in.Ciphertext)
	if err != nil {
		return nil, err
	}
	m := req.mount

	dreq := DecryptRequest{
		MountID: m.id,
		KeyName: req.keyName,
		Wrapped: wk,
		AAD:     buildAAD(m.id, req.keyName, keyContext),
	}
	if s.cache == nil {
		plaintext, err := m.backend.Decrypt(ctx, dreq)
		if err != nil {
			return nil, err
		}
		data := &decryptData{Plaintext: base64.StdEncoding.EncodeToString(plaintext)}
		clear(plaintext)
		return &result{data: data}, nil
	}

	ck := newCacheKey(m.id, req.keyName, keyContext, *in.Ciphertext)
	if plaintext, ok := s.cache.get(ck); ok {
		req.cacheHit = true
		data := &decryptData{Plaintext: base64.StdEncoding.EncodeToString(plaintext)}
		clear(plaintext)
		return &result{data: data}, nil
	}
	// RGW sends the same decrypt many times at once (the parts of a multipart
	// upload). With a slow KMS they would all miss the cache and queue up
	// behind each other, so only the first one calls the backend and the
	// others wait for its result.
	//
	// The call must not die with the request that happened to start it, so
	// it does not inherit that request's cancellation. Every request that
	// gets here was authorized on its own.
	encoded, err, _ := s.decryptFlight.Do(string(ck[:]), func() (any, error) {
		gen := s.cache.generation()
		plaintext, err := m.backend.Decrypt(context.WithoutCancel(ctx), dreq)
		if err != nil {
			return nil, err
		}
		defer clear(plaintext)
		s.cache.put(ck, req.keyID(), plaintext, gen)
		// shared by all waiting requests, hence an immutable string
		return base64.StdEncoding.EncodeToString(plaintext), nil
	})
	if err != nil {
		return nil, err
	}
	return &result{data: &decryptData{Plaintext: encoded.(string)}}, nil
}

// unmanaged answers a key operation on a mount whose backend has no
// KeyLifecycle.
func unmanaged(m *mount) (*result, error) {
	if m.rejectUnmanagedKeyOps {
		return nil, methodNotAllowed("")
	}
	return noContent, nil
}

type keyCreateBody struct {
	Exportable bool `json:"exportable"`
}

func (s *Server) handleKeyCreate(ctx context.Context, req *request, body []byte) (*result, error) {
	var in keyCreateBody
	if err := decodeBody(body, &in); err != nil {
		return nil, err
	}
	if in.Exportable {
		return nil, badRequest("exportable keys are not supported")
	}
	m := req.mount
	if m.lifecycle == nil {
		return unmanaged(m)
	}
	if err := m.lifecycle.CreateKey(ctx, m.id, req.keyName); err != nil {
		return nil, err
	}
	return noContent, nil
}

type keyConfigBody struct {
	DeletionAllowed *bool `json:"deletion_allowed"`
}

func (s *Server) handleKeyConfig(req *request, body []byte) (*result, error) {
	var in keyConfigBody
	if err := decodeBody(body, &in); err != nil {
		return nil, err
	}
	m := req.mount
	if m.lifecycle == nil && m.rejectUnmanagedKeyOps {
		return unmanaged(m)
	}
	// The flag is only kept where it is going to be checked.
	if in.DeletionAllowed != nil && m.requireDeletionAllowed {
		s.mu.Lock()
		if *in.DeletionAllowed {
			s.deletionAllowed[req.keyID()] = struct{}{}
		} else {
			delete(s.deletionAllowed, req.keyID())
		}
		s.mu.Unlock()
	}
	return noContent, nil
}

func (s *Server) handleKeyDelete(ctx context.Context, req *request) (*result, error) {
	m := req.mount
	if m.lifecycle == nil && m.rejectUnmanagedKeyOps {
		return unmanaged(m)
	}
	if m.requireDeletionAllowed {
		s.mu.Lock()
		_, allowed := s.deletionAllowed[req.keyID()]
		s.mu.Unlock()
		if !allowed {
			return nil, badRequest("deletion is not allowed for this key")
		}
	}
	var err error
	if m.lifecycle != nil {
		err = m.lifecycle.DeleteKey(ctx, m.id, req.keyName)
	}
	// Also when the backend reports a failure: the key may be gone all the
	// same (a timeout after the delete took effect), and then its cached
	// plaintexts must not outlive it.
	if s.cache != nil {
		s.cache.invalidate(req.keyID())
	}
	if err != nil {
		return nil, err
	}
	if m.requireDeletionAllowed {
		s.mu.Lock()
		delete(s.deletionAllowed, req.keyID())
		s.mu.Unlock()
	}
	return noContent, nil
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

// writeError answers with a Vault-style error and returns the status. Details
// of the error go to the log only.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, req *request, err error) int {
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
	if re, ok := errors.AsType[*requestError](err); ok && re.allow != "" {
		w.Header().Set("Allow", re.allow)
	}
	writeJSON(w, status, errorBody{Errors: []string{msg}})
	return status
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
