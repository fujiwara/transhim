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
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultMaxBodySize is the default limit for request bodies.
const DefaultMaxBodySize = 1 << 20

// DefaultBodyReadTimeout is the default limit for the time a client may take
// to send its request body.
const DefaultBodyReadTimeout = 10 * time.Second

type config struct {
	mounts               []*mount
	authorizer           Authorizer
	allowUnauthenticated bool
	logger               *slog.Logger
	maxBodySize          int64
	bodyReadTimeout      time.Duration
	cache                *DecryptCacheConfig
	auditHook            AuditHook
	tokenLookup          bool
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

// WithBodyReadTimeout sets how long a client may take to send its request
// body. The default is DefaultBodyReadTimeout. Bodies are read before the
// request is authorized, so this is what stops a client that is not let in
// from keeping a connection busy by sending slowly.
//
// The limit is a read deadline on the connection, which the server lifts
// again once it has the body: a deadline set by http.Server.ReadTimeout ends
// there as well, and does not run into the time the backend takes. It has no
// effect behind an http.ResponseWriter that cannot set deadlines.
func WithBodyReadTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return errors.New("body read timeout must be positive")
		}
		c.bodyReadTimeout = d
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

// tokenLookupPath is where Vault serves a token's own metadata.
const tokenLookupPath = "/v1/auth/token/lookup-self"

// WithTokenLookup makes the server answer GET /v1/auth/token/lookup-self, the
// one path it can serve outside its mounts. Some clients read it at startup
// to check their token, and do not start without it (docs/compat.md).
//
// The request is authorized with the operation OpTokenLookup and no mount ID
// and key name. The answer describes a token that never expires and cannot be
// renewed, whatever the token is: the server knows nothing about it but the
// authorizer's verdict.
func WithTokenLookup() Option {
	return func(c *config) error {
		c.tokenLookup = true
		return nil
	}
}

// Server is an http.Handler that serves the Vault Transit API for its mounts.
// Outside of them it serves nothing, or with WithTokenLookup one path.
type Server struct {
	mounts          []*mount // longest prefix first
	authorizer      Authorizer
	logger          *slog.Logger
	maxBodySize     int64
	bodyReadTimeout time.Duration
	cache           *decryptCache // nil if disabled
	// decryptFlight merges concurrent decrypts of the same request into one
	// backend call. It is only used with the cache.
	decryptFlight singleflight.Group
	warmOnDatakey bool
	auditHook     AuditHook
	tokenLookup   bool

	// deletionAllowed holds the keys whose config set deletion_allowed, for
	// mounts with RequireDeletionAllowed.
	mu              sync.Mutex
	deletionAllowed map[keyID]struct{}
}

// NewServer builds a Server. It needs at least one Mount, and either
// WithAuthorizer or an explicit AllowUnauthenticated.
func NewServer(opts ...Option) (*Server, error) {
	c := &config{maxBodySize: DefaultMaxBodySize, bodyReadTimeout: DefaultBodyReadTimeout}
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
		bodyReadTimeout: c.bodyReadTimeout,
		auditHook:       c.auditHook,
		tokenLookup:     c.tokenLookup,
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
	case name == "":
		// not a key: listing keys is not supported
		return "", "", errUnsupportedPath
	case method == http.MethodGet:
		return OpKeyRead, name, nil
	}
	return "", "", methodNotAllowed("GET, POST, PUT, DELETE")
}

// request is the state of one request being served.
type request struct {
	// context is the decoded context of the request body, or nil.
	context  []byte
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
			Context:    req.context,
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
	if s.tokenLookup && r.URL.Path == tokenLookupPath {
		return s.handleTokenLookup(r, req)
	}
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

	// The body is read before the request is authorized, because the
	// authorizer is told the context. A body that cannot be used is reported
	// only after that: a client that is not allowed in gets a 403 whatever it
	// sent.
	body, bodyErr := s.readBody(w, r)
	if bodyErr == nil {
		req.context, bodyErr = requestContext(op, body)
	}
	if err := s.authorize(r, req); err != nil {
		return nil, err
	}
	if bodyErr != nil {
		return nil, bodyErr
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
	case OpKeyRead:
		return s.handleKeyRead(r.Context(), req)
	}
	return nil, fmt.Errorf("unhandled operation %q", op)
}

// authorize asks the authorizer, if there is one, about the request.
func (s *Server) authorize(r *http.Request, req *request) error {
	if s.authorizer == nil {
		return nil
	}
	ar := AuthRequest{
		Op:         req.op,
		KeyName:    req.keyName,
		Context:    bytes.Clone(req.context),
		Token:      r.Header.Get("X-Vault-Token"),
		Namespace:  r.Header.Get("X-Vault-Namespace"),
		TLS:        r.TLS,
		RemoteAddr: r.RemoteAddr,
	}
	if req.mount != nil {
		ar.MountID = req.mount.id
	}
	return s.authorizer(r.Context(), ar)
}

// tokenLookupData is the "data" of the lookup-self answer: the fields of
// Vault's that say how long the token lives. Clients use them to decide
// whether to renew it; with these values they do not. The token itself and
// its accessor, which Vault also returns, are left out.
type tokenLookupData struct {
	CreationTTL int      `json:"creation_ttl"`
	ExpireTime  *string  `json:"expire_time"`
	Policies    []string `json:"policies"`
	Renewable   bool     `json:"renewable"`
	TTL         int      `json:"ttl"`
	Type        string   `json:"type"`
}

func (s *Server) handleTokenLookup(r *http.Request, req *request) (*result, error) {
	req.op = OpTokenLookup
	if r.Method != http.MethodGet {
		return nil, methodNotAllowed("GET")
	}
	if err := s.authorize(r, req); err != nil {
		return nil, err
	}
	return &result{data: &tokenLookupData{Policies: []string{"default"}, Type: "service"}}, nil
}

// readBody reads the whole request body, up to the size limit and within the
// time limit.
func (s *Server) readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	rc := http.NewResponseController(w)
	timed := rc.SetReadDeadline(time.Now().Add(s.bodyReadTimeout)) == nil
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxBodySize))
	if err != nil {
		// The rest of the body is not wanted. Without this, net/http reads
		// on to keep the connection for the next request; the deadline,
		// which stays in place, bounds whatever it still reads.
		w.Header().Set("Connection", "close")
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return nil, &requestError{status: http.StatusRequestEntityTooLarge, msg: "request body too large"}
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, &requestError{status: http.StatusRequestTimeout, msg: "request body not received in time"}
		}
		return nil, badRequest("failed to read request body")
	}
	if timed {
		// The deadline must not outlive the read: net/http keeps reading
		// from the connection while the handler runs, and a deadline that
		// passes then cancels the request's context in the middle of a
		// backend call.
		rc.SetReadDeadline(time.Time{})
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

// requestContext returns the decoded "context" field of a datakey, encrypt, or
// decrypt request. The other operations have none. An absent and an empty
// context are the same: nil.
//
// This is the one place where the context is taken from the body, so that the
// authorizer and the audit hook see exactly what is bound into the ciphertext.
func requestContext(op Op, body []byte) ([]byte, error) {
	if op != OpDataKey && op != OpEncrypt && op != OpDecrypt {
		return nil, nil
	}
	var in struct {
		Context string `json:"context"`
	}
	if err := decodeBody(body, &in); err != nil {
		return nil, err
	}
	if in.Context == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(in.Context)
	if err != nil {
		return nil, badRequest("failed to base64-decode context")
	}
	if len(b) == 0 {
		// "\r\n" is valid base64 for nothing: the decoder skips line ends
		return nil, nil
	}
	return b, nil
}

type dataKeyBody struct {
	Bits *int `json:"bits"`
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
	keyContext := req.context
	m := req.mount
	aad := buildAAD(m.id, req.keyName, keyContext)
	size := bits / 8
	var gen uint64
	if s.warmOnDatakey {
		gen = s.cache.generation()
	}

	var plaintext []byte
	var wk WrappedKey
	var err error
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
	Plaintext      *string `json:"plaintext"`
	KeyVersion     int     `json:"key_version"`
	AssociatedData string  `json:"associated_data"`
}

// errAssociatedData refuses Vault's associated_data. A client that sends it
// relies on it being bound into the ciphertext, like the context; ignoring
// it would drop that binding without anyone noticing.
var errAssociatedData = badRequest("associated_data is not supported")

type encryptData struct {
	Ciphertext string `json:"ciphertext"`
	KeyVersion int    `json:"key_version"`
}

func (s *Server) handleEncrypt(ctx context.Context, req *request, body []byte) (*result, error) {
	var in encryptBody
	if err := decodeBody(body, &in); err != nil {
		return nil, err
	}
	if in.AssociatedData != "" {
		return nil, errAssociatedData
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
	keyContext := req.context
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
	Ciphertext     *string `json:"ciphertext"`
	AssociatedData string  `json:"associated_data"`
}

type decryptData struct {
	Plaintext string `json:"plaintext"`
}

func (s *Server) handleDecrypt(ctx context.Context, req *request, body []byte) (*result, error) {
	var in decryptBody
	if err := decodeBody(body, &in); err != nil {
		return nil, err
	}
	if in.AssociatedData != "" {
		return nil, errAssociatedData
	}
	if in.Ciphertext == nil {
		return nil, badRequest("missing ciphertext to decrypt")
	}
	keyContext := req.context
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

// errKeyAbsent answers the read of a key that does not exist the way Vault
// does: 404 with an empty list of errors. Vault's clients take exactly that
// as "no such key" and anything else as a failure.
var errKeyAbsent = notFound("")

// keyReadData is the "data" of a key read: the fields Vault returns for an
// aes256-gcm96 key that is not derived, which is what a transhim key looks
// like from outside. Only latest_version, keys, and deletion_allowed vary.
type keyReadData struct {
	AllowPlaintextBackup bool `json:"allow_plaintext_backup"`
	AutoRotatePeriod     int  `json:"auto_rotate_period"`
	DeletionAllowed      bool `json:"deletion_allowed"`
	Derived              bool `json:"derived"`
	Exportable           bool `json:"exportable"`
	ImportedKey          bool `json:"imported_key"`
	// Keys maps a version to its creation time in Unix seconds. Only the
	// latest version is listed.
	Keys                 map[string]int64 `json:"keys"`
	LatestVersion        int              `json:"latest_version"`
	MinAvailableVersion  int              `json:"min_available_version"`
	MinDecryptionVersion int              `json:"min_decryption_version"`
	MinEncryptionVersion int              `json:"min_encryption_version"`
	Name                 string           `json:"name"`
	SoftDeleted          bool             `json:"soft_deleted"`
	SupportsDecryption   bool             `json:"supports_decryption"`
	// SupportsDerivation is true as it is in Vault for this key type; here it
	// says that a context is accepted.
	SupportsDerivation bool   `json:"supports_derivation"`
	SupportsEncryption bool   `json:"supports_encryption"`
	SupportsSigning    bool   `json:"supports_signing"`
	Type               string `json:"type"`
}

func (s *Server) handleKeyRead(ctx context.Context, req *request) (*result, error) {
	m := req.mount
	// Without a KeyDescriber the server cannot tell whether the key exists,
	// and says that it does.
	var info KeyInfo
	if m.describer != nil {
		var err error
		info, err = m.describer.DescribeKey(ctx, m.id, req.keyName)
		if errors.Is(err, ErrKeyNotFound) {
			return nil, errKeyAbsent
		}
		if err != nil {
			return nil, err
		}
	}
	version := max(info.Version, 1)
	var created int64
	if !info.CreatedAt.IsZero() {
		created = info.CreatedAt.Unix()
	}
	s.mu.Lock()
	_, deletionAllowed := s.deletionAllowed[req.keyID()]
	s.mu.Unlock()
	return &result{data: &keyReadData{
		DeletionAllowed:      deletionAllowed,
		Keys:                 map[string]int64{strconv.Itoa(version): created},
		LatestVersion:        version,
		MinDecryptionVersion: 1,
		Name:                 req.keyName,
		SupportsDecryption:   true,
		SupportsDerivation:   true,
		SupportsEncryption:   true,
		Type:                 "aes256-gcm96",
	}}, nil
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
	body := errorBody{Errors: []string{}}
	if msg != "" {
		body.Errors = append(body.Errors, msg)
	}
	writeJSON(w, status, body)
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
