// Package sakurakms is an example transhim.Backend for SAKURA Cloud KMS.
//
// It wraps and unwraps with a KMS key per key name, using the KMS encrypt and
// decrypt calls. It does not create or delete KMS keys: they are provisioned
// by the operator. For per-bucket keys (Ceph RGW SSE-S3), use it as the root
// of a hierarchical.Backend.
//
// # Binding the AAD
//
// SAKURA Cloud KMS has no parameter for additional authenticated data. The
// backend therefore encrypts
//
//	0x01 || sha256(AAD) || plaintext
//
// and, after decrypting, checks that the hash is the one of the request's AAD
// before returning the plaintext. The KMS ciphertext is authenticated
// (AES-256-GCM), so the hash inside it cannot be exchanged: a ciphertext made
// for one mount, key name, and context does not decrypt for another.
//
// # On-disk contract
//
// The following are bound into every ciphertext. Changing any of them makes
// existing ciphertexts undecryptable:
//
//   - The layout above.
//   - The KMS key a key name resolves to (see WithKeys). Rotating a key in
//     KMS keeps its ID and is not affected.
//
// # Cost
//
// A KMS call typically takes seconds, and concurrent calls do not run faster.
// Every datakey, encrypt, and uncached decrypt request is one KMS call. Use
// the server's decrypt cache, and the hierarchical backend where the client
// manages keys.
package sakurakms

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	ogen "github.com/ogen-go/ogen/validate"
	v1 "github.com/sacloud/sacloud-sdk-go/api/kms/apis/v1"
	"github.com/sacloud/sacloud-sdk-go/common/saclient"

	"github.com/fujiwara/transhim"
)

const (
	// formatVersion is the first byte of everything the backend encrypts.
	formatVersion = 0x01
	headerSize    = 1 + sha256.Size

	// MaxPlaintextSize is the largest plaintext the backend wraps, for use
	// with transhim.WithMaxPlaintextSize. KMS decrypts ciphertexts of up to
	// 3072 base64 characters. How much plaintext fits into that depends on
	// what KMS adds and on whether it encrypts the plaintext's base64 form
	// (sakumock does); 1024 bytes fit either way, and data keys and
	// intermediate keys are 64 bytes at most.
	MaxPlaintextSize = 1024

	// maxCiphertextSize is the largest ciphertext KMS accepts for decryption:
	// 3072 base64 characters.
	maxCiphertextSize = 3072 / 4 * 3
)

// Client is the part of the KMS key API (kms.KeyAPI of sacloud-sdk-go) the
// backend uses.
type Client interface {
	Encrypt(ctx context.Context, id string, plain []byte, algo v1.EncryptionRequestAlgo) (string, error)
	Decrypt(ctx context.Context, id, cipher string) ([]byte, error)
}

// Backend is a transhim.Backend on SAKURA Cloud KMS.
type Backend struct {
	client Client
	keyID  func(mountID, keyName string) (string, bool)
}

var _ transhim.Backend = (*Backend)(nil)

// Option configures a Backend.
type Option func(*Backend)

// WithKeys sets the keys clients can use: a map from key name to the resource
// ID of a KMS key. Any other key name is answered as not found.
//
// This decides which KMS keys a client can reach by naming them. Ceph RGW
// passes the key ID of an S3 request on without checking it.
func WithKeys(keys map[string]string) Option {
	return WithKeyID(func(_, keyName string) (string, bool) {
		id, ok := keys[keyName]
		return id, ok
	})
}

// WithKeyID sets how a key name is turned into the resource ID of a KMS key.
// The function returns false for names that must not be used.
func WithKeyID(fn func(mountID, keyName string) (id string, ok bool)) Option {
	return func(b *Backend) { b.keyID = fn }
}

// New returns a Backend that uses client. Without WithKeys or WithKeyID, the
// key name itself is the resource ID: clients can then use every key the
// server's API key can, so do not serve an SSE-KMS mount that way.
func New(client Client, opts ...Option) *Backend {
	b := &Backend{
		client: client,
		keyID:  func(_, keyName string) (string, bool) { return keyName, true },
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// resolve returns the KMS resource ID for a key name. Resource IDs are
// decimal numbers; anything else cannot be a key.
func (b *Backend) resolve(mountID, keyName string) (string, error) {
	id, ok := b.keyID(mountID, keyName)
	if !ok || id == "" {
		return "", fmt.Errorf("%w: %s", transhim.ErrKeyNotFound, keyName)
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("%w: %s", transhim.ErrKeyNotFound, keyName)
		}
	}
	return id, nil
}

// Encrypt implements transhim.Backend.
func (b *Backend) Encrypt(ctx context.Context, req transhim.EncryptRequest) (transhim.WrappedKey, error) {
	id, err := b.resolve(req.MountID, req.KeyName)
	if err != nil {
		return transhim.WrappedKey{}, err
	}
	if len(req.Plaintext) > MaxPlaintextSize {
		return transhim.WrappedKey{}, fmt.Errorf("%w: plaintext of %d bytes, the limit is %d", transhim.ErrInvalidRequest, len(req.Plaintext), MaxPlaintextSize)
	}
	sum := sha256.Sum256(req.AAD)
	payload := make([]byte, 0, headerSize+len(req.Plaintext))
	payload = append(payload, formatVersion)
	payload = append(payload, sum[:]...)
	payload = append(payload, req.Plaintext...)
	defer clear(payload)

	cipher, err := b.client.Encrypt(ctx, id, payload, v1.EncryptionRequestAlgoAes256Gcm)
	if err != nil {
		return transhim.WrappedKey{}, mapError("encrypt", err, transhim.ErrInvalidRequest)
	}
	// KMS returns base64; the envelope encodes it again, so store the bytes.
	blob, err := base64.StdEncoding.DecodeString(cipher)
	if err != nil {
		return transhim.WrappedKey{}, fmt.Errorf("kms encrypt: ciphertext is not base64: %w", err)
	}
	// KeyRef is informational: Decrypt does not rely on it, because a client
	// can change it.
	return transhim.WrappedKey{KeyRef: id, Version: 1, Blob: blob}, nil
}

// Decrypt implements transhim.Backend.
func (b *Backend) Decrypt(ctx context.Context, req transhim.DecryptRequest) ([]byte, error) {
	// nothing this backend made: no need to ask KMS
	if req.Wrapped.Version != 1 || len(req.Wrapped.Blob) == 0 || len(req.Wrapped.Blob) > maxCiphertextSize {
		return nil, transhim.ErrCiphertextMismatch
	}
	// The key is the one the name resolves to, so KMS refuses a ciphertext
	// made with any other key.
	id, err := b.resolve(req.MountID, req.KeyName)
	if err != nil {
		return nil, err
	}
	payload, err := b.client.Decrypt(ctx, id, base64.StdEncoding.EncodeToString(req.Wrapped.Blob))
	if err != nil {
		return nil, mapError("decrypt", err, transhim.ErrCiphertextMismatch)
	}
	defer clear(payload)
	sum := sha256.Sum256(req.AAD)
	if len(payload) < headerSize || payload[0] != formatVersion ||
		subtle.ConstantTimeCompare(payload[1:headerSize], sum[:]) != 1 {
		// made for another mount, key name, or context, or not by this backend
		return nil, transhim.ErrCiphertextMismatch
	}
	return append([]byte(nil), payload[headerSize:]...), nil
}

// mapError turns a KMS API error into one transhim knows how to answer. The
// KMS error stays in the chain for the log and the audit trail.
//
// The KMS API does not define its error responses, so this goes by the HTTP
// status alone. badRequest is what a 400 means for the operation: KMS answers
// it for a ciphertext it cannot decrypt, and for a key that is not active.
func mapError(op string, err error, badRequest error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("kms %s: %w", op, err)
	}
	wrap := func(kind error) error {
		return fmt.Errorf("%w: kms %s: %w", kind, op, err)
	}
	status := 0
	if u, ok := errors.AsType[*ogen.UnexpectedStatusCodeError](err); ok {
		status = u.StatusCode
	} else if saclient.IsNotFoundError(err) {
		status = http.StatusNotFound
	}
	switch {
	case status == http.StatusNotFound:
		return wrap(transhim.ErrKeyNotFound)
	case status == http.StatusBadRequest || status == http.StatusUnprocessableEntity:
		return wrap(badRequest)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return wrap(transhim.ErrPermissionDenied)
	case status == 0, status == http.StatusTooManyRequests, status >= 500:
		// no answer, throttled, or failing: worth retrying
		return &transhim.UpstreamError{Err: fmt.Errorf("kms %s: %w", op, err), Retryable: true}
	}
	return &transhim.UpstreamError{Err: fmt.Errorf("kms %s: %w", op, err)}
}
