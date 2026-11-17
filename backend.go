package transhim

import "context"

// Backend performs the actual key wrapping, typically by calling a cloud KMS.
//
// Implementations must cryptographically bind the AAD of each request: a
// ciphertext produced with one AAD must fail to decrypt with any other. The
// AAD carries the mount ID, the key name, and the client's context, so this is
// what stops a ciphertext from being decrypted under a different key name or
// context.
//
// Errors should wrap the sentinel errors of this package (ErrKeyNotFound,
// ErrCiphertextMismatch, ErrPermissionDenied, ErrUpstream) so that the server
// can answer with the right status. Any other error is answered with 500.
// Error details are logged but never sent to the client.
//
// Implementations must be safe for concurrent use.
type Backend interface {
	// Encrypt wraps req.Plaintext with the key named req.KeyName.
	Encrypt(ctx context.Context, req EncryptRequest) (WrappedKey, error)
	// Decrypt unwraps req.Wrapped. It returns ErrCiphertextMismatch if the
	// ciphertext does not verify against the key and req.AAD.
	Decrypt(ctx context.Context, req DecryptRequest) ([]byte, error)
}

// EncryptRequest is the input of Backend.Encrypt.
type EncryptRequest struct {
	// MountID identifies the mount. It is never the mount's prefix.
	MountID string
	// KeyName is the key name given by the client, as an opaque string.
	KeyName string
	// Plaintext is the data to wrap. The server zeroes it after the call, so
	// the backend must not retain it.
	Plaintext []byte
	// AAD must be cryptographically bound to the ciphertext.
	AAD []byte
}

// DecryptRequest is the input of Backend.Decrypt.
type DecryptRequest struct {
	// MountID identifies the mount. It is never the mount's prefix.
	MountID string
	// KeyName is the key name given by the client, as an opaque string.
	KeyName string
	// Wrapped is what Encrypt or GenerateDataKey returned earlier.
	Wrapped WrappedKey
	// AAD is the value that was passed when the ciphertext was made, provided
	// the client repeated the key name and context it used then.
	AAD []byte
}

// WrappedKey is a ciphertext as the backend sees it. The server stores it in
// the client-visible ciphertext string; the backend never sees that encoding.
type WrappedKey struct {
	// KeyRef is an opaque reference to the exact key (and key version) the
	// backend used, for example a KMS key ARN. It is returned on encrypt and
	// given back on decrypt. It is not authenticated by the server: a backend
	// that acts on it must make sure that doing so is safe.
	KeyRef string
	// Version is the key version shown to clients as "vault:vN". Values below
	// 1 are reported as 1.
	Version int
	// Blob is the ciphertext produced by the backend.
	Blob []byte
}

// DataKeyGenerator is an optional capability of a Backend. If a backend
// implements it, the datakey endpoint uses it instead of generating the key
// locally and calling Encrypt. It suits KMS APIs that have a native
// "generate data key" call.
type DataKeyGenerator interface {
	// GenerateDataKey returns a new random key of req.Bytes bytes, both in
	// plaintext and wrapped.
	GenerateDataKey(ctx context.Context, req DataKeyRequest) (plaintext []byte, wrapped WrappedKey, err error)
}

// DataKeyRequest is the input of DataKeyGenerator.GenerateDataKey.
type DataKeyRequest struct {
	// MountID identifies the mount. It is never the mount's prefix.
	MountID string
	// KeyName is the key name given by the client, as an opaque string.
	KeyName string
	// Bytes is the length of the data key to generate: 16, 32, or 64.
	Bytes int
	// AAD must be cryptographically bound to the ciphertext.
	AAD []byte
}
