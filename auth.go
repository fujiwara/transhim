package transhim

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
)

// Op names the operation a request performs.
type Op string

// Operations.
const (
	OpDataKey Op = "datakey"
	OpEncrypt Op = "encrypt"
	OpDecrypt Op = "decrypt"
	// OpKeyCreate is POST keys/{name}.
	OpKeyCreate Op = "key_create"
	// OpKeyConfig is POST keys/{name}/config.
	OpKeyConfig Op = "key_config"
	// OpKeyDelete is DELETE keys/{name}.
	OpKeyDelete Op = "key_delete"
)

// AuthRequest describes a request to an Authorizer.
type AuthRequest struct {
	// Op is the operation.
	Op Op
	// MountID identifies the mount. It is never the mount's prefix.
	MountID string
	// KeyName is the key the operation uses.
	KeyName string
	// Context is the decoded "context" of a datakey, encrypt, or decrypt
	// request: the bytes that are bound into the ciphertext along with the
	// mount ID and the key name. It is nil if the request has none, and for
	// the key operations, which never have one.
	//
	// The client chooses it. Ceph RGW sends a JSON object that names the S3
	// object: {"aws:s3:arn":"arn:aws:s3::<owner>:<bucket>/<object>"}. With
	// SSE-S3 that is RGW's own statement. With SSE-KMS the S3 user can add
	// entries and replace the ARN with any other, so it must not be what
	// decides which key that user may use (docs/compat.md).
	Context []byte
	// Token is the first X-Vault-Token header value, or "".
	Token string
	// Namespace is the X-Vault-Namespace header value. The server does not
	// interpret it.
	Namespace string
	// TLS is the connection's TLS state, or nil for plain HTTP. It gives
	// access to client certificates for mTLS.
	TLS *tls.ConnectionState
	// RemoteAddr is the peer address as reported by net/http.
	RemoteAddr string
}

// Authorizer decides whether a request may proceed. It returns nil to allow
// it, and an error wrapping ErrPermissionDenied to answer 403. Any other error
// also rejects the request, with the status its kind maps to (for example 502
// for ErrUpstream, 500 otherwise).
//
// It is called after the request body was read (up to the size limit) and
// before anything in it is reported as wrong, so a client that is refused
// learns nothing about its body.
//
// Clients such as Ceph RGW do not check whether an S3 user may use a given key
// name. If that matters, check it here. A Backend can restrict which keys a
// name may reach at all, but it is not called for requests answered from the
// decrypt cache, so it cannot decide per request.
type Authorizer func(ctx context.Context, req AuthRequest) error

// StaticTokenAuthorizer returns an Authorizer that allows every operation to
// requests carrying the given token, compared in constant time. An empty token
// allows nothing.
func StaticTokenAuthorizer(token string) Authorizer {
	want := sha256.Sum256([]byte(token))
	return func(_ context.Context, req AuthRequest) error {
		got := sha256.Sum256([]byte(req.Token))
		if token == "" || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			return ErrPermissionDenied
		}
		return nil
	}
}
