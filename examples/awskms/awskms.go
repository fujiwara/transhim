// Package awskms is an example transhim.Backend for AWS KMS.
//
// It wraps and unwraps with a symmetric KMS key per key name and generates
// data keys with the KMS GenerateDataKey call. It does not create or delete
// KMS keys: they are provisioned by the operator. For per-bucket keys (Ceph
// RGW SSE-S3), use it as the root of a hierarchical.Backend.
//
// # On-disk contract
//
// The following are bound into every ciphertext. Changing any of them makes
// existing ciphertexts undecryptable:
//
//   - The AAD of a request is passed to KMS as the encryption context
//     {"transhim-aad": hex(sha256(AAD))}. The hash keeps the value short
//     whatever the size of the client's context.
//   - Decrypt names the KMS key the key name resolves to (see WithKeyID). If a
//     key name is pointed at another KMS key, for example by moving an alias,
//     ciphertexts made with the old key no longer decrypt under that name.
//     Automatic key rotation in KMS keeps the key ID and is not affected.
package awskms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"
	"github.com/fujiwara/transhim"
)

// encryptionContextKey is the single entry of the KMS encryption context.
const encryptionContextKey = "transhim-aad"

// Client is the part of *kms.Client the backend uses.
type Client interface {
	Encrypt(ctx context.Context, in *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	GenerateDataKey(ctx context.Context, in *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
}

// Backend is a transhim.Backend and transhim.DataKeyGenerator on AWS KMS.
type Backend struct {
	client Client
	keyID  func(mountID, keyName string) string
}

var (
	_ transhim.Backend          = (*Backend)(nil)
	_ transhim.DataKeyGenerator = (*Backend)(nil)
)

// Option configures a Backend.
type Option func(*Backend)

// WithKeyID sets how a key name is turned into the KeyId given to KMS: a key
// ID, a key ARN, an alias name ("alias/..."), or an alias ARN. By default the
// key name is used as it is.
//
// This function decides which KMS keys a client can reach by naming them.
// Ceph RGW passes the key ID of an S3 request on without checking it, so do
// not leave the default in place for an SSE-KMS mount unless every key the
// server's IAM role may use is meant for every S3 user.
func WithKeyID(fn func(mountID, keyName string) string) Option {
	return func(b *Backend) { b.keyID = fn }
}

// WithAliasPrefix resolves a key name to the alias prefix+keyName, for example
// "alias/rgw/" + "my-key". Clients can then only reach keys that have an alias
// under the prefix.
func WithAliasPrefix(prefix string) Option {
	return WithKeyID(func(_, keyName string) string { return prefix + keyName })
}

// New returns a Backend that uses client.
func New(client Client, opts ...Option) *Backend {
	b := &Backend{
		client: client,
		keyID:  func(_, keyName string) string { return keyName },
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// encryptionContext turns the AAD into a KMS encryption context. KMS binds it
// to the ciphertext: decrypting with another one fails.
func encryptionContext(aad []byte) map[string]string {
	sum := sha256.Sum256(aad)
	return map[string]string{encryptionContextKey: hex.EncodeToString(sum[:])}
}

// Encrypt implements transhim.Backend.
func (b *Backend) Encrypt(ctx context.Context, req transhim.EncryptRequest) (transhim.WrappedKey, error) {
	if len(req.Plaintext) == 0 {
		// KMS encrypts 1 to 4096 bytes
		return transhim.WrappedKey{}, fmt.Errorf("%w: empty plaintext", transhim.ErrInvalidRequest)
	}
	out, err := b.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:             aws.String(b.keyID(req.MountID, req.KeyName)),
		Plaintext:         req.Plaintext,
		EncryptionContext: encryptionContext(req.AAD),
	})
	if err != nil {
		return transhim.WrappedKey{}, mapError("Encrypt", err)
	}
	return wrapped(out.KeyId, out.CiphertextBlob), nil
}

// GenerateDataKey implements transhim.DataKeyGenerator.
func (b *Backend) GenerateDataKey(ctx context.Context, req transhim.DataKeyRequest) ([]byte, transhim.WrappedKey, error) {
	out, err := b.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:             aws.String(b.keyID(req.MountID, req.KeyName)),
		NumberOfBytes:     aws.Int32(int32(req.Bytes)),
		EncryptionContext: encryptionContext(req.AAD),
	})
	if err != nil {
		return nil, transhim.WrappedKey{}, mapError("GenerateDataKey", err)
	}
	return out.Plaintext, wrapped(out.KeyId, out.CiphertextBlob), nil
}

// wrapped builds the WrappedKey of a KMS ciphertext. KeyRef is the ARN of the
// key KMS used. It is informational: Decrypt does not rely on it, because a
// client can change it.
func wrapped(keyARN *string, blob []byte) transhim.WrappedKey {
	return transhim.WrappedKey{KeyRef: aws.ToString(keyARN), Version: 1, Blob: blob}
}

// Decrypt implements transhim.Backend.
func (b *Backend) Decrypt(ctx context.Context, req transhim.DecryptRequest) ([]byte, error) {
	if req.Wrapped.Version != 1 {
		return nil, transhim.ErrCiphertextMismatch
	}
	out, err := b.client.Decrypt(ctx, &kms.DecryptInput{
		// Naming the key makes KMS refuse a ciphertext of any other key, on
		// top of the encryption context, which already carries the key name.
		KeyId:             aws.String(b.keyID(req.MountID, req.KeyName)),
		CiphertextBlob:    req.Wrapped.Blob,
		EncryptionContext: encryptionContext(req.AAD),
	})
	if err != nil {
		return nil, mapError("Decrypt", err)
	}
	return out.Plaintext, nil
}

// mapError turns a KMS error into one transhim knows how to answer. The KMS
// error stays in the chain for the log and the audit trail.
func mapError(op string, err error) error {
	wrap := func(kind error) error {
		return fmt.Errorf("%w: kms %s: %w", kind, op, err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("kms %s: %w", op, err)
	}
	ae, ok := errors.AsType[smithy.APIError](err)
	if !ok {
		// no answer from KMS: network trouble, timeouts
		return &transhim.UpstreamError{Err: fmt.Errorf("kms %s: %w", op, err), Retryable: true}
	}
	switch ae.ErrorCode() {
	case "NotFoundException":
		return wrap(transhim.ErrKeyNotFound)
	case "InvalidCiphertextException", "IncorrectKeyException":
		return wrap(transhim.ErrCiphertextMismatch)
	case "AccessDeniedException", "DisabledException", "KMSInvalidStateException", "InvalidGrantTokenException":
		// the server's role may not use the key, or the key was disabled or
		// scheduled for deletion: the way keys are revoked in KMS
		return wrap(transhim.ErrPermissionDenied)
	case "ThrottlingException", "LimitExceededException", "KMSInternalException",
		"DependencyTimeoutException", "KeyUnavailableException", "ServiceUnavailableException":
		return &transhim.UpstreamError{Err: fmt.Errorf("kms %s: %w", op, err), Retryable: true}
	}
	return &transhim.UpstreamError{Err: fmt.Errorf("kms %s: %w", op, err)}
}
