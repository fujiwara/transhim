package awskms_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/examples/awskms"
)

// stubClient records the requests and answers with fixed values.
type stubClient struct {
	err      error
	encrypt  *kms.EncryptInput
	decrypt  *kms.DecryptInput
	generate *kms.GenerateDataKeyInput
}

const stubARN = "arn:aws:kms:ap-northeast-1:123456789012:key/11111111-2222-3333-4444-555555555555"

func (c *stubClient) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	c.encrypt = in
	if c.err != nil {
		return nil, c.err
	}
	return &kms.EncryptOutput{KeyId: aws.String(stubARN), CiphertextBlob: []byte("blob")}, nil
}

func (c *stubClient) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	c.decrypt = in
	if c.err != nil {
		return nil, c.err
	}
	return &kms.DecryptOutput{Plaintext: []byte("plaintext")}, nil
}

func (c *stubClient) GenerateDataKey(_ context.Context, in *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	c.generate = in
	if c.err != nil {
		return nil, c.err
	}
	return &kms.GenerateDataKeyOutput{
		KeyId: aws.String(stubARN), CiphertextBlob: []byte("blob"), Plaintext: make([]byte, aws.ToInt32(in.NumberOfBytes)),
	}, nil
}

// checkContext checks the encryption context sent for the AAD "aad": a single
// entry with the hex SHA-256 of the AAD. This mapping is part of the on-disk
// contract, so it is spelled out here instead of calling the package.
func checkContext(t *testing.T, got map[string]string) {
	t.Helper()
	sum := sha256.Sum256([]byte("aad"))
	want := hex.EncodeToString(sum[:])
	if len(got) != 1 || got["transhim-aad"] != want {
		t.Errorf("encryption context = %v, want transhim-aad=%s", got, want)
	}
}

func TestRequests(t *testing.T) {
	ctx := t.Context()
	c := &stubClient{}
	b := awskms.New(c, awskms.WithAliasPrefix("alias/rgw/"))

	wk, err := b.Encrypt(ctx, transhim.EncryptRequest{MountID: "m", KeyName: "my-key", Plaintext: []byte("p"), AAD: []byte("aad")})
	if err != nil {
		t.Fatal(err)
	}
	if wk.KeyRef != stubARN || wk.Version != 1 || string(wk.Blob) != "blob" {
		t.Errorf("wrapped key = %+v", wk)
	}
	if got := aws.ToString(c.encrypt.KeyId); got != "alias/rgw/my-key" || string(c.encrypt.Plaintext) != "p" {
		t.Errorf("Encrypt request: KeyId = %q, Plaintext = %q", got, c.encrypt.Plaintext)
	}
	checkContext(t, c.encrypt.EncryptionContext)

	plaintext, err := b.Decrypt(ctx, transhim.DecryptRequest{MountID: "m", KeyName: "my-key", Wrapped: wk, AAD: []byte("aad")})
	if err != nil || string(plaintext) != "plaintext" {
		t.Fatalf("Decrypt = %q, %v", plaintext, err)
	}
	// the key is named by the request, not taken from the ciphertext's KeyRef
	if got := aws.ToString(c.decrypt.KeyId); got != "alias/rgw/my-key" || string(c.decrypt.CiphertextBlob) != "blob" {
		t.Errorf("Decrypt request: KeyId = %q, CiphertextBlob = %q", got, c.decrypt.CiphertextBlob)
	}
	checkContext(t, c.decrypt.EncryptionContext)

	key, wk, err := b.GenerateDataKey(ctx, transhim.DataKeyRequest{MountID: "m", KeyName: "my-key", Bytes: 64, AAD: []byte("aad")})
	if err != nil || len(key) != 64 || wk.KeyRef != stubARN || wk.Version != 1 {
		t.Fatalf("GenerateDataKey = %d bytes, %+v, %v", len(key), wk, err)
	}
	if got := aws.ToString(c.generate.KeyId); got != "alias/rgw/my-key" || aws.ToInt32(c.generate.NumberOfBytes) != 64 {
		t.Errorf("GenerateDataKey request: KeyId = %q, NumberOfBytes = %d", got, aws.ToInt32(c.generate.NumberOfBytes))
	}
	checkContext(t, c.generate.EncryptionContext)
}

func TestKeyID(t *testing.T) {
	ctx := t.Context()
	c := &stubClient{}
	// by default the key name is the KeyId
	awskms.New(c).Encrypt(ctx, transhim.EncryptRequest{MountID: "m", KeyName: "alias/root", Plaintext: []byte("p")})
	if got := aws.ToString(c.encrypt.KeyId); got != "alias/root" {
		t.Errorf("default KeyId = %q", got)
	}
	b := awskms.New(c, awskms.WithKeyID(func(mountID, keyName string) string {
		return fmt.Sprintf("alias/%s/%s", mountID, keyName)
	}))
	b.Encrypt(ctx, transhim.EncryptRequest{MountID: "m", KeyName: "k", Plaintext: []byte("p")})
	if got := aws.ToString(c.encrypt.KeyId); got != "alias/m/k" {
		t.Errorf("KeyId = %q, want alias/m/k", got)
	}
}

// KMS does not encrypt an empty plaintext.
func TestEncryptRejectsEmptyPlaintext(t *testing.T) {
	c := &stubClient{}
	_, err := awskms.New(c).Encrypt(t.Context(), transhim.EncryptRequest{KeyName: "k"})
	if !errors.Is(err, transhim.ErrInvalidRequest) || c.encrypt != nil {
		t.Errorf("err = %v, KMS called = %v; want ErrInvalidRequest without a call", err, c.encrypt != nil)
	}
}

func TestDecryptRejectsOtherVersions(t *testing.T) {
	c := &stubClient{}
	b := awskms.New(c)
	_, err := b.Decrypt(t.Context(), transhim.DecryptRequest{KeyName: "k", Wrapped: transhim.WrappedKey{Version: 2, Blob: []byte("blob")}})
	if !errors.Is(err, transhim.ErrCiphertextMismatch) || c.decrypt != nil {
		t.Errorf("err = %v, KMS called = %v; want ErrCiphertextMismatch without a call", err, c.decrypt != nil)
	}
}

func TestErrorMapping(t *testing.T) {
	api := func(code string) error { return &smithy.GenericAPIError{Code: code, Message: "SECRET detail"} }
	tests := []struct {
		err       error
		want      error
		retryable bool
	}{
		{&types.NotFoundException{}, transhim.ErrKeyNotFound, false},
		{&types.InvalidCiphertextException{}, transhim.ErrCiphertextMismatch, false},
		{&types.IncorrectKeyException{}, transhim.ErrCiphertextMismatch, false},
		{api("AccessDeniedException"), transhim.ErrPermissionDenied, false},
		{&types.DisabledException{}, transhim.ErrPermissionDenied, false},
		{&types.KMSInvalidStateException{}, transhim.ErrPermissionDenied, false},
		{api("ThrottlingException"), transhim.ErrUpstream, true},
		{&types.KMSInternalException{}, transhim.ErrUpstream, true},
		{&types.KeyUnavailableException{}, transhim.ErrUpstream, true},
		{&types.DependencyTimeoutException{}, transhim.ErrUpstream, true},
		{api("SomethingNew"), transhim.ErrUpstream, false},
		{errors.New("dial tcp: connection refused"), transhim.ErrUpstream, true},
	}
	ctx := t.Context()
	for _, tt := range tests {
		c := &stubClient{err: tt.err}
		b := awskms.New(c)
		_, encErr := b.Encrypt(ctx, transhim.EncryptRequest{KeyName: "k", Plaintext: []byte("p")})
		_, decErr := b.Decrypt(ctx, transhim.DecryptRequest{KeyName: "k", Wrapped: transhim.WrappedKey{Version: 1}})
		_, _, genErr := b.GenerateDataKey(ctx, transhim.DataKeyRequest{KeyName: "k", Bytes: 32})
		for op, err := range map[string]error{"Encrypt": encErr, "Decrypt": decErr, "GenerateDataKey": genErr} {
			if !errors.Is(err, tt.want) {
				t.Errorf("%s with %v: err = %v, want %v", op, tt.err, err, tt.want)
			}
			ue, ok := errors.AsType[*transhim.UpstreamError](err)
			if (ok && ue.Retryable) != tt.retryable {
				t.Errorf("%s with %v: retryable = %v, want %v", op, tt.err, ok && ue.Retryable, tt.retryable)
			}
			// the KMS error stays available for logs and audit
			if !errors.Is(err, tt.err) {
				t.Errorf("%s with %v: the KMS error is not in the chain of %v", op, tt.err, err)
			}
		}
	}

	// a canceled request is not a KMS failure
	c := &stubClient{err: fmt.Errorf("operation error KMS: %w", context.Canceled)}
	_, err := awskms.New(c).Encrypt(ctx, transhim.EncryptRequest{KeyName: "k", Plaintext: []byte("p")})
	if !errors.Is(err, context.Canceled) || errors.Is(err, transhim.ErrUpstream) {
		t.Errorf("canceled: err = %v, want context.Canceled and not ErrUpstream", err)
	}
}
