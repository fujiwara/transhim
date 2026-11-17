package awskms_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/examples/awskms"
	"github.com/fujiwara/transhim/hierarchical"
	"github.com/fujiwara/transhim/keystore/memstore"
	"github.com/fujiwara/transhim/transhimtest"
)

// The tests below run against a KMS endpoint, meant to be the AWS Emulator
// (https://github.com/aws/aws-emulator), never a real account:
//
//	aws-emulator --telemetry off --auth off &
//	export AWS_CA_BUNDLE=$HOME/.aws/emulator/9297/ca.pem
//	TRANSHIM_TEST_KMS_ENDPOINT=https://127.0.0.1:9297 go test ./...
//
// They create KMS keys and aliases there and leave them behind.

type emulator struct {
	client *kms.Client
	// prefix is an alias prefix of this test run's own.
	prefix string
}

func newEmulator(t *testing.T) *emulator {
	t.Helper()
	endpoint := os.Getenv("TRANSHIM_TEST_KMS_ENDPOINT")
	if endpoint == "" {
		t.Skip("TRANSHIM_TEST_KMS_ENDPOINT is not set")
	}
	// AWS_CA_BUNDLE is honored by the default config
	cfg, err := config.LoadDefaultConfig(t.Context(),
		config.WithRegion("ap-northeast-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("dummy", "dummy", "")),
	)
	if err != nil {
		t.Fatal(err)
	}
	suffix := make([]byte, 4)
	rand.Read(suffix)
	return &emulator{
		client: kms.NewFromConfig(cfg, func(o *kms.Options) { o.BaseEndpoint = aws.String(endpoint) }),
		prefix: fmt.Sprintf("alias/transhim-test-%x/", suffix),
	}
}

// createKey creates a KMS key with the alias prefix+name and returns its ID.
func (e *emulator) createKey(t *testing.T, name string) string {
	t.Helper()
	key, err := e.client.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	_, err = e.client.CreateAlias(t.Context(), &kms.CreateAliasInput{
		AliasName: aws.String(e.prefix + name), TargetKeyId: key.KeyMetadata.KeyId,
	})
	if err != nil {
		t.Fatalf("CreateAlias: %v", err)
	}
	return aws.ToString(key.KeyMetadata.KeyId)
}

func TestEmulatorBackend(t *testing.T) {
	e := newEmulator(t)
	ctx := t.Context()
	keyID := e.createKey(t, "a")
	e.createKey(t, "b")
	b := awskms.New(e.client, awskms.WithAliasPrefix(e.prefix))

	wk, err := b.Encrypt(ctx, transhim.EncryptRequest{MountID: "m", KeyName: "a", Plaintext: []byte("secret"), AAD: []byte("aad")})
	if err != nil {
		t.Fatal(err)
	}
	if want := "key/" + keyID; len(wk.KeyRef) < len(want) || wk.KeyRef[len(wk.KeyRef)-len(want):] != want {
		t.Errorf("KeyRef = %q, want the ARN of key %s", wk.KeyRef, keyID)
	}
	decrypt := func(name string, wk transhim.WrappedKey, aad string) ([]byte, error) {
		return b.Decrypt(ctx, transhim.DecryptRequest{MountID: "m", KeyName: name, Wrapped: wk, AAD: []byte(aad)})
	}
	if got, err := decrypt("a", wk, "aad"); err != nil || string(got) != "secret" {
		t.Fatalf("Decrypt = %q, %v", got, err)
	}
	// KMS enforces the binding
	if _, err := decrypt("a", wk, "other aad"); !errors.Is(err, transhim.ErrCiphertextMismatch) {
		t.Errorf("wrong AAD: err = %v, want ErrCiphertextMismatch", err)
	}
	if _, err := decrypt("b", wk, "aad"); !errors.Is(err, transhim.ErrCiphertextMismatch) {
		t.Errorf("wrong key: err = %v, want ErrCiphertextMismatch", err)
	}
	tampered := wk
	tampered.Blob = append([]byte(nil), wk.Blob...)
	tampered.Blob[len(tampered.Blob)-1] ^= 1
	if _, err := decrypt("a", tampered, "aad"); !errors.Is(err, transhim.ErrCiphertextMismatch) {
		t.Errorf("tampered: err = %v, want ErrCiphertextMismatch", err)
	}
	if _, err := decrypt("missing", wk, "aad"); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("missing key: err = %v, want ErrKeyNotFound", err)
	}
	if _, err := b.Encrypt(ctx, transhim.EncryptRequest{MountID: "m", KeyName: "missing", Plaintext: []byte("p")}); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("Encrypt with a missing key: err = %v, want ErrKeyNotFound", err)
	}

	for _, size := range []int{16, 32, 64} {
		key, wk, err := b.GenerateDataKey(ctx, transhim.DataKeyRequest{MountID: "m", KeyName: "a", Bytes: size, AAD: []byte("aad")})
		if err != nil || len(key) != size {
			t.Fatalf("GenerateDataKey(%d) = %d bytes, %v", size, len(key), err)
		}
		if got, err := decrypt("a", wk, "aad"); err != nil || string(got) != string(key) {
			t.Errorf("Decrypt of a %d byte data key: %v", size, err)
		}
	}

	// a disabled key is how access is revoked in KMS
	if _, err := e.client.DisableKey(ctx, &kms.DisableKeyInput{KeyId: &keyID}); err != nil {
		t.Fatalf("DisableKey: %v", err)
	}
	if _, err := decrypt("a", wk, "aad"); !errors.Is(err, transhim.ErrPermissionDenied) {
		t.Errorf("disabled key: err = %v, want ErrPermissionDenied", err)
	}
}

// TestEmulatorConformance runs the conformance suite on the two mounts of the
// example server.
func TestEmulatorConformance(t *testing.T) {
	e := newEmulator(t)
	const token = "conformance-token"
	e.createKey(t, "key-a")
	e.createKey(t, "key-b")
	e.createKey(t, "root")

	sseKMS := awskms.New(e.client, awskms.WithAliasPrefix(e.prefix))
	sseS3, err := hierarchical.New(awskms.New(e.client), e.prefix+"root", memstore.New())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := transhim.NewServer(
		transhim.Mount("/v1/transit-kms", "rgw-kms", sseKMS),
		transhim.Mount("/v1/transit-sse-s3", "rgw-sse-s3", sseS3),
		transhim.WithAuthorizer(transhim.StaticTokenAuthorizer(token)),
		transhim.WithDecryptCache(transhim.DecryptCacheConfig{MaxEntries: 100, TTL: time.Minute}),
		transhim.WithLogger(slog.New(slog.DiscardHandler)),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("SSE-KMS mount", func(t *testing.T) {
		transhimtest.RunConformance(t, transhimtest.Conformance{
			Handler: srv, Prefix: "/v1/transit-kms", Token: token, KeyNames: [2]string{"key-a", "key-b"},
		})
	})
	t.Run("SSE-S3 mount", func(t *testing.T) {
		transhimtest.RunConformance(t, transhimtest.Conformance{
			Handler: srv, Prefix: "/v1/transit-sse-s3", Token: token, ManagedKeys: true,
		})
	})
}
