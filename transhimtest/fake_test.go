package transhimtest_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/transhimtest"
)

func TestFakeBackend(t *testing.T) {
	ctx := t.Context()
	b := transhimtest.NewFakeBackend()
	b.AddKey("m", "k")
	b.AddKey("m", "other")

	wk, err := b.Encrypt(ctx, transhim.EncryptRequest{MountID: "m", KeyName: "k", Plaintext: []byte("secret"), AAD: []byte("aad")})
	if err != nil {
		t.Fatal(err)
	}
	if wk.Version != 1 || bytes.Contains(wk.Blob, []byte("secret")) {
		t.Errorf("wrapped key = %+v", wk)
	}
	got, err := b.Decrypt(ctx, transhim.DecryptRequest{MountID: "m", KeyName: "k", Wrapped: wk, AAD: []byte("aad")})
	if err != nil || string(got) != "secret" {
		t.Errorf("Decrypt = %q, %v", got, err)
	}

	// AddKey keeps an existing key
	b.AddKey("m", "k")
	if _, err := b.Decrypt(ctx, transhim.DecryptRequest{MountID: "m", KeyName: "k", Wrapped: wk, AAD: []byte("aad")}); err != nil {
		t.Errorf("Decrypt after a second AddKey: %v", err)
	}

	mismatches := map[string]transhim.DecryptRequest{
		"wrong AAD":  {MountID: "m", KeyName: "k", Wrapped: wk, AAD: []byte("other")},
		"wrong key":  {MountID: "m", KeyName: "other", Wrapped: wk, AAD: []byte("aad")},
		"wrong ref":  {MountID: "m", KeyName: "k", Wrapped: transhim.WrappedKey{KeyRef: "x", Blob: wk.Blob}, AAD: []byte("aad")},
		"short blob": {MountID: "m", KeyName: "k", Wrapped: transhim.WrappedKey{KeyRef: wk.KeyRef, Blob: []byte("x")}, AAD: []byte("aad")},
	}
	for name, req := range mismatches {
		if _, err := b.Decrypt(ctx, req); !errors.Is(err, transhim.ErrCiphertextMismatch) {
			t.Errorf("%s: err = %v, want ErrCiphertextMismatch", name, err)
		}
	}

	if _, err := b.Encrypt(ctx, transhim.EncryptRequest{MountID: "other-mount", KeyName: "k"}); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("key of another mount: err = %v, want ErrKeyNotFound", err)
	}
	b.RemoveKey("m", "k")
	if _, err := b.Decrypt(ctx, transhim.DecryptRequest{MountID: "m", KeyName: "k", Wrapped: wk, AAD: []byte("aad")}); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("removed key: err = %v, want ErrKeyNotFound", err)
	}
}

func TestFakeBackendInjection(t *testing.T) {
	ctx := t.Context()
	b := transhimtest.NewFakeBackend()
	b.AddKey("m", "k")
	req := transhim.EncryptRequest{MountID: "m", KeyName: "k", Plaintext: []byte("p")}

	boom := errors.New("boom")
	b.SetError(transhimtest.OpEncrypt, boom)
	if _, err := b.Encrypt(ctx, req); !errors.Is(err, boom) {
		t.Errorf("err = %v, want the injected error", err)
	}
	b.SetError(transhimtest.OpEncrypt, nil)
	if _, err := b.Encrypt(ctx, req); err != nil {
		t.Errorf("after removing the injection: %v", err)
	}
	if n := b.Calls(transhimtest.OpEncrypt); n != 2 {
		t.Errorf("Calls = %d, want 2", n)
	}

	b.SetDelay(time.Minute)
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := b.Encrypt(ctx, req); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestFakeBackendKeyLifecycle(t *testing.T) {
	ctx := t.Context()
	b := transhimtest.NewFakeBackend()
	var _ transhim.KeyLifecycle = b

	if err := b.CreateKey(ctx, "m", "k"); err != nil || !b.HasKey("m", "k") {
		t.Fatalf("CreateKey: %v, HasKey = %v", err, b.HasKey("m", "k"))
	}
	wk, err := b.Encrypt(ctx, transhim.EncryptRequest{MountID: "m", KeyName: "k", Plaintext: []byte("p")})
	if err != nil {
		t.Fatal(err)
	}
	// creating again keeps the key
	if err := b.CreateKey(ctx, "m", "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Decrypt(ctx, transhim.DecryptRequest{MountID: "m", KeyName: "k", Wrapped: wk}); err != nil {
		t.Errorf("Decrypt after a second CreateKey: %v", err)
	}
	// deleting is idempotent
	for range 2 {
		if err := b.DeleteKey(ctx, "m", "k"); err != nil || b.HasKey("m", "k") {
			t.Errorf("DeleteKey: %v, HasKey = %v", err, b.HasKey("m", "k"))
		}
	}
	boom := errors.New("boom")
	b.SetError(transhimtest.OpCreateKey, boom)
	b.SetError(transhimtest.OpDeleteKey, boom)
	if err := b.CreateKey(ctx, "m", "k"); !errors.Is(err, boom) || b.HasKey("m", "k") {
		t.Errorf("CreateKey with an injected error: %v, HasKey = %v", err, b.HasKey("m", "k"))
	}
	if err := b.DeleteKey(ctx, "m", "k"); !errors.Is(err, boom) {
		t.Errorf("DeleteKey with an injected error: %v", err)
	}
	if c, d := b.Calls(transhimtest.OpCreateKey), b.Calls(transhimtest.OpDeleteKey); c != 3 || d != 3 {
		t.Errorf("Calls = %d creates, %d deletes; want 3, 3", c, d)
	}
}

func TestFakeDataKeyBackend(t *testing.T) {
	ctx := t.Context()
	b := transhimtest.NewFakeBackend()
	b.AddKey("m", "k")
	g := b.WithDataKeyGenerator()
	var _ transhim.DataKeyGenerator = g

	plaintext, wk, err := g.GenerateDataKey(ctx, transhim.DataKeyRequest{MountID: "m", KeyName: "k", Bytes: 32, AAD: []byte("aad")})
	if err != nil || len(plaintext) != 32 {
		t.Fatalf("GenerateDataKey = %d bytes, %v", len(plaintext), err)
	}
	// the generator view shares keys with the backend it came from
	got, err := b.Decrypt(ctx, transhim.DecryptRequest{MountID: "m", KeyName: "k", Wrapped: wk, AAD: []byte("aad")})
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Errorf("Decrypt = %x, %v; want %x", got, err, plaintext)
	}
	if n := b.Calls(transhimtest.OpGenerateDataKey); n != 1 {
		t.Errorf("Calls = %d, want 1", n)
	}
}
