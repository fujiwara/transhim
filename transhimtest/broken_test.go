package transhimtest_test

import (
	"context"
	"errors"
	"testing"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/transhimtest"
)

// fails runs fn as a test of its own and reports whether it failed, without
// failing the calling test.
func fails(fn func(t *testing.T)) bool {
	res := testing.RunTests(func(string, string) (bool, error) { return true, nil },
		[]testing.InternalTest{{Name: "broken", F: fn}})
	return !res
}

// ignoreAAD encrypts and decrypts with a fixed AAD: ciphertexts are not bound
// to key name and context beyond the key itself.
type ignoreAAD struct{ *transhimtest.FakeBackend }

func (b ignoreAAD) Encrypt(ctx context.Context, req transhim.EncryptRequest) (transhim.WrappedKey, error) {
	req.AAD = nil
	return b.FakeBackend.Encrypt(ctx, req)
}

func (b ignoreAAD) Decrypt(ctx context.Context, req transhim.DecryptRequest) ([]byte, error) {
	req.AAD = nil
	return b.FakeBackend.Decrypt(ctx, req)
}

// keepKeys reports success on delete without deleting.
type keepKeys struct{ *transhimtest.FakeBackend }

func (keepKeys) DeleteKey(context.Context, string, string) error { return nil }

// replaceKeys makes a new key on every create.
type replaceKeys struct{ *transhimtest.FakeBackend }

func (b replaceKeys) CreateKey(ctx context.Context, mountID, keyName string) error {
	b.RemoveKey(mountID, keyName)
	return b.FakeBackend.CreateKey(ctx, mountID, keyName)
}

// hideNotFound reports a missing key as an unspecific error.
type hideNotFound struct{ *transhimtest.FakeBackend }

func (b hideNotFound) Encrypt(ctx context.Context, req transhim.EncryptRequest) (transhim.WrappedKey, error) {
	wk, err := b.FakeBackend.Encrypt(ctx, req)
	if errors.Is(err, transhim.ErrKeyNotFound) {
		err = errors.New("no such key")
	}
	return wk, err
}
