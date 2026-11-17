// Package transhimtest provides an in-memory backend for testing servers
// built with transhim. It must not be used to protect real data.
package transhimtest

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/fujiwara/transhim"
)

// Operation names used by FakeBackend.Calls and FakeBackend.SetError.
const (
	OpEncrypt         = "encrypt"
	OpDecrypt         = "decrypt"
	OpGenerateDataKey = "generate_data_key"
)

const fakeKeyRef = "fake"

// FakeBackend is a transhim.Backend that keeps AES-256 keys in memory and
// wraps with AES-GCM, binding the AAD. Keys exist only after AddKey.
//
// It can inject errors and latency, and counts calls. It is safe for
// concurrent use.
type FakeBackend struct {
	mu    sync.Mutex
	keys  map[fakeKeyID][]byte
	errs  map[string]error
	calls map[string]int
	delay time.Duration
}

type fakeKeyID struct{ mountID, name string }

// NewFakeBackend returns a FakeBackend without keys.
func NewFakeBackend() *FakeBackend {
	return &FakeBackend{
		keys:  map[fakeKeyID][]byte{},
		errs:  map[string]error{},
		calls: map[string]int{},
	}
}

// AddKey creates a random key for (mountID, name). An existing key is kept.
func (b *FakeBackend) AddKey(mountID, name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := fakeKeyID{mountID, name}
	if _, ok := b.keys[id]; ok {
		return
	}
	key := make([]byte, 32)
	rand.Read(key)
	b.keys[id] = key
}

// RemoveKey deletes the key for (mountID, name), if any.
func (b *FakeBackend) RemoveKey(mountID, name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.keys, fakeKeyID{mountID, name})
}

// SetError makes every later call of op (one of the Op constants of this
// package) fail with err. A nil err removes the injection.
func (b *FakeBackend) SetError(op string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		delete(b.errs, op)
		return
	}
	b.errs[op] = err
}

// SetDelay makes every later call wait for d, or until its context ends.
func (b *FakeBackend) SetDelay(d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.delay = d
}

// Calls returns how many times op (one of the Op constants of this package)
// was called, including failed calls.
func (b *FakeBackend) Calls(op string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls[op]
}

// begin counts the call, applies the delay and injected error, and returns the
// AEAD for the key.
func (b *FakeBackend) begin(ctx context.Context, op, mountID, name string) (cipher.AEAD, error) {
	b.mu.Lock()
	b.calls[op]++
	delay, injected := b.delay, b.errs[op]
	key, ok := b.keys[fakeKeyID{mountID, name}]
	b.mu.Unlock()

	if delay > 0 {
		t := time.NewTimer(delay)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if injected != nil {
		return nil, injected
	}
	if !ok {
		return nil, fmt.Errorf("%w: %s", transhim.ErrKeyNotFound, name)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func seal(aead cipher.AEAD, plaintext, aad []byte) transhim.WrappedKey {
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	return transhim.WrappedKey{
		KeyRef:  fakeKeyRef,
		Version: 1,
		Blob:    aead.Seal(nonce, nonce, plaintext, aad),
	}
}

// Encrypt implements transhim.Backend.
func (b *FakeBackend) Encrypt(ctx context.Context, req transhim.EncryptRequest) (transhim.WrappedKey, error) {
	aead, err := b.begin(ctx, OpEncrypt, req.MountID, req.KeyName)
	if err != nil {
		return transhim.WrappedKey{}, err
	}
	return seal(aead, req.Plaintext, req.AAD), nil
}

// Decrypt implements transhim.Backend.
func (b *FakeBackend) Decrypt(ctx context.Context, req transhim.DecryptRequest) ([]byte, error) {
	aead, err := b.begin(ctx, OpDecrypt, req.MountID, req.KeyName)
	if err != nil {
		return nil, err
	}
	blob := req.Wrapped.Blob
	if req.Wrapped.KeyRef != fakeKeyRef || len(blob) < aead.NonceSize() {
		return nil, transhim.ErrCiphertextMismatch
	}
	plaintext, err := aead.Open(nil, blob[:aead.NonceSize()], blob[aead.NonceSize():], req.AAD)
	if err != nil {
		return nil, transhim.ErrCiphertextMismatch
	}
	return plaintext, nil
}

// WithDataKeyGenerator returns a view of b that also implements
// transhim.DataKeyGenerator. It shares keys, injections, and counters with b.
func (b *FakeBackend) WithDataKeyGenerator() *FakeDataKeyBackend {
	return &FakeDataKeyBackend{FakeBackend: b}
}

// FakeDataKeyBackend is a FakeBackend that generates data keys itself, like a
// KMS with a native "generate data key" call.
type FakeDataKeyBackend struct {
	*FakeBackend
}

// GenerateDataKey implements transhim.DataKeyGenerator.
func (b *FakeDataKeyBackend) GenerateDataKey(ctx context.Context, req transhim.DataKeyRequest) ([]byte, transhim.WrappedKey, error) {
	aead, err := b.begin(ctx, OpGenerateDataKey, req.MountID, req.KeyName)
	if err != nil {
		return nil, transhim.WrappedKey{}, err
	}
	plaintext := make([]byte, req.Bytes)
	rand.Read(plaintext)
	return plaintext, seal(aead, plaintext, req.AAD), nil
}
