package integration_test

import (
	"slices"
	"testing"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/hierarchical"
)

// TestRGWReadOnlyKeyStore runs SSE-S3 against a server that must not write to
// the key store (hierarchical.ReadOnly). The bucket keys are created and
// deleted by a second backend on the same store, as a provisioning tool would.
func TestRGWReadOnlyKeyStore(t *testing.T) {
	h := newHarness(t, false, hierarchical.ReadOnly())
	provisioner, err := hierarchical.New(h.root, rootKey, h.store)
	if err != nil {
		t.Fatal(err)
	}
	b := h.newBucket(t, "readonly")
	small := []byte("hello")

	// Before the key is provisioned, an SSE-S3 write fails and stores
	// nothing. RGW asks for the key to be created, which tells its name.
	err = b.put("early", small, sseS3)
	t.Logf("PutObject before the key is provisioned = %s", outcome(err))
	if err == nil {
		t.Fatal("PutObject succeeded without a key")
	}
	evs := h.take()
	if got := ops(evs, sseMount); !slices.Equal(got, []string{"key_create 400"}) {
		t.Fatalf("PutObject before the key is provisioned caused %v, want only a refused key_create", got)
	}
	if b.exists("early") {
		t.Error("the object was stored although its key could not be created")
	}
	keyName := evs[0].KeyName
	if h.store.Len() != 0 {
		t.Fatalf("%d keys in the store, want none: the server must not create keys", h.store.Len())
	}

	if err := provisioner.CreateKey(t.Context(), sseMount, keyName); err != nil {
		t.Fatal(err)
	}
	b.mustPut("obj", small, sseS3)
	b.mustGet("obj", small, sseS3)
	if got := ops(h.take(), sseMount); !slices.Equal(got, []string{"key_create 204", "datakey 200", "decrypt 200"}) {
		t.Errorf("PutObject and GetObject with a provisioned key caused %v", got)
	}

	// Deleting the bucket does not delete the key: that is the provisioning
	// side's job as well.
	if err := b.destroy(t.Context()); err != nil {
		t.Fatal(err)
	}
	evs = h.take()
	if count(evs, sseMount, transhim.OpKeyDelete) != 1 {
		t.Errorf("DeleteBucket caused %v, want a key_delete", ops(evs, sseMount))
	}
	if h.store.Len() != 1 {
		t.Errorf("%d keys in the store after DeleteBucket, want 1: the server must not delete keys", h.store.Len())
	}
	if err := provisioner.DeleteKey(t.Context(), sseMount, keyName); err != nil {
		t.Fatal(err)
	}
}
