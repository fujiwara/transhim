package integration_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/fujiwara/transhim"
)

// TestRGW is the acceptance test: SSE-KMS and SSE-S3 of a real Ceph RGW,
// without and with the decrypt cache.
func TestRGW(t *testing.T) {
	for _, tt := range []struct {
		name  string
		cache bool
	}{
		{"no cache", false},
		{"decrypt cache", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, tt.cache)
			t.Run("SSE-KMS", func(t *testing.T) { testSSEKMS(t, h, tt.cache) })
			t.Run("SSE-S3", func(t *testing.T) { testSSES3(t, h) })
		})
	}
}

func testSSEKMS(t *testing.T, h *harness, cache bool) {
	b := h.newBucket(t, "kms")
	small := randomBytes(1024)
	h.take()

	t.Run("PutObject and GetObject", func(t *testing.T) {
		b.mustPut("obj1", small, sseKMS(kmsKey1))
		if got := ops(h.take(), kmsMount); !slices.Equal(got, []string{"datakey 200"}) {
			t.Errorf("PutObject caused %v, want one datakey", got)
		}
		b.mustGet("obj1", small, sseKMS(kmsKey1))
		evs := h.take()
		if got := ops(evs, kmsMount); !slices.Equal(got, []string{"decrypt 200"}) {
			t.Errorf("GetObject caused %v, want one decrypt", got)
		}
		if len(evs) > 0 && evs[0].KeyName != kmsKey1 {
			t.Errorf("key name = %q, want the client's key ID %q", evs[0].KeyName, kmsKey1)
		}
		// RGW decrypts on every read of the object
		b.mustGet("obj1", small, sseKMS(kmsKey1))
		if !b.exists("obj1") {
			t.Error("HeadObject failed")
		}
		if n := count(h.take(), kmsMount, transhim.OpDecrypt); n != 2 {
			t.Errorf("GetObject and HeadObject caused %d decrypts, want 2", n)
		}
		if got := ops(h.take(), sseMount); len(got) != 0 {
			t.Errorf("SSE-KMS used the SSE-S3 mount: %v", got)
		}
	})

	t.Run("multipart upload", func(t *testing.T) {
		data := randomBytes(5<<20 + 1024)
		if err := b.multipart("obj-mp", data, sseKMS(kmsKey1)); err != nil {
			t.Fatal(err)
		}
		evs := h.take()
		if n := count(evs, kmsMount, transhim.OpDataKey); n != 1 {
			t.Errorf("multipart upload caused %d datakey calls, want 1", n)
		}
		// one decrypt per part, at least: all for the same wrapped key
		if n := count(evs, kmsMount, transhim.OpDecrypt); n < 2 {
			t.Errorf("multipart upload caused %d decrypts, want at least one per part", n)
		}
		b.mustGet("obj-mp", data, sseKMS(kmsKey1))
	})

	t.Run("bucket default encryption", func(t *testing.T) {
		b.setDefaultEncryption(sseKMS(kmsKey2))
		h.take()
		b.mustPut("obj-default", small, sseNone)
		evs := h.take()
		if got := ops(evs, kmsMount); !slices.Equal(got, []string{"datakey 200"}) || evs[0].KeyName != kmsKey2 {
			t.Errorf("PutObject without SSE headers caused %v, want one datakey for %s", evs, kmsKey2)
		}
		b.mustGet("obj-default", small, sseKMS(kmsKey2))
	})

	t.Run("key that does not exist", func(t *testing.T) {
		h.take()
		err := b.put("obj-nokey", small, sseKMS("no-such-key"))
		if got := outcome(err); got != "400 InvalidArgument" {
			t.Errorf("PutObject = %s, want 400 InvalidArgument", got)
		}
		if got := ops(h.take(), kmsMount); !slices.Equal(got, []string{"datakey 400"}) {
			t.Errorf("PutObject caused %v, want a failed datakey", got)
		}
		if b.exists("obj-nokey") {
			t.Error("the object was stored although no key was available")
		}
	})

	if !cache {
		// With the cache, the removal takes effect after its TTL (documented).
		t.Run("key removed in the KMS", func(t *testing.T) {
			b.mustPut("obj-gone", small, sseKMS(kmsKey2))
			h.kms.RemoveKey(kmsMount, kmsKey2)
			defer h.kms.AddKey(kmsMount, kmsKey2)
			_, _, err := b.get("obj-gone")
			if got := outcome(err); got != "400 InvalidArgument" {
				t.Errorf("GetObject = %s, want 400 InvalidArgument", got)
			}
		})
	}

	t.Run("DeleteBucket", func(t *testing.T) {
		h.take()
		if err := b.destroy(t.Context()); err != nil {
			t.Fatal(err)
		}
		// SSE-KMS keys are the operator's: RGW must not touch them
		for _, ev := range h.take() {
			if ev.Op == transhim.OpKeyCreate || ev.Op == transhim.OpKeyConfig || ev.Op == transhim.OpKeyDelete {
				t.Errorf("deleting an SSE-KMS bucket caused %s", ev)
			}
		}
	})
}

func testSSES3(t *testing.T, h *harness) {
	small := randomBytes(1024)
	if n := h.store.Len(); n != 0 {
		t.Fatalf("%d bucket keys are stored before the test", n)
	}

	t.Run("life of a bucket", func(t *testing.T) {
		b := h.newBucket(t, "sse")
		h.take()

		b.mustPut("plain", small, sseNone)
		if evs := h.take(); len(evs) != 0 || h.store.Len() != 0 {
			t.Errorf("an unencrypted PutObject caused %v", evs)
		}

		// the first encrypted write creates the bucket's key, then uses it
		b.mustPut("obj1", small, sseS3)
		evs := h.take()
		if got := ops(evs, sseMount); !slices.Equal(got, []string{"key_create 204", "datakey 200"}) {
			t.Fatalf("first PutObject caused %v, want key_create and datakey", got)
		}
		keyName := evs[0].KeyName
		if evs[1].KeyName != keyName || h.store.Len() != 1 {
			t.Errorf("datakey used %q, the key created is %q; %d keys stored", evs[1].KeyName, keyName, h.store.Len())
		}
		if got := ops(evs, kmsMount); len(got) != 0 {
			t.Errorf("SSE-S3 used the SSE-KMS mount: %v", got)
		}

		// later writes use the same key without creating it again
		b.mustPut("obj2", small, sseS3)
		if got := ops(h.take(), sseMount); !slices.Equal(got, []string{"datakey 200"}) {
			t.Errorf("second PutObject caused %v, want only datakey", got)
		}
		b.mustGet("obj1", small, sseS3)
		b.mustGet("obj2", small, sseS3)
		b.mustGet("plain", small, sseNone)
		if got := ops(h.take(), sseMount); !slices.Equal(got, []string{"decrypt 200", "decrypt 200"}) {
			t.Errorf("reading two encrypted objects and a plain one caused %v, want two decrypts", got)
		}

		data := randomBytes(5<<20 + 1024)
		if err := b.multipart("obj-mp", data, sseS3); err != nil {
			t.Fatal(err)
		}
		b.mustGet("obj-mp", data, sseS3)

		b.setDefaultEncryption(sseS3)
		b.mustPut("obj-default", small, sseNone)
		b.mustGet("obj-default", small, sseS3)
		for _, ev := range h.take() {
			if ev.MountID == sseMount && (ev.KeyName != keyName || ev.Op == transhim.OpKeyCreate || ev.Status >= 300) {
				t.Errorf("unexpected call: %s", ev)
			}
		}

		// deleting the bucket deletes its key: config, then DELETE. RGW
		// before tentacle only gets this far because config answers with an
		// empty 204 (docs/compat.md).
		if err := b.destroy(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := ops(h.take(), sseMount); !slices.Equal(got, []string{"key_config 204", "key_delete 204"}) {
			t.Errorf("DeleteBucket caused %v, want key_config and key_delete", got)
		}
		if n := h.store.Len(); n != 0 {
			t.Errorf("%d keys stored after DeleteBucket, want 0: the bucket's key must be shredded", n)
		}
	})

	t.Run("DeleteBucketEncryption keeps old objects readable", func(t *testing.T) {
		b := h.newBucket(t, "unconf")
		h.take()
		b.mustPut("before", small, sseS3)
		created := sseS3Keys(h.take())
		if _, err := h.s3.DeleteBucketEncryption(t.Context(), &s3.DeleteBucketEncryptionInput{Bucket: &b.name}); err != nil {
			t.Fatal(err)
		}
		// RGW forgot the key without deleting it ...
		if got := ops(h.take(), sseMount); len(got) != 0 || h.store.Len() != 1 {
			t.Errorf("DeleteBucketEncryption caused %v; %d keys stored, want none and 1", got, h.store.Len())
		}
		// ... and creates it again under the same name on the next write
		b.mustPut("after", small, sseS3)
		evs := h.take()
		if again := sseS3Keys(evs); !slices.Equal(again, created) || len(created) != 1 {
			t.Errorf("keys created: first %v, then %v; want the same single name", created, again)
		}
		if h.store.Len() != 1 {
			t.Errorf("%d keys stored, want 1", h.store.Len())
		}
		// the existing key must have survived that
		b.mustGet("before", small, sseS3)
		b.mustGet("after", small, sseS3)

		if err := b.destroy(t.Context()); err != nil {
			t.Fatal(err)
		}
		if n := h.store.Len(); n != 0 {
			t.Errorf("%d keys stored after DeleteBucket, want 0", n)
		}
	})

	t.Run("bucket that was never encrypted", func(t *testing.T) {
		b := h.newBucket(t, "unused")
		b.mustPut("plain", small, sseNone)
		h.take()
		if err := b.destroy(t.Context()); err != nil {
			t.Fatal(err)
		}
		if evs := h.take(); len(evs) != 0 {
			t.Errorf("deleting a bucket without a key caused %v", evs)
		}
	})
}

// TestRGWFaults records how RGW reacts when the Transit endpoint fails. The
// point that matters: RGW must never store an object unencrypted, or hand out
// one, because its key service misbehaves.
func TestRGWFaults(t *testing.T) {
	h := newHarness(t, false)
	small := randomBytes(1024)
	b := h.newBucket(t, "faults")
	b.mustPut("existing", small, sseKMS(kmsKey1))

	faults := []struct {
		name string
		f    fault
	}{
		{"403", fault{status: 403, body: `{"errors":["permission denied"]}`}},
		{"500", fault{status: 500, body: `{"errors":["internal error"]}`}},
		{"502", fault{status: 502, body: `{"errors":["upstream key service error"]}`}},
		{"503", fault{status: 503, body: `{"errors":["upstream key service error"]}`}},
		{"200 without data", fault{status: 200, body: `{}`}},
		{"200 that is not JSON", fault{status: 200, body: `<html>`}},
		{"connection reset", fault{reset: true}},
		{"slow (3s)", fault{delay: 3 * time.Second}},
	}
	for _, tt := range faults {
		t.Run(tt.name, func(t *testing.T) {
			slow := tt.f.delay > 0 && tt.f.status == 0 && !tt.f.reset

			f := tt.f
			f.op = "datakey"
			stop := h.inject(f)
			start := time.Now()
			err := b.put("new-"+tt.name, small, sseKMS(kmsKey1))
			stop()
			t.Logf("datakey %s: PutObject = %s (%v)", tt.name, outcome(err), time.Since(start).Round(100*time.Millisecond))
			switch {
			case slow:
				if err != nil {
					t.Errorf("PutObject with a slow datakey failed: %v", err)
				}
			case err == nil:
				t.Error("PutObject succeeded although datakey failed")
			}
			if !slow && b.exists("new-"+tt.name) {
				t.Error("the object was stored although no data key was available")
			}

			f.op = "decrypt"
			stop = h.inject(f)
			start = time.Now()
			data, _, err := b.get("existing")
			stop()
			t.Logf("decrypt %s: GetObject = %s (%v)", tt.name, outcome(err), time.Since(start).Round(100*time.Millisecond))
			switch {
			case slow:
				if err != nil {
					t.Errorf("GetObject with a slow decrypt failed: %v", err)
				}
			case err == nil:
				t.Errorf("GetObject succeeded although decrypt failed; it returned %d bytes", len(data))
			}
		})
	}
	// the endpoint works again: nothing is stuck
	b.mustGet("existing", small, sseKMS(kmsKey1))

	t.Run("SSE-S3 key operations", func(t *testing.T) {
		s := h.newBucket(t, "s3faults")
		stop := h.inject(fault{op: "keys", status: 500, body: `{"errors":["internal error"]}`})
		err := s.put("obj", small, sseS3)
		stop()
		t.Logf("key create 500: PutObject = %s", outcome(err))
		if err == nil || s.exists("obj") {
			t.Errorf("PutObject = %s although the bucket key could not be created", outcome(err))
		}

		s.mustPut("obj", small, sseS3)
		if n := h.store.Len(); n != 1 {
			t.Fatalf("%d keys stored, want 1", n)
		}
		s.h.s3.DeleteObject(t.Context(), &s3.DeleteObjectInput{Bucket: &s.name, Key: new("obj")})
		stop = h.inject(fault{op: "keys", status: 500, body: `{"errors":["internal error"]}`})
		_, err = h.s3.DeleteBucket(t.Context(), &s3.DeleteBucketInput{Bucket: &s.name})
		stop()
		t.Logf("key config/delete 500: DeleteBucket = %s; %d keys left in the store", outcome(err), h.store.Len())
		// RGW removes the bucket whatever the key service says: the key is
		// orphaned (docs/compat.md).
		_, herr := h.s3.HeadBucket(t.Context(), &s3.HeadBucketInput{Bucket: &s.name})
		if err != nil || herr == nil {
			t.Errorf("DeleteBucket = %s, bucket still exists: %v", outcome(err), herr == nil)
		}
		if n := h.store.Len(); n != 1 {
			t.Errorf("%d keys stored, want the orphaned 1", n)
		}
	})
}

// TestRGWEndpointDown: with nothing listening, RGW fails encrypted requests.
func TestRGWEndpointDown(t *testing.T) {
	h := newHarness(t, false)
	b := h.newBucket(t, "down")
	small := randomBytes(1024)
	b.mustPut("existing", small, sseKMS(kmsKey1))
	b.mustPut("plain", small, sseNone)

	h.shutdown()
	err := b.put("new", small, sseKMS(kmsKey1))
	t.Logf("endpoint down: PutObject = %s", outcome(err))
	if err == nil || b.exists("new") {
		t.Errorf("PutObject = %s with the Transit endpoint down", outcome(err))
	}
	_, _, err = b.get("existing")
	t.Logf("endpoint down: GetObject = %s", outcome(err))
	if err == nil {
		t.Error("GetObject of an encrypted object succeeded with the Transit endpoint down")
	}
	// unencrypted objects do not depend on it
	b.mustGet("plain", small, sseNone)
	if _, ok := errors.AsType[smithy.APIError](err); !ok {
		t.Errorf("GetObject failed without an S3 error: %v", err)
	}
}
