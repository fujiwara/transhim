package integration_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fujiwara/transhim"
)

// TestRGWContext records what the context of RGW's requests says about the S3
// object, and how far a server can rely on it (docs/compat.md): it reaches
// authorizers and audit hooks as AuthRequest.Context and AuditEvent.Context.
func TestRGWContext(t *testing.T) {
	h := newHarness(t, false)
	b := h.newBucket(t, "ctx")
	h.take()

	// put writes an object, optionally with an encryption context of the S3
	// client, reads it back, and returns the contexts RGW sent for the write
	// and for the read.
	put := func(t *testing.T, key string, e sse, clientContext string) (write, read map[string]string) {
		t.Helper()
		in := &s3.PutObjectInput{
			Bucket: &b.name, Key: &key, Body: bytes.NewReader([]byte("data")),
			ServerSideEncryption: e.algorithm, SSEKMSKeyId: e.keyIDPtr(),
		}
		if clientContext != "" {
			in.SSEKMSEncryptionContext = new(base64.StdEncoding.EncodeToString([]byte(clientContext)))
		}
		if _, err := h.s3.PutObject(t.Context(), in); err != nil {
			t.Fatalf("PutObject: %s", outcome(err))
		}
		write = contextOf(t, h.take(), transhim.OpDataKey)
		if _, err := h.s3.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &b.name, Key: &key}); err != nil {
			t.Fatalf("GetObject: %s", outcome(err))
		}
		read = contextOf(t, h.take(), transhim.OpDecrypt)
		return write, read
	}
	// wantObject checks that the context names the object the way RGW does:
	// arn:aws:s3::<owner>:<bucket>/<object>
	wantObject := func(t *testing.T, c map[string]string, key string) {
		t.Helper()
		arn := c["aws:s3:arn"]
		if !strings.HasPrefix(arn, "arn:aws:s3::") || !strings.HasSuffix(arn, ":"+b.name+"/"+key) {
			t.Errorf("aws:s3:arn = %q, want the ARN of %s/%s", arn, b.name, key)
		}
	}

	t.Run("SSE-KMS names the object", func(t *testing.T) {
		write, read := put(t, "dir/obj 1", sseKMS(kmsKey1), "")
		wantObject(t, write, "dir/obj 1")
		wantObject(t, read, "dir/obj 1")
		if len(write) != 1 || len(read) != 1 {
			t.Errorf("contexts = %v, %v; want nothing but aws:s3:arn", write, read)
		}
	})

	t.Run("SSE-KMS adds the client's entries", func(t *testing.T) {
		write, read := put(t, "extra", sseKMS(kmsKey1), `{"team":"a"}`)
		wantObject(t, write, "extra")
		wantObject(t, read, "extra")
		if write["team"] != "a" || read["team"] != "a" {
			t.Errorf("contexts = %v, %v; want the client's entry in both", write, read)
		}
	})

	// This is why the context cannot decide what an S3 user may do with
	// SSE-KMS: the user can name any object in it.
	t.Run("SSE-KMS lets the client replace the ARN", func(t *testing.T) {
		const forged = "arn:aws:s3::someone:else/object"
		write, read := put(t, "forged", sseKMS(kmsKey1), `{"aws:s3:arn":"`+forged+`"}`)
		if write["aws:s3:arn"] != forged || read["aws:s3:arn"] != forged {
			t.Errorf("aws:s3:arn = %q on write, %q on read; RGW used to pass on the client's value %q",
				write["aws:s3:arn"], read["aws:s3:arn"], forged)
		}
	})

	t.Run("SSE-S3 names the object", func(t *testing.T) {
		write, read := put(t, "s3", sseS3, "")
		wantObject(t, write, "s3")
		wantObject(t, read, "s3")
		if len(write) != 1 || len(read) != 1 {
			t.Errorf("contexts = %v, %v; want nothing but aws:s3:arn", write, read)
		}
	})

	// With SSE-S3 the client has no say in the context.
	t.Run("SSE-S3 refuses a client context", func(t *testing.T) {
		_, err := h.s3.PutObject(t.Context(), &s3.PutObjectInput{
			Bucket: &b.name, Key: new("s3-forged"), Body: bytes.NewReader([]byte("data")),
			ServerSideEncryption:    sseS3.algorithm,
			SSEKMSEncryptionContext: new(base64.StdEncoding.EncodeToString([]byte(`{"aws:s3:arn":"forged"}`))),
		})
		if got := outcome(err); got != "400 InvalidArgument" {
			t.Errorf("PutObject = %s, want 400 InvalidArgument", got)
		}
		if evs := h.take(); len(evs) != 0 {
			t.Errorf("RGW called the Transit endpoint: %v", evs)
		}
	})
}

// contextOf returns the context of the one event of op in evs, which must be
// a JSON object of strings.
func contextOf(t *testing.T, evs []event, op transhim.Op) map[string]string {
	t.Helper()
	var found []event
	for _, ev := range evs {
		if ev.Op == op {
			found = append(found, ev)
		}
	}
	if len(found) != 1 {
		t.Fatalf("got %d %s requests in %v, want 1", len(found), op, evs)
	}
	var c map[string]string
	if err := json.Unmarshal([]byte(found[0].Context), &c); err != nil {
		t.Fatalf("context %q of %s is not a JSON object of strings: %v", found[0].Context, found[0], err)
	}
	return c
}
