// Package integration_test is the v1 acceptance test of transhim: a real Ceph
// RGW doing SSE-KMS and SSE-S3 against a transhim server.
//
// It is a module of its own, so that the AWS SDK it needs for talking to RGW
// stays out of transhim's dependencies.
//
// The tests are skipped unless TRANSHIM_TEST_RGW_ENDPOINT is set:
//
//	docker compose up -d --wait ceph
//	cd integration && TRANSHIM_TEST_RGW_ENDPOINT=http://127.0.0.1:7480 go test ./...
//
// RGW is configured (compose.yml) to use the Transit endpoint at
// http://127.0.0.1:8201 with the mounts /v1/transit-kms and
// /v1/transit-sse-s3. The tests start a transhim server there.
package integration_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/hierarchical"
	"github.com/fujiwara/transhim/keystore/memstore"
	"github.com/fujiwara/transhim/transhimtest"
)

const (
	kmsMount = "rgw-kms"
	sseMount = "rgw-sse-s3"
	rootKey  = "root"
	// SSE-KMS keys are provisioned by the operator, not by RGW.
	kmsKey1 = "testkey-1"
	kmsKey2 = "testkey-2"
)

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// event is what the tests look at in an audit event.
type event struct {
	Op      transhim.Op
	MountID string
	KeyName string
	Status  int
	// Context is the context RGW sent, decoded.
	Context string
}

func (e event) String() string {
	return fmt.Sprintf("%s %s/%s => %d", e.Op, e.MountID, e.KeyName, e.Status)
}

// fault makes the Transit endpoint misbehave for the requests it matches.
type fault struct {
	// op is the path element that selects the requests: "datakey",
	// "decrypt", or "keys".
	op string
	// status and body are sent instead of transhim's answer, if status != 0.
	status int
	body   string
	// delay is waited before answering (or before failing).
	delay time.Duration
	// reset closes the connection without an answer.
	reset bool
}

// harness is a transhim server for RGW, plus the means to observe it.
type harness struct {
	kms   *transhimtest.FakeBackend
	root  *transhimtest.FakeBackend
	store *memstore.Store
	s3    *s3.Client

	// shutdown stops the Transit endpoint: nothing listens there afterwards.
	shutdown func()

	mu     sync.Mutex
	events []event
	fault  *fault
}

// newHarness starts a transhim server where RGW expects its Transit endpoint.
// sseOpts configure the hierarchical backend of the SSE-S3 mount.
func newHarness(t *testing.T, decryptCache bool, sseOpts ...hierarchical.Option) *harness {
	t.Helper()
	endpoint := os.Getenv("TRANSHIM_TEST_RGW_ENDPOINT")
	if endpoint == "" {
		t.Skip("TRANSHIM_TEST_RGW_ENDPOINT is not set")
	}
	h := &harness{
		kms:   transhimtest.NewFakeBackend(),
		root:  transhimtest.NewFakeBackend(),
		store: memstore.New(),
	}
	h.kms.AddKey(kmsMount, kmsKey1)
	h.kms.AddKey(kmsMount, kmsKey2)
	h.root.AddKey(sseMount, rootKey)
	sse, err := hierarchical.New(h.root, rootKey, h.store, sseOpts...)
	if err != nil {
		t.Fatal(err)
	}
	opts := []transhim.Option{
		// the mounts and the token of compose.yml
		transhim.Mount("/v1/transit-kms", kmsMount, plainBackend{h.kms}),
		transhim.Mount("/v1/transit-sse-s3", sseMount, sse),
		transhim.WithAuthorizer(transhim.StaticTokenAuthorizer(envOr("VAULT_TOKEN", "transhim-dev-token"))),
		transhim.WithLogger(slog.New(slog.DiscardHandler)),
		transhim.WithAuditHook(func(_ context.Context, ev transhim.AuditEvent) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.events = append(h.events, event{ev.Op, ev.MountID, ev.KeyName, ev.Status, string(ev.Context)})
		}),
	}
	if decryptCache {
		opts = append(opts, transhim.WithDecryptCache(transhim.DecryptCacheConfig{MaxEntries: 1000, TTL: time.Hour}))
	}
	srv, err := transhim.NewServer(opts...)
	if err != nil {
		t.Fatal(err)
	}

	addr := envOr("TRANSHIM_TEST_LISTEN", "127.0.0.1:8201")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen on %s, where RGW expects the Transit endpoint: %v", addr, err)
	}
	hs := &http.Server{Handler: h.withFaults(srv)}
	go hs.Serve(ln)
	h.shutdown = func() { hs.Close() }
	t.Cleanup(h.shutdown)

	h.s3 = s3.New(s3.Options{
		BaseEndpoint: aws.String(endpoint),
		Region:       "us-east-1",
		UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider(
			envOr("TRANSHIM_TEST_RGW_ACCESS_KEY_ID", "backendkey"),
			envOr("TRANSHIM_TEST_RGW_SECRET_ACCESS_KEY", "backendsecret"), ""),
		// the tests look at RGW's first answer, also when it is an error
		RetryMaxAttempts: 1,
		// trailing checksums need TLS, and older RGW releases lack them
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
	return h
}

// plainBackend hides the optional interfaces of the backend it wraps: the
// SSE-KMS mount has no KeyLifecycle, like a KMS with provisioned keys.
type plainBackend struct{ transhim.Backend }

// withFaults applies the current fault, if any, to matching requests.
func (h *harness) withFaults(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		f := h.fault
		h.mu.Unlock()
		if f == nil || !strings.Contains(r.URL.Path, "/"+f.op+"/") {
			next.ServeHTTP(w, r)
			return
		}
		if f.delay > 0 {
			select {
			case <-time.After(f.delay):
			case <-r.Context().Done():
				return
			}
		}
		switch {
		case f.reset:
			panic(http.ErrAbortHandler) // closes the connection
		case f.status != 0:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.status)
			io.WriteString(w, f.body)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// inject makes the Transit endpoint misbehave until the returned function is
// called.
func (h *harness) inject(f fault) (stop func()) {
	h.mu.Lock()
	h.fault = &f
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		h.fault = nil
		h.mu.Unlock()
	}
}

// take returns the events since the last call.
func (h *harness) take() []event {
	h.mu.Lock()
	defer h.mu.Unlock()
	evs := h.events
	h.events = nil
	return evs
}

// ops returns the events of evs for one mount, as "op status" strings.
func ops(evs []event, mountID string) []string {
	var out []string
	for _, ev := range evs {
		if ev.MountID == mountID {
			out = append(out, fmt.Sprintf("%s %d", ev.Op, ev.Status))
		}
	}
	return out
}

func count(evs []event, mountID string, op transhim.Op) int {
	n := 0
	for _, ev := range evs {
		if ev.MountID == mountID && ev.Op == op {
			n++
		}
	}
	return n
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// outcome describes how an S3 call ended: "ok", or the HTTP status and error
// code RGW answered with.
func outcome(err error) string {
	if err == nil {
		return "ok"
	}
	status := 0
	if re, ok := errors.AsType[*awshttp.ResponseError](err); ok {
		status = re.HTTPStatusCode()
	}
	code := "?"
	if ae, ok := errors.AsType[smithy.APIError](err); ok {
		code = ae.ErrorCode()
	}
	if status == 0 {
		return "no answer: " + err.Error()
	}
	return fmt.Sprintf("%d %s", status, code)
}

// bucket is a bucket of its own for one test.
type bucket struct {
	t    *testing.T
	h    *harness
	name string
}

func (h *harness) newBucket(t *testing.T, purpose string) *bucket {
	t.Helper()
	b := &bucket{t: t, h: h, name: fmt.Sprintf("transhim-%s-%x", purpose, randomBytes(4))}
	if _, err := h.s3.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &b.name}); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	// best effort, with a context that outlives the test's
	t.Cleanup(func() { b.destroy(context.Background()) })
	return b
}

// destroy removes the bucket and everything in it.
func (b *bucket) destroy(ctx context.Context) error {
	ups, _ := b.h.s3.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &b.name})
	if ups != nil {
		for _, u := range ups.Uploads {
			b.h.s3.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: &b.name, Key: u.Key, UploadId: u.UploadId})
		}
	}
	list, err := b.h.s3.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &b.name})
	if err != nil {
		if ae, ok := errors.AsType[smithy.APIError](err); ok && ae.ErrorCode() == "NoSuchBucket" {
			return nil
		}
		return err
	}
	for _, o := range list.Contents {
		if _, err := b.h.s3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &b.name, Key: o.Key}); err != nil {
			return err
		}
	}
	_, err = b.h.s3.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &b.name})
	return err
}

// sse says how an object is to be encrypted. The zero value sends no SSE
// headers.
type sse struct {
	algorithm types.ServerSideEncryption
	keyID     string
}

var (
	sseS3   = sse{algorithm: types.ServerSideEncryptionAes256}
	sseNone = sse{}
)

func sseKMS(keyID string) sse {
	return sse{algorithm: types.ServerSideEncryptionAwsKms, keyID: keyID}
}

func (e sse) keyIDPtr() *string {
	if e.keyID == "" {
		return nil
	}
	return &e.keyID
}

func (b *bucket) put(key string, data []byte, enc sse) error {
	_, err := b.h.s3.PutObject(b.t.Context(), &s3.PutObjectInput{
		Bucket: &b.name, Key: &key, Body: bytes.NewReader(data),
		ServerSideEncryption: enc.algorithm, SSEKMSKeyId: enc.keyIDPtr(),
	})
	return err
}

func (b *bucket) mustPut(key string, data []byte, enc sse) {
	b.t.Helper()
	if err := b.put(key, data, enc); err != nil {
		b.t.Fatalf("PutObject %s: %v", key, err)
	}
}

func (b *bucket) get(key string) ([]byte, *s3.GetObjectOutput, error) {
	out, err := b.h.s3.GetObject(b.t.Context(), &s3.GetObjectInput{Bucket: &b.name, Key: &key})
	if err != nil {
		return nil, nil, err
	}
	defer out.Body.Close()
	data, err := io.ReadAll(out.Body)
	return data, out, err
}

// mustGet reads an object and checks its content and how RGW says it is
// encrypted.
func (b *bucket) mustGet(key string, want []byte, enc sse) {
	b.t.Helper()
	data, out, err := b.get(key)
	if err != nil {
		b.t.Fatalf("GetObject %s: %v", key, err)
	}
	if !bytes.Equal(data, want) {
		b.t.Errorf("GetObject %s: got %d bytes that differ from the %d bytes written", key, len(data), len(want))
	}
	if out.ServerSideEncryption != enc.algorithm {
		b.t.Errorf("GetObject %s: encryption = %q, want %q", key, out.ServerSideEncryption, enc.algorithm)
	}
	if enc.keyID != "" && aws.ToString(out.SSEKMSKeyId) != enc.keyID {
		b.t.Errorf("GetObject %s: key ID = %q, want %q", key, aws.ToString(out.SSEKMSKeyId), enc.keyID)
	}
}

func (b *bucket) exists(key string) bool {
	_, err := b.h.s3.HeadObject(b.t.Context(), &s3.HeadObjectInput{Bucket: &b.name, Key: &key})
	return err == nil
}

// multipart uploads data in two parts.
func (b *bucket) multipart(key string, data []byte, enc sse) error {
	ctx := b.t.Context()
	up, err := b.h.s3.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: &b.name, Key: &key,
		ServerSideEncryption: enc.algorithm, SSEKMSKeyId: enc.keyIDPtr(),
	})
	if err != nil {
		return fmt.Errorf("CreateMultipartUpload: %w", err)
	}
	const partSize = 5 << 20 // the minimum for all parts but the last
	var parts []types.CompletedPart
	for n := int32(1); len(data) > 0; n++ {
		part := data[:min(partSize, len(data))]
		data = data[len(part):]
		out, err := b.h.s3.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: &b.name, Key: &key, UploadId: up.UploadId, PartNumber: &n, Body: bytes.NewReader(part),
		})
		if err != nil {
			return fmt.Errorf("UploadPart %d: %w", n, err)
		}
		parts = append(parts, types.CompletedPart{PartNumber: aws.Int32(n), ETag: out.ETag})
	}
	_, err = b.h.s3.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: &b.name, Key: &key, UploadId: up.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	})
	if err != nil {
		return fmt.Errorf("CompleteMultipartUpload: %w", err)
	}
	return nil
}

func (b *bucket) setDefaultEncryption(enc sse) {
	b.t.Helper()
	_, err := b.h.s3.PutBucketEncryption(b.t.Context(), &s3.PutBucketEncryptionInput{
		Bucket: &b.name,
		ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
			Rules: []types.ServerSideEncryptionRule{{
				ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
					SSEAlgorithm: enc.algorithm, KMSMasterKeyID: enc.keyIDPtr(),
				},
			}},
		},
	})
	if err != nil {
		b.t.Fatalf("PutBucketEncryption: %v", err)
	}
}

// sseS3Keys returns the names of the keys RGW created on the SSE-S3 mount in
// evs, without repeats.
func sseS3Keys(evs []event) []string {
	var names []string
	for _, ev := range evs {
		if ev.MountID == sseMount && ev.Op == transhim.OpKeyCreate && !slices.Contains(names, ev.KeyName) {
			names = append(names, ev.KeyName)
		}
	}
	return names
}
