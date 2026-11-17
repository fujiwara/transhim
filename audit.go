package transhim

import (
	"context"
	"time"
)

// AuditEvent describes one finished request. It never contains key material,
// ciphertexts, or tokens, and of the request body only the context.
type AuditEvent struct {
	// Time is when the request arrived.
	Time time.Time
	// Op is the operation, or "" if the request did not match one.
	Op Op
	// MountID identifies the mount, or "" if the request matched none.
	MountID string
	// KeyName is the key the request named, or "" if it had no valid one.
	KeyName string
	// Context is the decoded "context" of a datakey, encrypt, or decrypt
	// request, or nil. With Ceph RGW it names the S3 object the request is
	// for; see AuthRequest.Context for how far that can be trusted. The hook
	// must not modify it.
	Context []byte
	// CacheHit reports that a decrypt was answered from the decrypt cache.
	CacheHit bool
	// Duration is the time spent serving the request.
	Duration time.Duration
	// Status is the HTTP status of the answer.
	Status int
	// Err is the error that made the request fail, or nil. Unlike the answer
	// sent to the client, it carries the details of backend errors.
	Err error
	// RemoteAddr is the peer address as reported by net/http.
	RemoteAddr string
	// RequestID is the request_id of the answer.
	RequestID string
}

// AuditHook receives an AuditEvent for every request, including rejected ones
// and those that matched no mount. It is called synchronously after the answer
// was written, so it must not block: hand the event to a queue if processing
// it can take time. The context is the request's and may already be canceled.
type AuditHook func(ctx context.Context, ev AuditEvent)
