package transhim

import (
	"context"
	"time"
)

// AuditEvent describes one finished request. It never contains key material,
// ciphertexts, tokens, or request bodies.
type AuditEvent struct {
	// Time is when the request arrived.
	Time time.Time
	// Op is the operation, or "" if the request did not match one.
	Op Op
	// MountID identifies the mount, or "" if the request matched none.
	MountID string
	// KeyName is the key the request named, or "" if it had no valid one.
	KeyName string
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
