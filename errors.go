package transhim

import (
	"errors"
	"net/http"
)

// Sentinel errors. Backends and authorizers return errors that wrap these, and
// the server maps them to Vault-style responses.
var (
	// ErrInvalidRequest is answered with 400.
	ErrInvalidRequest = errors.New("invalid request")
	// ErrKeyNotFound is answered with 400 "encryption key not found", as
	// Vault does.
	ErrKeyNotFound = errors.New("encryption key not found")
	// ErrCiphertextMismatch means that a ciphertext did not verify: wrong key
	// name, wrong context, or tampered data. It is answered with 400
	// "invalid ciphertext", without detail.
	ErrCiphertextMismatch = errors.New("invalid ciphertext")
	// ErrPermissionDenied is answered with 403.
	ErrPermissionDenied = errors.New("permission denied")
	// ErrUpstream means that the key service behind the backend failed. It is
	// answered with 502, or with 503 if it is an UpstreamError marked
	// Retryable.
	ErrUpstream = errors.New("upstream key service error")
)

// UpstreamError is an ErrUpstream that can say whether retrying may help
// (throttling, temporary unavailability).
type UpstreamError struct {
	// Err is the underlying error. It is logged, never sent to the client.
	Err error
	// Retryable makes the server answer 503 instead of 502.
	Retryable bool
}

func (e *UpstreamError) Error() string {
	if e.Err == nil {
		return ErrUpstream.Error()
	}
	return ErrUpstream.Error() + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *UpstreamError) Unwrap() error { return e.Err }

// Is reports that an UpstreamError is an ErrUpstream.
func (e *UpstreamError) Is(target error) bool { return target == ErrUpstream }

// requestError is an error made by the server itself whose message is safe to
// show to the client.
type requestError struct {
	status int
	msg    string
}

func (e *requestError) Error() string { return e.msg }

func (e *requestError) Is(target error) bool {
	return e.status == http.StatusBadRequest && target == ErrInvalidRequest
}

func badRequest(msg string) error {
	return &requestError{status: http.StatusBadRequest, msg: msg}
}

// errorResponse maps an error to the status and message sent to the client.
// The message never contains details of errors that come from a backend.
func errorResponse(err error) (status int, msg string) {
	if re, ok := errors.AsType[*requestError](err); ok {
		return re.status, re.msg
	}
	switch {
	case errors.Is(err, ErrKeyNotFound):
		return http.StatusBadRequest, ErrKeyNotFound.Error()
	case errors.Is(err, ErrCiphertextMismatch):
		return http.StatusBadRequest, ErrCiphertextMismatch.Error()
	case errors.Is(err, ErrInvalidRequest):
		return http.StatusBadRequest, ErrInvalidRequest.Error()
	case errors.Is(err, ErrPermissionDenied):
		return http.StatusForbidden, ErrPermissionDenied.Error()
	case errors.Is(err, ErrUpstream):
		if ue, ok := errors.AsType[*UpstreamError](err); ok && ue.Retryable {
			return http.StatusServiceUnavailable, ErrUpstream.Error()
		}
		return http.StatusBadGateway, ErrUpstream.Error()
	}
	return http.StatusInternalServerError, "internal error"
}
