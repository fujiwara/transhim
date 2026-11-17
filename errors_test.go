package transhim

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestErrorResponse(t *testing.T) {
	secret := errors.New("secret detail")
	tests := []struct {
		err    error
		status int
		msg    string
	}{
		{ErrInvalidRequest, 400, "invalid request"},
		{fmt.Errorf("%w: %w", ErrInvalidRequest, secret), 400, "invalid request"},
		{badRequest("missing ciphertext to decrypt"), 400, "missing ciphertext to decrypt"},
		{ErrKeyNotFound, 400, "encryption key not found"},
		{fmt.Errorf("%w: my-key", ErrKeyNotFound), 400, "encryption key not found"},
		{ErrCiphertextMismatch, 400, "invalid ciphertext"},
		{errBadEnvelope, 400, "invalid ciphertext"},
		{ErrPermissionDenied, 403, "permission denied"},
		{fmt.Errorf("token expired: %w", ErrPermissionDenied), 403, "permission denied"},
		{ErrUpstream, 502, "upstream key service error"},
		{fmt.Errorf("%w: %w", ErrUpstream, secret), 502, "upstream key service error"},
		{&UpstreamError{Err: secret}, 502, "upstream key service error"},
		{&UpstreamError{Err: secret, Retryable: true}, 503, "upstream key service error"},
		{fmt.Errorf("wrapped: %w", &UpstreamError{Retryable: true}), 503, "upstream key service error"},
		{secret, 500, "internal error"},
		{&requestError{status: http.StatusNotFound, msg: "unsupported path"}, 404, "unsupported path"},
	}
	for _, tt := range tests {
		status, msg := errorResponse(tt.err)
		if status != tt.status || msg != tt.msg {
			t.Errorf("%v: got %d %q, want %d %q", tt.err, status, msg, tt.status, tt.msg)
		}
	}
}

func TestUpstreamError(t *testing.T) {
	cause := errors.New("throttled")
	err := error(&UpstreamError{Err: cause, Retryable: true})
	if !errors.Is(err, ErrUpstream) || !errors.Is(err, cause) {
		t.Errorf("%v must be both ErrUpstream and its cause", err)
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Error("UpstreamError must not match other sentinels")
	}
	if !errors.Is(badRequest("x"), ErrInvalidRequest) {
		t.Error("a bad request error must be an ErrInvalidRequest")
	}
}
