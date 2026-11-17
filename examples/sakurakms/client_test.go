package sakurakms_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// client sends Transit requests to a handler.
type client struct {
	t       *testing.T
	handler http.Handler
	token   string
}

// do sends a request and returns the string fields of the answer's data.
func (c *client) do(method, path, body string, wantStatus int) map[string]string {
	c.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-Vault-Token", c.token)
	w := httptest.NewRecorder()
	c.handler.ServeHTTP(w, req)
	if w.Code != wantStatus {
		c.t.Fatalf("%s %s: got %d %q, want %d", method, path, w.Code, w.Body.String(), wantStatus)
	}
	var out struct {
		Data map[string]any `json:"data"`
	}
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			c.t.Fatalf("%s %s: %v", method, path, err)
		}
	}
	fields := map[string]string{}
	for k, v := range out.Data {
		if s, ok := v.(string); ok {
			fields[k] = s
		}
	}
	return fields
}
