package transhim

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// DefaultMaxPlaintextSize is the default limit for the decoded plaintext of an
// encrypt request. Many cloud KMS encrypt APIs cap at 4 KiB.
const DefaultMaxPlaintextSize = 4096

type mount struct {
	prefix           string
	id               string
	backend          Backend
	maxPlaintextSize int
}

// MountOption configures a single mount.
type MountOption func(*mount) error

// WithMaxPlaintextSize sets the largest plaintext, in bytes after base64
// decoding, that the encrypt endpoint of the mount accepts. The default is
// DefaultMaxPlaintextSize.
func WithMaxPlaintextSize(n int) MountOption {
	return func(m *mount) error {
		if n <= 0 {
			return errors.New("max plaintext size must be positive")
		}
		m.maxPlaintextSize = n
		return nil
	}
}

// Mount serves the Transit API under prefix (for example "/v1/transit"),
// backed by backend.
//
// The prefix is used for HTTP routing only and must match the client's prefix
// setting. It can be changed at any time.
//
// The mount ID identifies the mount everywhere else: in backend requests, in
// authorization requests, and in the data bound to every ciphertext. It is
// required, must not contain control characters, and must be unique within a
// server. Changing the mount ID makes every existing ciphertext of the mount
// undecryptable.
func Mount(prefix, mountID string, backend Backend, opts ...MountOption) Option {
	return func(c *config) error {
		p, err := normalizePrefix(prefix)
		if err != nil {
			return fmt.Errorf("mount %q: %w", prefix, err)
		}
		if mountID == "" {
			return fmt.Errorf("mount %q: mount ID must not be empty", prefix)
		}
		if hasControl(mountID) {
			return fmt.Errorf("mount %q: mount ID must not contain control characters", prefix)
		}
		if backend == nil {
			return fmt.Errorf("mount %q: backend must not be nil", prefix)
		}
		m := &mount{prefix: p, id: mountID, backend: backend, maxPlaintextSize: DefaultMaxPlaintextSize}
		for _, opt := range opts {
			if err := opt(m); err != nil {
				return fmt.Errorf("mount %q: %w", prefix, err)
			}
		}
		for _, other := range c.mounts {
			if other.prefix == m.prefix {
				return fmt.Errorf("mount %q: prefix is already mounted", prefix)
			}
			if other.id == m.id {
				return fmt.Errorf("mount %q: mount ID %q is already used by %q", prefix, mountID, other.prefix)
			}
		}
		c.mounts = append(c.mounts, m)
		return nil
	}
}

// normalizePrefix returns prefix with a single leading '/' and no trailing
// '/'. The result must be usable as is in a URL path, because routing compares
// it with the escaped request path.
func normalizePrefix(prefix string) (string, error) {
	p := strings.Trim(prefix, "/")
	if p == "" {
		return "", errors.New("prefix must not be empty")
	}
	p = "/" + p
	if strings.Contains(p, "//") {
		return "", errors.New("prefix must not contain empty path segments")
	}
	if (&url.URL{Path: p}).EscapedPath() != p || strings.ContainsAny(p, "?#") {
		return "", errors.New("prefix must not contain characters that need URL escaping")
	}
	return p, nil
}
