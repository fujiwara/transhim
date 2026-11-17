package transhim

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	envelopePrefix        = "vault:v"
	envelopeFormatVersion = 0x01
	aadPrefix             = "transhim/v1"
)

// errBadEnvelope is deliberately without detail: it is reported to clients as
// ErrCiphertextMismatch.
var errBadEnvelope = fmt.Errorf("%w: malformed envelope", ErrCiphertextMismatch)

// encodeEnvelope builds the client-visible ciphertext string:
//
//	vault:v{N}:{base64std(payload)}
//
// where payload is
//
//	byte    format version (0x01)
//	byte    flags (reserved, 0)
//	uvarint len(keyRef) | keyRef
//	uvarint len(blob)   | blob
func encodeEnvelope(wk WrappedKey) string {
	payload := make([]byte, 0, 2+2*binary.MaxVarintLen64+len(wk.KeyRef)+len(wk.Blob))
	payload = append(payload, envelopeFormatVersion, 0)
	payload = binary.AppendUvarint(payload, uint64(len(wk.KeyRef)))
	payload = append(payload, wk.KeyRef...)
	payload = binary.AppendUvarint(payload, uint64(len(wk.Blob)))
	payload = append(payload, wk.Blob...)
	return envelopePrefix + strconv.Itoa(keyVersion(wk)) + ":" + base64.StdEncoding.EncodeToString(payload)
}

// keyVersion is the version shown to clients: at least 1.
func keyVersion(wk WrappedKey) int {
	return max(wk.Version, 1)
}

// decodeEnvelope parses a ciphertext string made by encodeEnvelope. Any
// failure is an ErrCiphertextMismatch.
func decodeEnvelope(s string) (WrappedKey, error) {
	rest, ok := strings.CutPrefix(s, envelopePrefix)
	if !ok {
		return WrappedKey{}, errBadEnvelope
	}
	ver, b64, ok := strings.Cut(rest, ":")
	if !ok {
		return WrappedKey{}, errBadEnvelope
	}
	// strict decimal: no sign, no leading zero
	version, err := strconv.Atoi(ver)
	if err != nil || version < 1 || strconv.Itoa(version) != ver {
		return WrappedKey{}, errBadEnvelope
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil {
		return WrappedKey{}, errBadEnvelope
	}
	if len(payload) < 2 || payload[0] != envelopeFormatVersion || payload[1] != 0 {
		return WrappedKey{}, errBadEnvelope
	}
	payload = payload[2:]
	keyRef, payload, err := readField(payload)
	if err != nil {
		return WrappedKey{}, err
	}
	blob, payload, err := readField(payload)
	if err != nil {
		return WrappedKey{}, err
	}
	if len(payload) != 0 {
		return WrappedKey{}, errBadEnvelope
	}
	wk := WrappedKey{KeyRef: string(keyRef), Version: version, Blob: blob}
	// Accept the canonical encoding only (it rules out non-minimal varints),
	// so that one ciphertext has exactly one string form.
	if encodeEnvelope(wk) != s {
		return WrappedKey{}, errBadEnvelope
	}
	return wk, nil
}

// readField reads one length-prefixed field and returns it with the rest.
func readField(b []byte) (field, rest []byte, err error) {
	n, size := binary.Uvarint(b)
	if size <= 0 || n > uint64(len(b)-size) {
		return nil, nil, errBadEnvelope
	}
	b = b[size:]
	return b[:n], b[n:], nil
}

// buildAAD computes the value every backend call must bind:
//
//	"transhim/v1" || 0x00 || mount_id || 0x00 || key_name || 0x00 || context
//
// mount_id and key_name cannot contain NUL (both are validated), so the
// encoding is unambiguous even though context is arbitrary bytes.
func buildAAD(mountID, keyName string, context []byte) []byte {
	aad := make([]byte, 0, len(aadPrefix)+len(mountID)+len(keyName)+len(context)+3)
	aad = append(aad, aadPrefix...)
	aad = append(aad, 0)
	aad = append(aad, mountID...)
	aad = append(aad, 0)
	aad = append(aad, keyName...)
	aad = append(aad, 0)
	aad = append(aad, context...)
	return aad
}

// validateKeyName checks a key name after it was URL-unescaped once. Key names
// are opaque strings, but must not be empty and must not contain '/' or
// control characters.
func validateKeyName(name string) error {
	if name == "" {
		return errors.New("empty key name")
	}
	if strings.Contains(name, "/") {
		return errors.New("key name must not contain '/'")
	}
	if hasControl(name) {
		return errors.New("key name must not contain control characters")
	}
	return nil
}

// hasControl reports whether s contains a control character (C0 including NUL,
// DEL, or C1). Invalid UTF-8 counts as well.
func hasControl(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return true
		}
	}
	return false
}
