// Package blind computes the names a blinded R2Notary log (M8) gives object keys:
// keyHmac = lowercase hex of HMAC-SHA256(blinding key, UTF-8 key). The blinding key is the log's
// KEY_BLINDING_KEY, shared with readers who may locate entries by key name; it is unpadded
// base64url of at least 32 bytes. Written from the format description; no code is shared with the
// TypeScript writer.
package blind

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// MinKeyBytes is the shortest blinding key the writer accepts.
const MinKeyBytes = 32

// ParseKey decodes a blinding key: unpadded base64url, canonical, at least 32 bytes.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, errors.New("blinding key must be unpadded base64url")
	}
	if len(b) < MinKeyBytes {
		return nil, errors.New("blinding key must be at least 32 bytes")
	}
	return b, nil
}

// Name returns the keyHmac a blinded log uses for objectKey.
func Name(key []byte, objectKey string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(objectKey))
	return hex.EncodeToString(m.Sum(nil))
}
