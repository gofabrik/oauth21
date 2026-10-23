package oauth21

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"strings"
)

// SecretHasher hashes Client secrets for the Client Store and verifies secrets against those hashes.
type SecretHasher interface {
	Hash(secret string) (string, error)
	// Verify reports whether secret matches hash, comparing in constant time.
	Verify(hash, secret string) bool
}

// pbkdf2Prefix starts every hash PBKDF2 makes.
const pbkdf2Prefix = "$pbkdf2-sha256$"

// PBKDF2 is the default SecretHasher: PBKDF2-HMAC-SHA256 in the format $pbkdf2-sha256$<iterations>$<salt>$<key>.
type PBKDF2 struct {
	// Iterations defaults to 600000.
	Iterations int
}

// Hash returns the hash of secret with a fresh 16-byte salt.
func (p PBKDF2) Hash(secret string) (string, error) {
	iterations := p.Iterations
	if iterations <= 0 {
		iterations = 600000
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, secret, salt, iterations, sha256.Size)
	if err != nil {
		return "", err
	}
	return pbkdf2Prefix + strconv.Itoa(iterations) + "$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}

// Verify reports whether secret matches hash, comparing in constant time.
func (PBKDF2) Verify(hash, secret string) bool {
	rest, ok := strings.CutPrefix(hash, pbkdf2Prefix)
	if !ok {
		return false
	}
	parts := strings.Split(rest, "$")
	if len(parts) != 3 {
		return false
	}
	iterations, err := strconv.Atoi(parts[0])
	if err != nil || iterations <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, secret, salt, iterations, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}
