// Package token mints and verifies powd's two self-authenticating token
// types: challenges and cookies. Both are plain dot-separated text with a
// trailing hex HMAC-SHA256, so the server needs no storage to trust them
// and a human can read one off the wire.
//
//	challenge: powd1.<expiry>.<difficulty>.<rand>.<mac>
//	cookie:    v1.<expiry>.<binding>.<mac>
//
// Every MAC is computed over a domain-separation prefix plus the payload,
// so a challenge can never be replayed as a cookie or vice versa. This is
// the only package in powd that touches the secret.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// SecretLen is the required secret size in bytes.
const SecretLen = 32

// Domain-separation prefixes, one per MAC purpose.
const (
	challengePrefix = "powd/challenge\n"
	cookiePrefix    = "powd/cookie\n"
	bindPrefix      = "powd/bind\n"
)

const (
	challengeVersion = "powd1"
	cookieVersion    = "v1"
)

var (
	// ErrBadToken covers everything that makes a token untrustworthy:
	// wrong shape, wrong version, or a MAC that does not verify.
	ErrBadToken = errors.New("invalid token")
	// ErrExpired means the token was authentic but past its expiry.
	ErrExpired = errors.New("token expired")
)

// Signer mints and verifies tokens under one HMAC secret.
type Signer struct {
	secret []byte
}

// New returns a Signer for a SecretLen-byte secret.
func New(secret []byte) (*Signer, error) {
	if len(secret) != SecretLen {
		return nil, fmt.Errorf("secret must be %d bytes, got %d", SecretLen, len(secret))
	}
	return &Signer{secret: secret}, nil
}

// Challenge holds the authenticated fields of a verified challenge token.
type Challenge struct {
	Expiry     time.Time
	Difficulty int    // required leading zero bits
	Rand       string // 32 hex chars, unique per challenge; the replay-cache key
}

// MintChallenge returns a fresh challenge token expiring at now+ttl.
func (s *Signer) MintChallenge(now time.Time, ttl time.Duration, difficulty int) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	payload := fmt.Sprintf("%s.%d.%d.%s",
		challengeVersion, now.Add(ttl).Unix(), difficulty, hex.EncodeToString(b[:]))
	return payload + "." + hex.EncodeToString(s.mac(challengePrefix, payload))
}

// VerifyChallenge authenticates tok and returns its fields. The MAC is
// checked before any field is interpreted; everything after that check
// operates on server-issued data.
func (s *Signer) VerifyChallenge(now time.Time, tok string) (Challenge, error) {
	payload, ok := s.checkMAC(challengePrefix, tok)
	if !ok {
		return Challenge{}, ErrBadToken
	}
	f := strings.Split(payload, ".")
	if len(f) != 4 || f[0] != challengeVersion {
		return Challenge{}, ErrBadToken
	}
	expiry, err1 := strconv.ParseInt(f[1], 10, 64)
	difficulty, err2 := strconv.Atoi(f[2])
	if err1 != nil || err2 != nil {
		return Challenge{}, ErrBadToken
	}
	c := Challenge{Expiry: time.Unix(expiry, 0), Difficulty: difficulty, Rand: f[3]}
	if now.After(c.Expiry) {
		return Challenge{}, ErrExpired
	}
	return c, nil
}

// Binding derives the client-binding field stored in a cookie. The caller
// passes whichever request properties the configuration enables; a
// disabled property is the empty string. With no properties at all the
// field is the literal "-": an unbound cookie is explicit about it.
//
// The value is a truncated hash: nothing about the client is recoverable
// from a cookie. It is a hurdle against cookie sharing, not an identity —
// the MAC provides the actual integrity.
func Binding(ua, ipPrefix string) string {
	if ua == "" && ipPrefix == "" {
		return "-"
	}
	sum := sha256.Sum256([]byte(bindPrefix + ua + "\n" + ipPrefix))
	return hex.EncodeToString(sum[:8])
}

// MintCookie returns a signed cookie value expiring at now+ttl, bound to
// the given Binding value.
func (s *Signer) MintCookie(now time.Time, ttl time.Duration, binding string) string {
	payload := fmt.Sprintf("%s.%d.%s", cookieVersion, now.Add(ttl).Unix(), binding)
	return payload + "." + hex.EncodeToString(s.mac(cookiePrefix, payload))
}

// VerifyCookie authenticates value and requires that the binding inside
// the cookie equals the one recomputed from the live request. Bindings are
// derived from attacker-visible request data, so a constant-time compare
// is not needed for them; the MAC compare is constant-time.
func (s *Signer) VerifyCookie(now time.Time, value, binding string) error {
	payload, ok := s.checkMAC(cookiePrefix, value)
	if !ok {
		return ErrBadToken
	}
	f := strings.Split(payload, ".")
	if len(f) != 3 || f[0] != cookieVersion {
		return ErrBadToken
	}
	expiry, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return ErrBadToken
	}
	if f[2] != binding {
		return ErrBadToken
	}
	if now.After(time.Unix(expiry, 0)) {
		return ErrExpired
	}
	return nil
}

// mac returns HMAC-SHA256(secret, prefix||payload).
func (s *Signer) mac(prefix, payload string) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(prefix))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// checkMAC splits tok into payload and MAC at the last '.' and verifies
// the MAC in constant time. On success the returned payload is trusted.
func (s *Signer) checkMAC(prefix, tok string) (payload string, ok bool) {
	i := strings.LastIndexByte(tok, '.')
	if i < 0 {
		return "", false
	}
	payload = tok[:i]
	got, err := hex.DecodeString(tok[i+1:])
	if err != nil {
		return "", false
	}
	if !hmac.Equal(got, s.mac(prefix, payload)) {
		return "", false
	}
	return payload, true
}

// RandomSecret returns a fresh random secret.
func RandomSecret() []byte {
	b := make([]byte, SecretLen)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// LoadSecret returns the hex-encoded secret stored at path, creating the
// file with a fresh secret and mode 0600 if it does not exist. Creation
// uses O_EXCL so that two instances booting at once against a shared
// secret file converge on whichever one wins.
func LoadSecret(path string) ([]byte, error) {
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			secret, derr := hex.DecodeString(strings.TrimSpace(string(data)))
			if derr != nil || len(secret) != SecretLen {
				return nil, fmt.Errorf("%s: expected %d hex-encoded secret bytes", path, SecretLen)
			}
			return secret, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue // another instance created it first; read theirs
		}
		if err != nil {
			return nil, err
		}
		secret := RandomSecret()
		_, werr := f.WriteString(hex.EncodeToString(secret) + "\n")
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return nil, werr
		}
		return secret, nil
	}
}
