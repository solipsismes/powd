package token

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Whole-second times everywhere: token expiries have second resolution.
var (
	now = time.Unix(1_720_000_000, 0)
	ttl = 2 * time.Minute
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := New(bytesSecret(0))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// bytesSecret returns a deterministic secret seeded with b.
func bytesSecret(b byte) []byte {
	secret := make([]byte, SecretLen)
	for i := range secret {
		secret[i] = b + byte(i)
	}
	return secret
}

// sign returns payload plus a valid MAC for it — used to forge tokens that
// authenticate but carry hostile payloads.
func sign(s *Signer, prefix, payload string) string {
	return payload + "." + hex.EncodeToString(s.mac(prefix, payload))
}

func TestNewRejectsWrongSecretLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := New(make([]byte, n)); err == nil {
			t.Errorf("New accepted a %d-byte secret", n)
		}
	}
}

func TestChallengeRoundTrip(t *testing.T) {
	s := testSigner(t)
	tok := s.MintChallenge(now, ttl, 18)

	c, err := s.VerifyChallenge(now, tok)
	if err != nil {
		t.Fatalf("VerifyChallenge: %v", err)
	}
	if !c.Expiry.Equal(now.Add(ttl)) {
		t.Errorf("Expiry = %v, want %v", c.Expiry, now.Add(ttl))
	}
	if c.Difficulty != 18 {
		t.Errorf("Difficulty = %d, want 18", c.Difficulty)
	}
	if len(c.Rand) != 32 {
		t.Errorf("Rand = %q, want 32 hex chars", c.Rand)
	}
	if _, err := hex.DecodeString(c.Rand); err != nil {
		t.Errorf("Rand is not hex: %q", c.Rand)
	}
}

func TestChallengeUniqueness(t *testing.T) {
	s := testSigner(t)
	if s.MintChallenge(now, ttl, 18) == s.MintChallenge(now, ttl, 18) {
		t.Error("two challenges minted with identical parameters are equal")
	}
}

func TestChallengeExpiry(t *testing.T) {
	s := testSigner(t)
	tok := s.MintChallenge(now, ttl, 18)

	// Valid at the expiry instant itself, expired one second later.
	if _, err := s.VerifyChallenge(now.Add(ttl), tok); err != nil {
		t.Errorf("at expiry: %v, want valid", err)
	}
	if _, err := s.VerifyChallenge(now.Add(ttl+time.Second), tok); !errors.Is(err, ErrExpired) {
		t.Errorf("past expiry: %v, want ErrExpired", err)
	}
}

func TestChallengeTamper(t *testing.T) {
	s := testSigner(t)
	tok := s.MintChallenge(now, ttl, 18)
	f := strings.Split(tok, ".")
	if len(f) != 5 {
		t.Fatalf("token has %d fields: %q", len(f), tok)
	}

	// Rewriting any single field must break authentication.
	tampered := map[string][]string{
		"version":    {"powd2", f[1], f[2], f[3], f[4]},
		"expiry":     {f[0], "9999999999", f[2], f[3], f[4]},
		"difficulty": {f[0], f[1], "1", f[3], f[4]},
		"rand":       {f[0], f[1], f[2], strings.Repeat("0", 32), f[4]},
		"mac":        {f[0], f[1], f[2], f[3], strings.Repeat("0", 64)},
	}
	for name, fields := range tampered {
		if _, err := s.VerifyChallenge(now, strings.Join(fields, ".")); !errors.Is(err, ErrBadToken) {
			t.Errorf("tampered %s: %v, want ErrBadToken", name, err)
		}
	}
}

func TestChallengeWrongSecret(t *testing.T) {
	s := testSigner(t)
	other, _ := New(bytesSecret(100))
	if _, err := other.VerifyChallenge(now, s.MintChallenge(now, ttl, 18)); !errors.Is(err, ErrBadToken) {
		t.Errorf("wrong secret: %v, want ErrBadToken", err)
	}
}

func TestChallengeMalformed(t *testing.T) {
	s := testSigner(t)
	for _, tok := range []string{
		"",
		".",
		"powd1",
		"junk-without-dots",
		"powd1.123.18.abcd.zz-not-hex",
	} {
		if _, err := s.VerifyChallenge(now, tok); !errors.Is(err, ErrBadToken) {
			t.Errorf("VerifyChallenge(%q) = %v, want ErrBadToken", tok, err)
		}
	}
}

// Forged payloads with valid MACs: the parse code behind the MAC check
// must still reject anything it does not recognise.
func TestChallengeHostileSignedPayloads(t *testing.T) {
	s := testSigner(t)
	for _, payload := range []string{
		"powd2.1720000120.18.00000000000000000000000000000000", // unknown version
		"powd1.notanumber.18.00000000000000000000000000000000", // bad expiry
		"powd1.1720000120.xx.00000000000000000000000000000000", // bad difficulty
		"powd1.1720000120.18",          // too few fields
		"powd1.1720000120.18.aa.extra", // too many fields
	} {
		if _, err := s.VerifyChallenge(now, sign(s, challengePrefix, payload)); !errors.Is(err, ErrBadToken) {
			t.Errorf("payload %q: %v, want ErrBadToken", payload, err)
		}
	}
}

func TestCookieRoundTrip(t *testing.T) {
	s := testSigner(t)
	for _, binding := range []string{"-", Binding("Mozilla/5.0", "203.0.113.0")} {
		value := s.MintCookie(now, 24*time.Hour, binding)
		if err := s.VerifyCookie(now, value, binding); err != nil {
			t.Errorf("binding %q: %v, want valid", binding, err)
		}
	}
}

func TestCookieWrongBinding(t *testing.T) {
	s := testSigner(t)
	value := s.MintCookie(now, 24*time.Hour, Binding("Mozilla/5.0", ""))

	for _, wrong := range []string{Binding("curl/8.0", ""), "-", ""} {
		if err := s.VerifyCookie(now, value, wrong); !errors.Is(err, ErrBadToken) {
			t.Errorf("binding %q: %v, want ErrBadToken", wrong, err)
		}
	}
}

func TestCookieExpiry(t *testing.T) {
	s := testSigner(t)
	value := s.MintCookie(now, 24*time.Hour, "-")

	if err := s.VerifyCookie(now.Add(24*time.Hour), value, "-"); err != nil {
		t.Errorf("at expiry: %v, want valid", err)
	}
	if err := s.VerifyCookie(now.Add(24*time.Hour+time.Second), value, "-"); !errors.Is(err, ErrExpired) {
		t.Errorf("past expiry: %v, want ErrExpired", err)
	}
}

func TestCookieTamper(t *testing.T) {
	s := testSigner(t)
	value := s.MintCookie(now, 24*time.Hour, "-")
	f := strings.Split(value, ".")
	if len(f) != 4 {
		t.Fatalf("cookie has %d fields: %q", len(f), value)
	}

	tampered := map[string][]string{
		"version": {"v2", f[1], f[2], f[3]},
		"expiry":  {f[0], "9999999999", f[2], f[3]},
		"binding": {f[0], f[1], "0123456789abcdef", f[3]},
		"mac":     {f[0], f[1], f[2], strings.Repeat("0", 64)},
	}
	for name, fields := range tampered {
		if err := s.VerifyCookie(now, strings.Join(fields, "."), "-"); !errors.Is(err, ErrBadToken) {
			t.Errorf("tampered %s: %v, want ErrBadToken", name, err)
		}
	}
}

// A token of one type must never verify as the other, even when an
// attacker reshapes a signed payload. The domain-separation prefixes make
// the MACs incompatible regardless of payload shape.
func TestDomainSeparation(t *testing.T) {
	s := testSigner(t)

	if err := s.VerifyCookie(now, s.MintChallenge(now, ttl, 18), "-"); !errors.Is(err, ErrBadToken) {
		t.Errorf("challenge verified as cookie: %v", err)
	}
	if _, err := s.VerifyChallenge(now, s.MintCookie(now, ttl, "-")); !errors.Is(err, ErrBadToken) {
		t.Errorf("cookie verified as challenge: %v", err)
	}

	// A cookie-shaped payload signed with the challenge prefix must fail
	// cookie verification: shape alone is not enough.
	forged := sign(s, challengePrefix, "v1.1720086400.-")
	if err := s.VerifyCookie(now, forged, "-"); !errors.Is(err, ErrBadToken) {
		t.Errorf("cross-domain forgery verified: %v", err)
	}
}

func TestBinding(t *testing.T) {
	if got := Binding("", ""); got != "-" {
		t.Errorf(`Binding("", "") = %q, want "-"`, got)
	}
	b := Binding("Mozilla/5.0", "203.0.113.0")
	if len(b) != 16 {
		t.Errorf("Binding = %q, want 16 hex chars", b)
	}
	if b != Binding("Mozilla/5.0", "203.0.113.0") {
		t.Error("Binding is not deterministic")
	}
	if b == Binding("curl/8.0", "203.0.113.0") || b == Binding("Mozilla/5.0", "198.51.100.0") {
		t.Error("Binding does not distinguish inputs")
	}
	// The two components must not be confusable with each other.
	if Binding("a", "b") == Binding("a\nb", "") {
		t.Error("Binding components can be shifted between fields")
	}
}

func TestLoadSecretCreates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")

	created, err := LoadSecret(path)
	if err != nil {
		t.Fatalf("LoadSecret (create): %v", err)
	}
	if len(created) != SecretLen {
		t.Fatalf("secret is %d bytes, want %d", len(created), SecretLen)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("secret file mode = %o, want 600", mode)
	}

	reloaded, err := LoadSecret(path)
	if err != nil {
		t.Fatalf("LoadSecret (reload): %v", err)
	}
	if hex.EncodeToString(created) != hex.EncodeToString(reloaded) {
		t.Error("reloaded secret differs from created secret")
	}
}

func TestLoadSecretRejectsBadFiles(t *testing.T) {
	for name, content := range map[string]string{
		"empty":     "",
		"not hex":   strings.Repeat("zz", SecretLen) + "\n",
		"too short": strings.Repeat("ab", SecretLen-1) + "\n",
		"too long":  strings.Repeat("ab", SecretLen+1) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadSecret(path); err == nil {
				t.Error("LoadSecret accepted a malformed secret file")
			}
		})
	}
}

func TestRandomSecret(t *testing.T) {
	a, b := RandomSecret(), RandomSecret()
	if len(a) != SecretLen {
		t.Errorf("len = %d, want %d", len(a), SecretLen)
	}
	if hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Error("two RandomSecret calls returned the same bytes")
	}
}
