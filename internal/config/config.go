// Package config loads powd's configuration file.
//
// The file format is a deliberately small subset of TOML, so that the
// parser itself stays short enough to audit in one sitting: flat
// "key = value" statements where a value is a double-quoted string, an
// integer, a boolean, or an array of double-quoted strings. Comments start
// with '#'. Arrays may span multiple lines and may end with a trailing
// comma. That is the entire grammar — tables, nesting, floats and dates
// are deliberately unsupported.
//
// Unknown and duplicate keys are errors, not warnings: a typo must fail at
// boot, never run silently with a default.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

// Config holds the complete, validated runtime configuration.
type Config struct {
	Listen         string        // address to listen on, e.g. ":8081"
	Upstream       *url.URL      // application server requests are proxied to
	Difficulty     int           // required leading zero bits in a solution hash
	CookieAge      time.Duration // lifetime of an issued cookie
	ChallengeAge   time.Duration // lifetime of an issued challenge
	SecretFile     string        // optional path to the persistent HMAC secret
	BindUA         bool          // bind cookies to the User-Agent header
	BindIP         bool          // bind cookies to the client's IP prefix
	InsecureCookie bool          // omit the Secure cookie attribute (testing only)
	Protect        []string      // path prefixes that require proof of work
	Exclude        []string      // path prefixes exempt from protection
}

func defaults() *Config {
	return &Config{
		Difficulty:   18,
		CookieAge:    24 * time.Hour,
		ChallengeAge: 2 * time.Minute,
		BindUA:       true,
		Protect:      []string{"/"},
	}
}

// Load reads and parses the configuration file at path.
func Load(path string) (*Config, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(string(src))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse parses configuration text and validates the result.
func Parse(src string) (*Config, error) {
	cfg := defaults()
	seen := make(map[string]bool)

	lines, err := logicalLines(src)
	if err != nil {
		return nil, err
	}
	for _, ln := range lines {
		key, val, err := parseStatement(ln)
		if err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, errf(ln.num, "duplicate key %q", key)
		}
		seen[key] = true
		if err := cfg.set(ln.num, key, val); err != nil {
			return nil, err
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("missing required key %q", "listen")
	}
	if c.Upstream == nil {
		return fmt.Errorf("missing required key %q", "upstream")
	}
	if c.Difficulty < 1 || c.Difficulty > 32 {
		return fmt.Errorf("difficulty must be between 1 and 32 leading zero bits")
	}
	if c.CookieAge <= 0 {
		return fmt.Errorf("cookie_age must be positive")
	}
	if c.ChallengeAge <= 0 {
		return fmt.Errorf("challenge_age must be positive")
	}
	// Entries are normalized ("/blog/" → "/blog") so that segment-aware
	// prefix matching can assume clean paths.
	for i, p := range c.Protect {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("protect: path %q must start with '/'", p)
		}
		c.Protect[i] = path.Clean(p)
	}
	for i, p := range c.Exclude {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("exclude: path %q must start with '/'", p)
		}
		c.Exclude[i] = path.Clean(p)
	}
	return nil
}

// set assigns one parsed value to its field, checking the value's type.
func (c *Config) set(line int, key string, v any) error {
	switch key {
	case "listen":
		return setString(line, key, v, &c.Listen)
	case "upstream":
		s, ok := v.(string)
		if !ok {
			return errf(line, "%s: expected a string", key)
		}
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errf(line, "upstream: must be an http:// or https:// URL")
		}
		c.Upstream = u
	case "difficulty":
		n, ok := v.(int)
		if !ok {
			return errf(line, "%s: expected an integer", key)
		}
		c.Difficulty = n
	case "cookie_age":
		return setDuration(line, key, v, &c.CookieAge)
	case "challenge_age":
		return setDuration(line, key, v, &c.ChallengeAge)
	case "secret_file":
		return setString(line, key, v, &c.SecretFile)
	case "bind_ua":
		return setBool(line, key, v, &c.BindUA)
	case "bind_ip":
		return setBool(line, key, v, &c.BindIP)
	case "insecure_cookie":
		return setBool(line, key, v, &c.InsecureCookie)
	case "protect":
		return setStrings(line, key, v, &c.Protect)
	case "exclude":
		return setStrings(line, key, v, &c.Exclude)
	default:
		return errf(line, "unknown key %q", key)
	}
	return nil
}

func setString(line int, key string, v any, dst *string) error {
	s, ok := v.(string)
	if !ok {
		return errf(line, "%s: expected a string", key)
	}
	*dst = s
	return nil
}

func setBool(line int, key string, v any, dst *bool) error {
	b, ok := v.(bool)
	if !ok {
		return errf(line, "%s: expected true or false", key)
	}
	*dst = b
	return nil
}

func setStrings(line int, key string, v any, dst *[]string) error {
	a, ok := v.([]string)
	if !ok {
		return errf(line, "%s: expected an array of strings", key)
	}
	*dst = a
	return nil
}

func setDuration(line int, key string, v any, dst *time.Duration) error {
	s, ok := v.(string)
	if !ok {
		return errf(line, `%s: expected a duration string like "24h"`, key)
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return errf(line, "%s: invalid duration %q", key, s)
	}
	*dst = d
	return nil
}

// logicalLine is one "key = value" statement and the physical line it
// starts on, used for error messages.
type logicalLine struct {
	text string
	num  int
}

// logicalLines splits src into statements: comments and blank lines are
// dropped, and a multi-line array is joined into a single statement.
func logicalLines(src string) ([]logicalLine, error) {
	var (
		out   []logicalLine
		buf   strings.Builder
		start int
		depth int // currently unclosed '[' brackets
	)
	for i, raw := range strings.Split(src, "\n") {
		num := i + 1
		text, delta, err := stripComment(raw)
		if err != nil {
			return nil, errf(num, "%s", err)
		}
		text = strings.TrimSpace(text)
		if depth == 0 {
			if text == "" {
				continue
			}
			start = num
			buf.Reset()
			buf.WriteString(text)
		} else if text != "" {
			buf.WriteByte(' ')
			buf.WriteString(text)
		}
		depth += delta
		if depth < 0 {
			return nil, errf(num, "unexpected ']'")
		}
		if depth == 0 {
			out = append(out, logicalLine{buf.String(), start})
		}
	}
	if depth > 0 {
		return nil, errf(start, "unterminated array")
	}
	return out, nil
}

// stripComment removes a '#' comment from a physical line, honouring quoted
// strings, and reports the line's bracket balance so the caller can join
// multi-line arrays. A string may not span physical lines.
func stripComment(raw string) (text string, bracketDelta int, err error) {
	inQuote := false
	escaped := false
	for i, r := range raw {
		if inQuote {
			switch {
			case escaped:
				escaped = false
			case r == '\\':
				escaped = true
			case r == '"':
				inQuote = false
			}
			continue
		}
		switch r {
		case '"':
			inQuote = true
		case '#':
			return raw[:i], bracketDelta, nil
		case '[':
			bracketDelta++
		case ']':
			bracketDelta--
		}
	}
	if inQuote {
		return "", 0, fmt.Errorf("unterminated string")
	}
	return raw, bracketDelta, nil
}

// parseStatement splits one statement into its key and typed value.
func parseStatement(ln logicalLine) (key string, val any, err error) {
	eq := strings.IndexByte(ln.text, '=')
	if eq < 0 {
		return "", nil, errf(ln.num, "expected 'key = value'")
	}
	key = strings.TrimSpace(ln.text[:eq])
	if !validKey(key) {
		return "", nil, errf(ln.num, "invalid key %q", key)
	}
	val, err = parseValue(ln.num, key, strings.TrimSpace(ln.text[eq+1:]))
	return key, val, err
}

func validKey(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_' || (r >= 'a' && r <= 'z'):
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func parseValue(line int, key, s string) (any, error) {
	switch {
	case s == "":
		return nil, errf(line, "%s: missing value", key)
	case s[0] == '"':
		v, rest, err := parseQuoted(s)
		if err != nil {
			return nil, errf(line, "%s: %s", key, err)
		}
		if strings.TrimSpace(rest) != "" {
			return nil, errf(line, "%s: unexpected text after value", key)
		}
		return v, nil
	case s[0] == '[':
		return parseArray(line, key, s)
	case s == "true":
		return true, nil
	case s == "false":
		return false, nil
	default:
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, errf(line, "%s: unrecognized value %q", key, s)
		}
		return n, nil
	}
}

// parseQuoted decodes the double-quoted string that s starts with and
// returns the decoded value plus the text after the closing quote. The
// supported escapes are \" \\ \n \t.
func parseQuoted(s string) (val, rest string, err error) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			return b.String(), s[i+1:], nil
		case '\\':
			i++
			if i >= len(s) {
				return "", "", fmt.Errorf("unterminated string")
			}
			switch s[i] {
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				return "", "", fmt.Errorf(`unsupported escape \%c`, s[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", "", fmt.Errorf("unterminated string")
}

// parseArray parses a complete array of quoted strings, e.g.
// ["/a", "/b",]. A trailing comma is allowed.
func parseArray(line int, key, s string) ([]string, error) {
	out := []string{}
	rest := strings.TrimSpace(s[1:])
	for {
		switch {
		case rest == "":
			return nil, errf(line, "%s: unterminated array", key)
		case rest[0] == ']':
			if strings.TrimSpace(rest[1:]) != "" {
				return nil, errf(line, "%s: unexpected text after array", key)
			}
			return out, nil
		case rest[0] != '"':
			return nil, errf(line, "%s: array elements must be quoted strings", key)
		}
		v, r, err := parseQuoted(rest)
		if err != nil {
			return nil, errf(line, "%s: %s", key, err)
		}
		out = append(out, v)
		rest = strings.TrimSpace(r)
		switch {
		case strings.HasPrefix(rest, ","):
			rest = strings.TrimSpace(rest[1:])
		case strings.HasPrefix(rest, "]") || rest == "":
			// closing bracket or unterminated: handled at the top of the loop
		default:
			return nil, errf(line, "%s: expected ',' or ']' in array", key)
		}
	}
}

func errf(line int, format string, args ...any) error {
	return fmt.Errorf("line %d: %s", line, fmt.Sprintf(format, args...))
}
