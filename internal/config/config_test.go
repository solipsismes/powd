package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"powd/internal/config"
)

// minimal is the smallest valid configuration.
const minimal = `
listen   = ":8081"
upstream = "http://127.0.0.1:8080"
`

func TestParseFull(t *testing.T) {
	src := `
# powd example configuration
listen        = ":8081"
upstream      = "https://app.internal:8080" # trailing comment
difficulty    = 20
cookie_age    = "12h"
challenge_age = "90s"
secret_file   = "/var/lib/powd/secret"
bind_ua       = false
bind_ip       = true
insecure_cookie = true

protect = [
    "/",        # everything...
    "/blog",
]
exclude = ["/rss", "/robots.txt"]
`
	cfg, err := config.Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Listen != ":8081" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if got := cfg.Upstream.String(); got != "https://app.internal:8080" {
		t.Errorf("Upstream = %q", got)
	}
	if cfg.Difficulty != 20 {
		t.Errorf("Difficulty = %d", cfg.Difficulty)
	}
	if cfg.CookieAge != 12*time.Hour {
		t.Errorf("CookieAge = %v", cfg.CookieAge)
	}
	if cfg.ChallengeAge != 90*time.Second {
		t.Errorf("ChallengeAge = %v", cfg.ChallengeAge)
	}
	if cfg.SecretFile != "/var/lib/powd/secret" {
		t.Errorf("SecretFile = %q", cfg.SecretFile)
	}
	if cfg.BindUA || !cfg.BindIP || !cfg.InsecureCookie {
		t.Errorf("bools = %v %v %v", cfg.BindUA, cfg.BindIP, cfg.InsecureCookie)
	}
	if want := []string{"/", "/blog"}; !reflect.DeepEqual(cfg.Protect, want) {
		t.Errorf("Protect = %v", cfg.Protect)
	}
	if want := []string{"/rss", "/robots.txt"}; !reflect.DeepEqual(cfg.Exclude, want) {
		t.Errorf("Exclude = %v", cfg.Exclude)
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := config.Parse(minimal)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Difficulty != 18 {
		t.Errorf("default Difficulty = %d, want 18", cfg.Difficulty)
	}
	if cfg.CookieAge != 24*time.Hour {
		t.Errorf("default CookieAge = %v, want 24h", cfg.CookieAge)
	}
	if cfg.ChallengeAge != 2*time.Minute {
		t.Errorf("default ChallengeAge = %v, want 2m", cfg.ChallengeAge)
	}
	if !cfg.BindUA {
		t.Error("default BindUA = false, want true")
	}
	if cfg.BindIP || cfg.InsecureCookie {
		t.Error("BindIP and InsecureCookie should default to false")
	}
	if want := []string{"/"}; !reflect.DeepEqual(cfg.Protect, want) {
		t.Errorf("default Protect = %v, want %v", cfg.Protect, want)
	}
	if len(cfg.Exclude) != 0 {
		t.Errorf("default Exclude = %v, want empty", cfg.Exclude)
	}
	if cfg.SecretFile != "" {
		t.Errorf("default SecretFile = %q, want empty", cfg.SecretFile)
	}
}

func TestPathsAreNormalized(t *testing.T) {
	cfg, err := config.Parse(minimal + "protect = [\"/blog/\", \"/a/./b\"]\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if want := []string{"/blog", "/a/b"}; !reflect.DeepEqual(cfg.Protect, want) {
		t.Errorf("Protect = %v, want %v", cfg.Protect, want)
	}
}

func TestEmptyArrayOverridesDefault(t *testing.T) {
	cfg, err := config.Parse(minimal + "protect = []\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Protect == nil || len(cfg.Protect) != 0 {
		t.Errorf("Protect = %v, want set-but-empty", cfg.Protect)
	}
}

func TestQuotedValues(t *testing.T) {
	// '#' and '=' inside strings must survive; escapes must decode.
	src := `
listen      = "#not = a comment"
upstream    = "http://127.0.0.1:8080"
secret_file = "with \"quotes\" and \\ and \t"
`
	cfg, err := config.Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Listen != "#not = a comment" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if want := "with \"quotes\" and \\ and \t"; cfg.SecretFile != want {
		t.Errorf("SecretFile = %q, want %q", cfg.SecretFile, want)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string // substring of the expected error
	}{
		{"missing listen", `upstream = "http://x:1"`, `missing required key "listen"`},
		{"missing upstream", `listen = ":8081"`, `missing required key "upstream"`},
		{"unknown key", minimal + "dificulty = 22\n", `unknown key "dificulty"`},
		{"duplicate key", minimal + "listen = \":1\"\n", `duplicate key "listen"`},
		{"invalid key", minimal + "Bad-Key = 1\n", `invalid key "Bad-Key"`},
		{"missing equals", minimal + "difficulty\n", "expected 'key = value'"},
		{"missing value", minimal + "difficulty =\n", "missing value"},
		{"int as string", minimal + "difficulty = \"22\"\n", "expected an integer"},
		{"bare word", minimal + "bind_ua = yes\n", `unrecognized value "yes"`},
		{"bool as int", minimal + "bind_ua = 1\n", "expected true or false"},
		{"bad duration", minimal + "cookie_age = \"1 day\"\n", `invalid duration "1 day"`},
		{"duration as int", minimal + "cookie_age = 24\n", "expected a duration string"},
		{"zero duration", minimal + "cookie_age = \"0s\"\n", "must be positive"},
		{"difficulty too low", minimal + "difficulty = 0\n", "between 1 and 32"},
		{"difficulty too high", minimal + "difficulty = 40\n", "between 1 and 32"},
		{"unterminated string", minimal + "secret_file = \"oops\n", "unterminated string"},
		{"bad escape", minimal + `secret_file = "a\qb"` + "\n", `unsupported escape \q`},
		{"unterminated array", minimal + "protect = [\n\"/a\",\n", "unterminated array"},
		{"stray bracket", minimal + "protect = ]\n", "unexpected ']'"},
		{"unquoted element", minimal + "protect = [/a]\n", "must be quoted strings"},
		{"missing comma", minimal + "protect = [\"/a\" \"/b\"]\n", "expected ',' or ']'"},
		{"text after value", minimal + "secret_file = \"/s\" extra\n", "unexpected text after value"},
		{"text after array", minimal + "protect = [\"/a\"] extra\n", "unexpected text after array"},
		{"string as array", minimal + "protect = \"/a\"\n", "expected an array"},
		{"relative protect path", minimal + "protect = [\"blog\"]\n", `path "blog" must start with '/'`},
		{"relative exclude path", minimal + "exclude = [\"rss\"]\n", `path "rss" must start with '/'`},
		{"upstream not a URL", `listen = ":1"` + "\nupstream = \"127.0.0.1:8080\"\n", "http:// or https://"},
		{"upstream bad scheme", `listen = ":1"` + "\nupstream = \"ftp://x:1\"\n", "http:// or https://"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := config.Parse(tt.src)
			if err == nil {
				t.Fatalf("Parse succeeded, want error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want substring %q", err, tt.want)
			}
		})
	}
}

func TestErrorsCarryLineNumbers(t *testing.T) {
	_, err := config.Parse(minimal + "\ndificulty = 22\n")
	if err == nil {
		t.Fatal("Parse succeeded, want error")
	}
	// minimal is 3 lines (leading newline); the bad key is on line 5.
	if !strings.HasPrefix(err.Error(), "line 5:") {
		t.Errorf("error = %q, want prefix \"line 5:\"", err)
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "powd.toml")
	if err := os.WriteFile(path, []byte(minimal), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":8081" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
}

func TestLoadErrorsIncludePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "powd.toml")
	if err := os.WriteFile(path, []byte("nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("error = %v, want it to mention %q", err, path)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := config.Load(filepath.Join(t.TempDir(), "absent.toml")); err == nil {
		t.Error("Load succeeded on a missing file")
	}
}
