package server_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"powd/internal/config"
	"powd/internal/pow"
	"powd/internal/server"
	"powd/internal/token"
)

const (
	testUA         = "test-agent/1.0"
	testDifficulty = 8 // ~256 hashes: instant in tests
	verifyPath     = "/.powd/verify"
)

type fixture struct {
	handler http.Handler
	signer  *token.Signer
	cfg     *config.Config
}

// newFixture builds a Server in front of a stub upstream that echoes what
// it received. mutate adjusts the default config before wiring.
func newFixture(t *testing.T, mutate func(*config.Config)) *fixture {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "upstream path=%s host=%s xff=%s",
			r.URL.Path, r.Host, r.Header.Get("X-Forwarded-For"))
	}))
	t.Cleanup(upstream.Close)

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Listen:         ":0",
		Upstream:       u,
		Difficulty:     testDifficulty,
		CookieAge:      24 * time.Hour,
		ChallengeAge:   2 * time.Minute,
		BindUA:         true,
		InsecureCookie: true,
		Protect:        []string{"/"},
		Exclude:        []string{"/rss", "/healthz"},
	}
	if mutate != nil {
		mutate(cfg)
	}

	secret := make([]byte, token.SecretLen)
	signer, err := token.New(secret)
	if err != nil {
		t.Fatal(err)
	}
	logger := log.New(io.Discard, "", 0)
	return &fixture{handler: server.New(cfg, signer, logger), signer: signer, cfg: cfg}
}

func (f *fixture) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// get issues a browser-shaped GET request.
func (f *fixture) get(path string, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("User-Agent", testUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	for k, vs := range header {
		req.Header[k] = vs
	}
	return f.do(req)
}

var challengeAttr = regexp.MustCompile(`data-challenge="([^"]+)"`)

// challengeFor fetches path and extracts the challenge token from the
// interstitial page.
func (f *fixture) challengeFor(t *testing.T, path string) string {
	t.Helper()
	rec := f.get(path, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET %s = %d, want 403 challenge", path, rec.Code)
	}
	m := challengeAttr.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no data-challenge attribute in challenge page:\n%s", rec.Body.String())
	}
	return m[1]
}

// verify submits a challenge/solution pair the way the page JS does.
func (f *fixture) verify(challenge, solution string, header http.Header) *httptest.ResponseRecorder {
	form := url.Values{"challenge": {challenge}, "solution": {solution}}
	req := httptest.NewRequest(http.MethodPost, verifyPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", testUA)
	for k, vs := range header {
		req.Header[k] = vs
	}
	return f.do(req)
}

// earnCookie runs the full challenge→solve→verify flow and returns the
// issued cookie.
func (f *fixture) earnCookie(t *testing.T) *http.Cookie {
	t.Helper()
	challenge := f.challengeFor(t, "/")
	rec := f.verify(challenge, pow.Solve(challenge, testDifficulty), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("verify = %d, want 204; body: %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "powd" {
		t.Fatalf("cookies = %v, want one powd cookie", cookies)
	}
	return cookies[0]
}

func wantUpstream(t *testing.T, rec *httptest.ResponseRecorder, path string) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 proxied; body: %s", rec.Code, rec.Body.String())
	}
	if want := "upstream path=" + path; !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("body = %q, want it to contain %q", rec.Body.String(), want)
	}
}

func TestUnprotectedPathIsProxied(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.Protect = []string{"/blog"} })
	wantUpstream(t, f.get("/other", nil), "/other")
}

func TestExcludedPathIsProxied(t *testing.T) {
	f := newFixture(t, nil)
	wantUpstream(t, f.get("/rss", nil), "/rss")
	wantUpstream(t, f.get("/rss/feed.xml", nil), "/rss/feed.xml")
}

func TestPrefixMatchingIsSegmentAware(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.Protect = []string{"/blog"} })
	// /blogroll is not under /blog: proxied without a cookie.
	wantUpstream(t, f.get("/blogroll", nil), "/blogroll")
	if rec := f.get("/blog/post", nil); rec.Code != http.StatusForbidden {
		t.Errorf("GET /blog/post = %d, want 403", rec.Code)
	}
	// /rssx is not under the /rss exclude: still protected.
	f2 := newFixture(t, nil)
	if rec := f2.get("/rssx", nil); rec.Code != http.StatusForbidden {
		t.Errorf("GET /rssx = %d, want 403", rec.Code)
	}
}

func TestPathTraversalCannotBypassProtection(t *testing.T) {
	f := newFixture(t, nil)
	if rec := f.get("/rss/../secret", nil); rec.Code != http.StatusForbidden {
		t.Errorf("GET /rss/../secret = %d, want 403 (decision must use the cleaned path)", rec.Code)
	}
}

func TestChallengePage(t *testing.T) {
	f := newFixture(t, nil)
	rec := f.get("/", nil)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), fmt.Sprintf(`data-difficulty="%d"`, testDifficulty)) {
		t.Error("page is missing the data-difficulty attribute")
	}

	// The embedded token must be a genuine, verifiable challenge.
	m := challengeAttr.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("page is missing the data-challenge attribute")
	}
	c, err := f.signer.VerifyChallenge(time.Now(), m[1])
	if err != nil {
		t.Fatalf("embedded challenge does not verify: %v", err)
	}
	if c.Difficulty != testDifficulty {
		t.Errorf("challenge difficulty = %d, want %d", c.Difficulty, testDifficulty)
	}
}

func TestHeadGetsHeadersOnly(t *testing.T) {
	f := newFixture(t, nil)
	req := httptest.NewRequest(http.MethodHead, "/", nil)
	req.Header.Set("Accept", "text/html")
	rec := f.do(req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("HEAD / = %d, want 403", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD response has %d body bytes, want 0", rec.Body.Len())
	}
}

func TestNonNavigationRequestsGetTextError(t *testing.T) {
	f := newFixture(t, nil)

	post := httptest.NewRequest(http.MethodPost, "/form", strings.NewReader("x=1"))
	if rec := f.do(post); rec.Code != http.StatusForbidden ||
		!strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("POST without cookie: status=%d type=%q, want 403 text/plain",
			rec.Code, rec.Header().Get("Content-Type"))
	}

	rec := f.get("/", http.Header{"Accept": {"application/json"}})
	if rec.Code != http.StatusForbidden || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("JSON client: status=%d type=%q, want 403 text/plain",
			rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestFullFlow(t *testing.T) {
	f := newFixture(t, nil)
	cookie := f.earnCookie(t)

	if !cookie.HttpOnly || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie attributes = %+v, want HttpOnly, Path=/, SameSite=Lax", cookie)
	}
	if cookie.Secure {
		t.Error("cookie is Secure despite insecure_cookie = true")
	}
	if cookie.MaxAge != int((24 * time.Hour).Seconds()) {
		t.Errorf("cookie MaxAge = %d, want 86400", cookie.MaxAge)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", testUA)
	req.AddCookie(cookie)
	wantUpstream(t, f.do(req), "/")
}

func TestCookieIsSecureByDefault(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.InsecureCookie = false })
	if !f.earnCookie(t).Secure {
		t.Error("cookie is not Secure with default configuration")
	}
}

func TestReplayIsRejected(t *testing.T) {
	f := newFixture(t, nil)
	challenge := f.challengeFor(t, "/")
	solution := pow.Solve(challenge, testDifficulty)

	if rec := f.verify(challenge, solution, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("first verify = %d, want 204", rec.Code)
	}
	if rec := f.verify(challenge, solution, nil); rec.Code != http.StatusForbidden {
		t.Errorf("replayed verify = %d, want 403", rec.Code)
	}
}

func TestWrongSolutionDoesNotBurnChallenge(t *testing.T) {
	f := newFixture(t, nil)
	challenge := f.challengeFor(t, "/")

	if rec := f.verify(challenge, "not-a-solution", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong solution = %d, want 403", rec.Code)
	}
	// A correct retry must still succeed: rejection happens before Redeem.
	if rec := f.verify(challenge, pow.Solve(challenge, testDifficulty), nil); rec.Code != http.StatusNoContent {
		t.Errorf("correct retry = %d, want 204", rec.Code)
	}
}

func TestExpiredChallengeIsRejected(t *testing.T) {
	f := newFixture(t, nil)
	stale := f.signer.MintChallenge(time.Now().Add(-3*time.Minute), 2*time.Minute, testDifficulty)
	if rec := f.verify(stale, pow.Solve(stale, testDifficulty), nil); rec.Code != http.StatusForbidden {
		t.Errorf("expired challenge = %d, want 403", rec.Code)
	}
}

func TestForgedChallengeIsRejected(t *testing.T) {
	f := newFixture(t, nil)
	other, err := token.New(token.RandomSecret())
	if err != nil {
		t.Fatal(err)
	}
	forged := other.MintChallenge(time.Now(), 2*time.Minute, testDifficulty)
	if rec := f.verify(forged, pow.Solve(forged, testDifficulty), nil); rec.Code != http.StatusForbidden {
		t.Errorf("forged challenge = %d, want 403", rec.Code)
	}
}

func TestVerifyEndpointErrors(t *testing.T) {
	f := newFixture(t, nil)

	get := httptest.NewRequest(http.MethodGet, verifyPath, nil)
	if rec := f.do(get); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
		t.Errorf("GET verify = %d (Allow=%q), want 405 with Allow: POST",
			rec.Code, rec.Header().Get("Allow"))
	}

	empty := httptest.NewRequest(http.MethodPost, verifyPath, strings.NewReader(""))
	empty.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec := f.do(empty); rec.Code != http.StatusBadRequest {
		t.Errorf("empty form = %d, want 400", rec.Code)
	}

	huge := httptest.NewRequest(http.MethodPost, verifyPath,
		strings.NewReader("challenge="+strings.Repeat("a", 1<<20)))
	huge.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec := f.do(huge); rec.Code != http.StatusBadRequest {
		t.Errorf("oversized body = %d, want 400", rec.Code)
	}

	if rec := f.get("/.powd/nothing", nil); rec.Code != http.StatusNotFound {
		t.Errorf("GET /.powd/nothing = %d, want 404 (never proxied, never challenged)", rec.Code)
	}
}

func TestUABindingIsEnforced(t *testing.T) {
	f := newFixture(t, nil) // bind_ua on by default
	cookie := f.earnCookie(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "different-agent/2.0")
	req.Header.Set("Accept", "text/html")
	req.AddCookie(cookie)
	if rec := f.do(req); rec.Code != http.StatusForbidden {
		t.Errorf("cookie with foreign User-Agent = %d, want 403", rec.Code)
	}
}

func TestIPBindingIsEnforced(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.BindUA = false
		c.BindIP = true
	})
	mint := http.Header{"X-Real-Ip": {"203.0.113.7"}}
	challenge := f.challengeFor(t, "/")
	rec := f.verify(challenge, pow.Solve(challenge, testDifficulty), mint)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("verify = %d, want 204", rec.Code)
	}
	cookie := rec.Result().Cookies()[0]

	// Same /24: accepted. Different network: challenged again.
	sameNet := httptest.NewRequest(http.MethodGet, "/", nil)
	sameNet.Header.Set("X-Real-Ip", "203.0.113.99")
	sameNet.AddCookie(cookie)
	wantUpstream(t, f.do(sameNet), "/")

	otherNet := httptest.NewRequest(http.MethodGet, "/", nil)
	otherNet.Header.Set("X-Real-Ip", "198.51.100.1")
	otherNet.Header.Set("Accept", "text/html")
	otherNet.AddCookie(cookie)
	if rec := f.do(otherNet); rec.Code != http.StatusForbidden {
		t.Errorf("cookie from another network = %d, want 403", rec.Code)
	}
}

func TestTamperedCookieIsRejected(t *testing.T) {
	f := newFixture(t, nil)
	cookie := f.earnCookie(t)
	cookie.Value = strings.Replace(cookie.Value, "v1", "v1x", 1)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", testUA)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(cookie)
	if rec := f.do(req); rec.Code != http.StatusForbidden {
		t.Errorf("tampered cookie = %d, want 403", rec.Code)
	}
}

func TestProxyPreservesHostAndSetsForwardedFor(t *testing.T) {
	f := newFixture(t, nil)
	rec := f.get("/rss", nil) // excluded: proxied without a cookie
	body := rec.Body.String()
	if !strings.Contains(body, "host=example.com") {
		t.Errorf("upstream saw %q, want original Host example.com", body)
	}
	// httptest.NewRequest's client address is 192.0.2.1.
	if !strings.Contains(body, "xff=192.0.2.1") {
		t.Errorf("upstream saw %q, want X-Forwarded-For 192.0.2.1", body)
	}
}

func TestUpstreamDownYields502(t *testing.T) {
	f := newFixture(t, nil)
	// Point the proxy at a port that is closed by the time we call it.
	dead := httptest.NewServer(http.NotFoundHandler())
	u, _ := url.Parse(dead.URL)
	dead.Close()
	f.cfg.Upstream.Host = u.Host

	if rec := f.get("/rss", nil); rec.Code != http.StatusBadGateway {
		t.Errorf("dead upstream = %d, want 502", rec.Code)
	}
}
