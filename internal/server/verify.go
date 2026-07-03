package server

import (
	"net/http"
	"time"

	"github.com/solipsismes/powd/internal/pow"
)

// verifyPath is the one endpoint powd serves itself.
const verifyPath = "/.powd/verify"

// maxVerifyBody bounds a verification request. A challenge token is
// ~130 bytes and a solution is a short counter; 4 KB is generous.
const maxVerifyBody = 4096

// serveVerify handles POST /.powd/verify: it checks a solved challenge
// and issues the signed cookie. On success the client reloads the page it
// is already on — no redirect target ever travels in the request, so
// there is nothing to validate and no open-redirect surface.
//
// Malformed requests get a 400. Every rejection after that is a uniform
// 403 — same status, same body — so the endpoint reveals nothing about
// why a submission failed.
func (s *Server) serveVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxVerifyBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	challenge := r.PostForm.Get("challenge")
	solution := r.PostForm.Get("solution")
	if challenge == "" || solution == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	now := time.Now()
	c, err := s.signer.VerifyChallenge(now, challenge)
	if err != nil {
		reject(w)
		return
	}
	if !pow.Check(challenge, solution, c.Difficulty) {
		reject(w)
		return
	}
	// Redeem strictly after the solution checks out: a wrong guess must
	// not burn the challenge for a client that retries correctly.
	if !s.seen.Redeem(now, c.Rand, c.Expiry) {
		reject(w)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    s.signer.MintCookie(now, s.cfg.CookieAge, s.binding(r)),
		Path:     "/",
		MaxAge:   int(s.cfg.CookieAge.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   !s.cfg.InsecureCookie,
	})
	w.WriteHeader(http.StatusNoContent)
}

// reject is the uniform verification failure.
func reject(w http.ResponseWriter) {
	http.Error(w, "forbidden", http.StatusForbidden)
}
