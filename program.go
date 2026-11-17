package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

// Options is what the Program is made from.
type Options struct {
	Upstream   string // LiteLLM's address, such as http://127.0.0.1:4001
	Issuer     string // SHPYRD_ISSUER
	Project    string // SHPYRD_PROJECT
	UIUsername string // UI_USERNAME
	UIPassword string // UI_PASSWORD
	Log        *log.Logger
	Now        func() time.Time // the clock; time.Now when nil
	HTTPClient *http.Client     // for the platform's keys; a default when nil
}

// Program is the door in front of LiteLLM. It passes every request on to
// LiteLLM untouched, except one: the browser navigation to the admin UI of
// a person the platform has identified as an admin or developer of the
// project, who is signed in to LiteLLM as its default admin on the spot.
// Everyone else meets LiteLLM's own login.
type Program struct {
	upstream *url.URL
	proxy    *httputil.ReverseProxy
	ready    chan struct{} // closed when LiteLLM first answered
	logf     func(string, ...any)
	now      func() time.Time
	probe    *http.Client

	verifier *verifier    // nil: signing in is off
	login    *loginClient // nil: signing in is off
}

// New makes the Program. What is missing for signing in is said in the
// log, and leaves LiteLLM's own login as the only way in.
func New(o Options) (*Program, error) {
	up, err := url.Parse(o.Upstream)
	if err != nil || up.Scheme == "" || up.Host == "" {
		return nil, errors.New("the upstream address is not a URL")
	}
	l := o.Log
	if l == nil {
		l = log.New(os.Stderr, "", 0)
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	p := &Program{upstream: up, ready: make(chan struct{}), logf: l.Printf, now: now, probe: &http.Client{Timeout: 3 * time.Second}}

	// No timeouts of the program's own: a completion can take minutes, and
	// a stream stays open as long as the client reads it.
	p.proxy = httputil.NewSingleHostReverseProxy(up)
	p.proxy.FlushInterval = -1
	p.proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		p.logf("litellm-door: LiteLLM did not answer %s %s: %v", r.Method, r.URL.Path, err)
		unavailable(w)
	}

	var missing []string
	if o.Issuer == "" {
		missing = append(missing, "SHPYRD_ISSUER is not set")
	}
	if o.Project == "" {
		missing = append(missing, "SHPYRD_PROJECT is not set")
	}
	if o.UIUsername == "" {
		missing = append(missing, "UI_USERNAME is not set")
	}
	if o.UIPassword == "" {
		missing = append(missing, "UI_PASSWORD is not set")
	}
	if len(missing) > 0 {
		p.logf("litellm-door: signing in to the admin UI with the platform's identity is off (%s); LiteLLM's own login is the way in", strings.Join(missing, ", "))
		return p, nil
	}
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	p.verifier = newVerifier(o.Issuer, o.Project, client, now, p.logf)
	p.login = newLoginClient(o.Upstream, o.UIUsername, o.UIPassword, now)
	return p, nil
}

// Handler is the program's whole HTTP surface.
func (p *Program) Handler() http.Handler { return http.HandlerFunc(p.serve) }

func (p *Program) isReady() bool {
	select {
	case <-p.ready:
		return true
	default:
		return false
	}
}

// Watch asks LiteLLM whether it is alive until it answers, then returns.
// Until then every request is answered 503, so that nothing takes a
// starting project for a ready one.
func (p *Program) Watch(ctx context.Context, every time.Duration) {
	for !p.isReady() {
		if p.alive() {
			close(p.ready)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

func (p *Program) alive() bool {
	resp, err := p.probe.Get(p.upstream.String() + "/health/liveliness")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func unavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "5")
	http.Error(w, "LiteLLM is not ready yet; try again in a few seconds.", http.StatusServiceUnavailable)
}

func (p *Program) serve(w http.ResponseWriter, r *http.Request) {
	if !p.isReady() {
		unavailable(w)
		return
	}
	if p.verifier != nil && isNavigation(r) && !hasSession(r, p.now()) {
		if p.signIn(w, r) {
			return
		}
	}
	p.proxy.ServeHTTP(w, r)
}

// isNavigation says a browser is opening a page of the admin UI: a GET of
// /ui or below it that asks for HTML and carries a platform-looking bearer.
// API calls (a key as the bearer, other paths) are never one.
func isNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet || !strings.Contains(r.Header.Get("Accept"), "text/html") {
		return false
	}
	if r.URL.Path != "/ui" && !strings.HasPrefix(r.URL.Path, "/ui/") {
		return false
	}
	tok, ok := bearer(r)
	return ok && looksLikeToken(tok)
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		return "", false
	}
	return strings.TrimSpace(h[7:]), true
}

// hasSession says the request carries a LiteLLM session: a "token" cookie
// that has not visibly run out. LiteLLM's token is a JWT with an exp; one
// whose exp has passed is replaced by a new sign-in, which overwrites the
// cookie. Whether the rest is genuine is LiteLLM's to say, and a cookie
// that cannot be read is left to it, so that a sign-in is never repeated
// in a loop.
func hasSession(r *http.Request, now time.Time) bool {
	c, err := r.Cookie("token")
	if err != nil || c.Value == "" {
		return false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return true
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return true
	}
	var s struct {
		Exp *int64 `json:"exp"`
	}
	if json.Unmarshal(b, &s) != nil || s.Exp == nil {
		return true
	}
	return *s.Exp > now.Unix()
}

// signIn signs the person in when the platform's token says they may be,
// and answers the navigation itself: the session LiteLLM issued, then a
// redirect to the same page. It says false when the request is to go on to
// LiteLLM as it is.
func (p *Program) signIn(w http.ResponseWriter, r *http.Request) bool {
	tok, _ := bearer(r)
	c, err := p.verifier.verify(tok)
	if err != nil {
		// A visitor without a valid identity is the normal case; only the
		// platform's keys failing is worth a line.
		if strings.HasPrefix(err.Error(), "the platform's keys") {
			p.logf("litellm-door: %v; LiteLLM's own login is the way in", err)
		}
		return false
	}
	if !c.mayAdminister() {
		return false
	}
	proto := ""
	if r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil {
		proto = "https"
	}
	cookies, err := p.login.login(r.Host, proto)
	if err != nil {
		if !errors.Is(err, errPaused) {
			p.logf("litellm-door: signing in to LiteLLM failed: %v", err)
		}
		return false
	}
	h := w.Header()
	for _, line := range cookies {
		if proto == "https" && !strings.Contains(strings.ToLower(line), "; secure") {
			line += "; Secure"
		}
		h.Add("Set-Cookie", line)
	}
	h.Set("Cache-Control", "no-store")
	h.Set("Location", landing(r.URL))
	w.WriteHeader(http.StatusSeeOther)
	return true
}

// landing is where a signed-in person goes: the page they asked for,
// always a path of this host under /ui, never anything built from the
// request that could name another host.
func landing(u *url.URL) string {
	clean := path.Clean("/" + u.Path)
	if clean != "/ui" && !strings.HasPrefix(clean, "/ui/") {
		clean = "/ui"
	}
	if strings.HasSuffix(u.Path, "/") && !strings.HasSuffix(clean, "/") {
		clean += "/"
	}
	return (&url.URL{Path: clean, RawQuery: u.RawQuery}).String()
}

// newServer is the program's HTTP server: a limit on reading the request
// header and nothing else, since responses are streams and long calls.
func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
}
