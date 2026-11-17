package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const sentinelPassword = "s3cr3t-sentinel-password-4f9a"

// ---- test doubles -------------------------------------------------------

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type recorded struct {
	Method, Path, Query, Auth, Host string
	Body                            []byte
	Form                            url.Values
}

// fakeLite stands in for LiteLLM: its login, its UI and a few API paths.
type fakeLite struct {
	*httptest.Server
	mu     sync.Mutex
	reqs   []recorded
	refuse bool
	issued string // the session token the last login handed out
}

func newFakeLite(t *testing.T) *fakeLite {
	f := &fakeLite{}
	f.Server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeLite) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	rec := recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), r.Host, body, nil}
	if r.Method == http.MethodPost && r.URL.Path == "/login" {
		q, _ := url.ParseQuery(string(body))
		rec.Form = q
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, rec)
	refuse := f.refuse
	f.mu.Unlock()

	switch {
	case r.URL.Path == "/health/liveliness":
		fmt.Fprint(w, "I'm alive!")
	case r.Method == http.MethodPost && r.URL.Path == "/login":
		if refuse || rec.Form.Get("username") != "admin" || rec.Form.Get("password") != sentinelPassword {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"message":"Authentication Error - invalid credentials"}}`)
			return
		}
		exp := time.Now().Add(24 * time.Hour).Unix()
		payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"user_id":"default_user_id","exp":%d}`, exp)))
		tok := "eyJhbGciOiJIUzI1NiJ9." + payload + "." + fmt.Sprint(len(f.reqs))
		f.mu.Lock()
		f.issued = tok
		f.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "token", Value: tok, Path: "/", SameSite: http.SameSiteLaxMode})
		w.Header().Set("Location", "http://"+r.Host+"/ui?login=success")
		w.WriteHeader(http.StatusSeeOther)
	case strings.HasPrefix(r.URL.Path, "/ui"):
		if c, err := r.Cookie("token"); err == nil && c.Value != "" {
			fmt.Fprint(w, "LITELLM UI")
			return
		}
		fmt.Fprint(w, "LITELLM LOGIN SCREEN")
	case r.URL.Path == "/v1/models":
		w.Header().Set("X-Litellm-Test", "yes")
		if r.Header.Get("Authorization") != "Bearer sk-good" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"message":"bad key"}}`)
			return
		}
		fmt.Fprint(w, `{"data":[]}`)
	default:
		w.Header().Set("X-Litellm-Test", "yes")
		fmt.Fprintf(w, "echo %s %s?%s %s", r.Method, r.URL.Path, r.URL.RawQuery, body)
	}
}

func (f *fakeLite) logins() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.reqs {
		if r.Method == http.MethodPost && r.Path == "/login" {
			n++
		}
	}
	return n
}

func (f *fakeLite) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}

func (f *fakeLite) lastIssued() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.issued
}

// fakeJWKS publishes the platform's keys.
type fakeJWKS struct {
	*httptest.Server
	mu   sync.Mutex
	keys map[string]ed25519.PublicKey
	down bool
	bad  bool
	hits int
}

func newFakeJWKS(t *testing.T) *fakeJWKS {
	j := &fakeJWKS{keys: map[string]ed25519.PublicKey{}}
	j.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		j.mu.Lock()
		defer j.mu.Unlock()
		if r.URL.Path != "/.well-known/jwks.json" {
			http.NotFound(w, r)
			return
		}
		j.hits++
		if j.down {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		if j.bad {
			fmt.Fprint(w, "this is not json")
			return
		}
		var ks []map[string]any
		for kid, pub := range j.keys {
			ks = append(ks, map[string]any{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": kid, "x": base64.RawURLEncoding.EncodeToString(pub)})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": ks})
	}))
	t.Cleanup(j.Close)
	return j
}

func (j *fakeJWKS) publish(kid string, pub ed25519.PublicKey) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.keys[kid] = pub
}

func (j *fakeJWKS) set(f func(j *fakeJWKS)) {
	j.mu.Lock()
	defer j.mu.Unlock()
	f(j)
}

func (j *fakeJWKS) fetches() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.hits
}

type signer struct {
	priv ed25519.PrivateKey
	kid  string
}

func newSigner(t *testing.T, kid string) signer {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub
	return signer{priv, kid}
}

func (s signer) public() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }

func (s signer) mint(alg string, claims map[string]any) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	head := enc(map[string]string{"alg": alg, "kid": s.kid, "typ": "JWT"})
	body := enc(claims)
	signed := head + "." + body
	var sig []byte
	switch alg {
	case "EdDSA":
		sig = ed25519.Sign(s.priv, []byte(signed))
	case "none":
		sig = nil
	default:
		sig = bytes.Repeat([]byte{7}, 32)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// rig is the Program in front of the fakes.
type rig struct {
	t     *testing.T
	door  *httptest.Server
	lite  *fakeLite
	jwks  *fakeJWKS
	logs  *syncBuf
	clock *fakeClock
	prog  *Program
	key   signer
}

func newRig(t *testing.T, mods ...func(*Options)) *rig {
	t.Helper()
	r := &rig{t: t, lite: newFakeLite(t), jwks: newFakeJWKS(t), logs: &syncBuf{}, clock: &fakeClock{t: time.Now()}, key: newSigner(t, "k1")}
	r.jwks.publish("k1", r.key.public())
	o := Options{
		Upstream:   r.lite.URL,
		Issuer:     r.jwks.URL,
		Project:    "litellm",
		UIUsername: "admin",
		UIPassword: sentinelPassword,
		Log:        log.New(r.logs, "", 0),
		Now:        r.clock.Now,
	}
	for _, m := range mods {
		m(&o)
	}
	p, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	r.prog = p
	p.Watch(t.Context(), 10*time.Millisecond)
	r.door = httptest.NewServer(p.Handler())
	t.Cleanup(r.door.Close)
	return r
}

func (r *rig) claims(over map[string]any) map[string]any {
	c := map[string]any{
		"iss": r.jwks.URL, "aud": "litellm", "sub": "idn_1", "ws": "default", "project": "litellm",
		"roles": []string{"admin"}, "teams": []string{}, "realm": "workspace",
		"iat": r.clock.Now().Unix(), "exp": r.clock.Now().Add(5 * time.Minute).Unix(),
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func (r *rig) token(over map[string]any) string { return r.key.mint("EdDSA", r.claims(over)) }

var noRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// nav is a browser opening a page of the UI, with the platform's bearer.
func (r *rig) nav(path, bearer string, header ...string) (*http.Response, string) {
	r.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, r.door.URL+path, nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	return r.do(req, nil)
}

func (r *rig) do(req *http.Request, jar http.CookieJar) (*http.Response, string) {
	r.t.Helper()
	c := &http.Client{CheckRedirect: noRedirect, Jar: jar, Timeout: 10 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (r *rig) assertLiteLLMsOwnLogin(resp *http.Response, body string) {
	r.t.Helper()
	if resp.StatusCode != 200 || body != "LITELLM LOGIN SCREEN" {
		r.t.Fatalf("want LiteLLM's own login screen, got %d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("Set-Cookie") != "" {
		r.t.Fatalf("a cookie was set: %v", resp.Header["Set-Cookie"])
	}
}

// ---- C1 -----------------------------------------------------------------

func TestAnAdminOrDeveloperOpensTheUISignedIn(t *testing.T) {
	for _, roles := range [][]string{{"admin"}, {"developer"}, {"developer", "admin"}, {"user", "developer"}} {
		t.Run(strings.Join(roles, ","), func(t *testing.T) {
			r := newRig(t)
			resp, _ := r.nav("/ui/", r.token(map[string]any{"roles": roles}), "X-Forwarded-Proto", "https")
			if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/ui/" {
				t.Fatalf("got %d, Location %q", resp.StatusCode, resp.Header.Get("Location"))
			}
			if r.lite.logins() != 1 {
				t.Fatalf("logins: %d", r.lite.logins())
			}
			var login recorded
			for _, q := range r.lite.requests() {
				if q.Path == "/login" {
					login = q
				}
			}
			if login.Form.Get("username") != "admin" || login.Form.Get("password") != sentinelPassword {
				t.Fatalf("the login form was %v", login.Form)
			}
			if login.Host != strings.TrimPrefix(r.door.URL, "http://") {
				t.Fatalf("LiteLLM saw host %q, not the browser's", login.Host)
			}
			cs := resp.Cookies()
			if len(cs) != 1 || cs[0].Name != "token" || cs[0].Value != r.lite.lastIssued() || cs[0].Path != "/" {
				t.Fatalf("cookies: %v (LiteLLM issued %q)", resp.Header["Set-Cookie"], r.lite.lastIssued())
			}
			if !cs[0].Secure {
				t.Fatalf("a sign-in over https must give a Secure cookie: %v", resp.Header["Set-Cookie"])
			}
			// The landing: with the cookie, the UI and not the login screen.
			jar, _ := cookiejar.New(nil)
			u, _ := url.Parse(r.door.URL)
			jar.SetCookies(u, []*http.Cookie{{Name: "token", Value: cs[0].Value, Path: "/"}})
			req, _ := http.NewRequest(http.MethodGet, r.door.URL+resp.Header.Get("Location"), nil)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Authorization", "Bearer "+r.token(map[string]any{"roles": roles}))
			_, body := r.do(req, jar)
			if body != "LITELLM UI" {
				t.Fatalf("landing body %q", body)
			}
		})
	}
}

func TestTheSessionResponseIsNotCacheable(t *testing.T) {
	r := newRig(t)
	resp, _ := r.nav("/ui", r.token(nil))
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q", resp.Header.Get("Cache-Control"))
	}
	if resp.Header.Get("Location") != "/ui" {
		t.Fatalf("Location %q", resp.Header.Get("Location"))
	}
}

// ---- C2, C3 -------------------------------------------------------------

func TestRolesComeFromTheVerifiedTokenNotFromHeaders(t *testing.T) {
	r := newRig(t)
	other := newSigner(t, "k1") // the same kid, a key the platform never published
	cases := map[string]string{
		"header without a token":     "",
		"header with a viewer token": r.token(map[string]any{"roles": []string{"viewer"}}),
		"header with a bad signature": func() string {
			return other.mint("EdDSA", r.claims(nil))
		}(),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			resp, body := r.nav("/ui/", tok, "X-Shpyrd-Roles", "admin", "X-Shpyrd-User", "someone@example.com")
			r.assertLiteLLMsOwnLogin(resp, body)
		})
	}
	if r.lite.logins() != 0 {
		t.Fatalf("a login reached LiteLLM")
	}
}

func TestNoSignInForWhoIsNotAnAdminOrDeveloper(t *testing.T) {
	r := newRig(t)
	stranger := newSigner(t, "k1")
	cases := map[string]string{
		"no token":                 "",
		"role user":                r.token(map[string]any{"roles": []string{"user"}}),
		"role viewer":              r.token(map[string]any{"roles": []string{"viewer"}}),
		"role reader":              r.token(map[string]any{"roles": []string{"reader"}}),
		"empty roles":              r.token(map[string]any{"roles": []string{}}),
		"no roles":                 r.token(map[string]any{"roles": nil}),
		"preview of an admin":      r.token(map[string]any{"preview": true}),
		"expired":                  r.token(map[string]any{"exp": r.clock.Now().Add(-time.Minute).Unix()}),
		"wrong audience":           r.token(map[string]any{"aud": "another-project"}),
		"wrong issuer":             r.token(map[string]any{"iss": "https://elsewhere.example"}),
		"key not in the JWKS":      stranger.mint("EdDSA", r.claims(nil)),
		"alg none":                 r.key.mint("none", r.claims(nil)),
		"alg HS256":                r.key.mint("HS256", r.claims(nil)),
		"malformed":                "not.a.jwt.at.all",
		"garbage":                  "xyz",
		"service realm":            r.token(map[string]any{"realm": "service", "roles": []string{}}),
		"service realm with admin": r.token(map[string]any{"realm": "service"}),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			resp, body := r.nav("/ui/", tok)
			r.assertLiteLLMsOwnLogin(resp, body)
		})
	}
	if r.lite.logins() != 0 {
		t.Fatalf("a login reached LiteLLM")
	}
}

// ---- C4 -----------------------------------------------------------------

func TestItFailsClosedWhenItIsNotConfigured(t *testing.T) {
	cases := map[string]struct {
		mod  func(*Options)
		says string
	}{
		"issuer":   {func(o *Options) { o.Issuer = "" }, "SHPYRD_ISSUER is not set"},
		"project":  {func(o *Options) { o.Project = "" }, "SHPYRD_PROJECT is not set"},
		"username": {func(o *Options) { o.UIUsername = "" }, "UI_USERNAME is not set"},
		"password": {func(o *Options) { o.UIPassword = "" }, "UI_PASSWORD is not set"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, c.mod)
			if !strings.Contains(r.logs.String(), c.says) {
				t.Fatalf("the log does not say why: %q", r.logs.String())
			}
			resp, body := r.nav("/ui/", r.token(nil))
			r.assertLiteLLMsOwnLogin(resp, body)
			if r.lite.logins() != 0 || r.jwks.fetches() != 0 {
				t.Fatalf("logins %d, fetches %d", r.lite.logins(), r.jwks.fetches())
			}
		})
	}
}

func TestItFailsClosedWhenThePlatformKeysAreUnreachableOrInvalid(t *testing.T) {
	for name, set := range map[string]func(*fakeJWKS){
		"down":    func(j *fakeJWKS) { j.down = true },
		"invalid": func(j *fakeJWKS) { j.bad = true },
		"empty":   func(j *fakeJWKS) { j.keys = map[string]ed25519.PublicKey{} },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.jwks.set(set)
			resp, body := r.nav("/ui/", r.token(nil))
			r.assertLiteLLMsOwnLogin(resp, body)
			if r.lite.logins() != 0 {
				t.Fatal("a login reached LiteLLM")
			}
			if !strings.Contains(r.logs.String(), "the platform's keys") || !strings.Contains(r.logs.String(), "LiteLLM's own login is the way in") {
				t.Fatalf("the log does not say why: %q", r.logs.String())
			}
		})
	}
}

func TestItFailsClosedWhenLiteLLMRefusesTheLogin(t *testing.T) {
	r := newRig(t, func(o *Options) { o.UIPassword = "not-the-password" })
	resp, body := r.nav("/ui/", r.token(nil))
	r.assertLiteLLMsOwnLogin(resp, body)
	if r.lite.logins() != 1 {
		t.Fatalf("logins: %d", r.lite.logins())
	}
	if !strings.Contains(r.logs.String(), "LiteLLM refused the login (status 401)") {
		t.Fatalf("the log does not say why: %q", r.logs.String())
	}
	// No hammering: LiteLLM counts failed sign-ins by address, and everyone's
	// own login shares this program's address.
	for i := 0; i < 3; i++ {
		resp, body = r.nav("/ui/", r.token(nil))
		r.assertLiteLLMsOwnLogin(resp, body)
	}
	if r.lite.logins() != 1 {
		t.Fatalf("it tried again at once: %d logins", r.lite.logins())
	}
	r.clock.Advance(2 * time.Minute)
	r.nav("/ui/", r.token(nil))
	if r.lite.logins() != 2 {
		t.Fatalf("it never tried again: %d logins", r.lite.logins())
	}
}

// ---- C5 -----------------------------------------------------------------

func TestAKeyPublishedLaterIsAcceptedWithoutARestart(t *testing.T) {
	r := newRig(t)
	if resp, _ := r.nav("/ui/", r.token(nil)); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("first token: %d", resp.StatusCode)
	}
	first := r.jwks.fetches()

	next := newSigner(t, "k2")
	tok := next.mint("EdDSA", r.claims(nil))
	// Not published yet: refused, and repeated asking does not fetch again.
	for i := 0; i < 20; i++ {
		resp, body := r.nav("/ui/", tok)
		r.assertLiteLLMsOwnLogin(resp, body)
	}
	if got := r.jwks.fetches() - first; got > 1 {
		t.Fatalf("%d fetches for an unknown key id", got)
	}
	r.jwks.publish("k2", next.public())
	// Published, but the last look was a moment ago: still no fetch.
	r.nav("/ui/", tok)
	if got := r.jwks.fetches() - first; got > 1 {
		t.Fatalf("%d fetches inside the minimum interval", got)
	}
	r.clock.Advance(time.Minute)
	if resp, _ := r.nav("/ui/", tok); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("the new key was not accepted: %d", resp.StatusCode)
	}
}

// ---- C6 -----------------------------------------------------------------

func TestOneLoginAcrossSeveralNavigations(t *testing.T) {
	r := newRig(t)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second} // follows redirects
	tok := r.token(nil)
	for _, p := range []string{"/ui/", "/ui/?login=success", "/ui/model_hub", "/ui/", "/ui"} {
		req, _ := http.NewRequest(http.MethodGet, r.door.URL+p, nil)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "LITELLM UI" {
			t.Fatalf("%s: %q", p, b)
		}
	}
	if r.lite.logins() != 1 {
		t.Fatalf("logins: %d", r.lite.logins())
	}
}

func TestAnExpiredSessionIsReplaced(t *testing.T) {
	r := newRig(t)
	old := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":1}`))
	resp, _ := r.nav("/ui/", r.token(nil), "Cookie", "token=a."+old+".c")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

// ---- C7 -----------------------------------------------------------------

func TestRedirectsStayOnThisHostUnderTheUI(t *testing.T) {
	r := newRig(t)
	for _, p := range []string{
		"/ui//evil.example", "/ui/?next=https://evil.example", "/ui/%2f%2fevil.example", "/ui///evil.example/x",
		"/ui/%2e%2e/%2e%2e/evil", "/ui/..//evil.example", "/ui/\\evil.example", "/ui/%0d%0aLocation:%20https://evil.example",
		"/ui/http://evil.example", "/ui?x=//evil.example",
	} {
		resp, _ := r.nav(p, r.token(nil))
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("%s: status %d", p, resp.StatusCode)
			continue
		}
		loc := resp.Header.Get("Location")
		u, err := url.Parse(loc)
		if err != nil || u.Host != "" || u.Scheme != "" || !(u.Path == "/ui" || strings.HasPrefix(u.Path, "/ui/")) || strings.HasPrefix(loc, "//") {
			t.Errorf("%s: Location %q leaves the UI of this host", p, loc)
		}
		// The next hop must be the same host.
		abs, _ := url.Parse(r.door.URL)
		if got := abs.ResolveReference(u); got.Host != abs.Host {
			t.Errorf("%s: resolves to %s", p, got)
		}
	}
}

// ---- C8 -----------------------------------------------------------------

func TestThePasswordStaysServerSide(t *testing.T) {
	check := func(t *testing.T, r *rig) {
		resp, body := r.nav("/ui/", r.token(nil))
		var all strings.Builder
		all.WriteString(body)
		for k, vs := range resp.Header {
			all.WriteString(k + ": " + strings.Join(vs, ",") + "\n")
		}
		resp2, body2 := r.nav("/ui/", r.token(nil))
		all.WriteString(body2)
		for k, vs := range resp2.Header {
			all.WriteString(k + ": " + strings.Join(vs, ",") + "\n")
		}
		for _, secret := range []string{sentinelPassword, url.QueryEscape(sentinelPassword)} {
			if strings.Contains(all.String(), secret) {
				t.Fatal("the password reached the browser")
			}
			if strings.Contains(r.logs.String(), secret) {
				t.Fatalf("the password is in the log: %s", r.logs.String())
			}
		}
	}
	t.Run("accepted", func(t *testing.T) { check(t, newRig(t)) })
	t.Run("refused", func(t *testing.T) {
		r := newRig(t)
		r.lite.mu.Lock()
		r.lite.refuse = true
		r.lite.mu.Unlock()
		check(t, r)
		if !strings.Contains(r.logs.String(), "refused") {
			t.Fatalf("the refusal was not logged: %q", r.logs.String())
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		r := newRig(t)
		r.lite.Close()
		check(t, r)
	})
}

// ---- C9 -----------------------------------------------------------------

func TestAPITrafficPassesUntouched(t *testing.T) {
	r := newRig(t)
	r.jwks.set(func(j *fakeJWKS) { j.down = true })
	type call struct{ method, path, query, auth, body string }
	calls := []call{
		{"GET", "/v1/models", "", "Bearer sk-good", ""},
		{"POST", "/v1/chat/completions", "stream=true&x=%2F", "Bearer sk-good", `{"model":"m","messages":[{"role":"user","content":"héllo"}]}`},
		{"POST", "/key/generate", "", "Bearer sk-good", `{"models":[]}`},
		{"GET", "/v1/models", "", "Bearer sk-wrong", ""},
		{"GET", "/ui/", "", "Bearer sk-good", ""}, // a key on a UI path: not a platform token
	}
	for _, c := range calls {
		req, _ := http.NewRequest(c.method, r.door.URL+c.path+"?"+c.query, strings.NewReader(c.body))
		if c.query == "" {
			req.URL.RawQuery = ""
		}
		req.Header.Set("Authorization", c.auth)
		req.Header.Set("Accept", "text/html")
		resp, body := r.do(req, nil)
		if c.path == "/v1/models" {
			if c.auth == "Bearer sk-good" && (resp.StatusCode != 200 || body != `{"data":[]}`) {
				t.Fatalf("%v: %d %q", c, resp.StatusCode, body)
			}
			if c.auth == "Bearer sk-wrong" && (resp.StatusCode != 401 || body != `{"error":{"message":"bad key"}}`) {
				t.Fatalf("%v: %d %q", c, resp.StatusCode, body)
			}
			if resp.Header.Get("X-Litellm-Test") != "yes" {
				t.Fatalf("a header of LiteLLM's was lost")
			}
		}
		if c.path == "/v1/chat/completions" && body != fmt.Sprintf("echo POST %s?%s %s", c.path, c.query, c.body) {
			t.Fatalf("body came back as %q", body)
		}
	}
	got := r.lite.requests()
	var seen []recorded
	for _, q := range got {
		if q.Path != "/health/liveliness" {
			seen = append(seen, q)
		}
	}
	if len(seen) != len(calls) {
		t.Fatalf("LiteLLM saw %d requests for %d calls", len(seen), len(calls))
	}
	for i, c := range calls {
		q := seen[i]
		if q.Method != c.method || q.Path != c.path || q.Query != c.query || q.Auth != c.auth || string(q.Body) != c.body {
			t.Fatalf("call %d reached LiteLLM as %+v, sent %+v", i, q, c)
		}
	}
	if r.jwks.fetches() != 0 || r.lite.logins() != 0 {
		t.Fatalf("fetches %d, logins %d", r.jwks.fetches(), r.lite.logins())
	}
}

// ---- C10 ----------------------------------------------------------------

func TestAStreamReachesTheClientBeforeItEnds(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/liveliness" {
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-release
		fmt.Fprint(w, "data: two\n\n")
	}))
	defer up.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	r := newRig(t, func(o *Options) { o.Upstream = up.URL })
	resp, err := http.Post(r.door.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(resp.Body).ReadString('\n')
		line <- s
	}()
	select {
	case s := <-line:
		if s != "data: one\n" {
			t.Fatalf("first chunk %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first chunk waited for the end of the response")
	}
	close(release)
}

func TestNoTimeOfTheProgramsOwnCutsALongCall(t *testing.T) {
	srv := newServer(":0", http.NotFoundHandler())
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 || srv.IdleTimeout < 0 {
		t.Fatalf("the server has a read or write timeout: %v %v", srv.ReadTimeout, srv.WriteTimeout)
	}
	// A slow answer comes through whole.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/liveliness" {
			return
		}
		time.Sleep(1500 * time.Millisecond)
		fmt.Fprint(w, "late but whole")
	}))
	defer up.Close()
	r := newRig(t, func(o *Options) { o.Upstream = up.URL })
	front := httptest.NewUnstartedServer(r.prog.Handler())
	front.Config.ReadHeaderTimeout = srv.ReadHeaderTimeout
	front.Start()
	defer front.Close()
	resp, err := http.Get(front.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "late but whole" {
		t.Fatalf("got %q", b)
	}
}

func TestAWebSocketUpgradePassesThrough(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/liveliness" {
			return
		}
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "no upgrade", 400)
			return
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(buf, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		buf.Flush()
		line, _ := buf.ReadString('\n')
		fmt.Fprint(buf, "echo:"+line)
		buf.Flush()
	}))
	defer up.Close()
	r := newRig(t, func(o *Options) { o.Upstream = up.URL })
	conn, err := net.Dial("tcp", strings.TrimPrefix(r.door.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "GET /v1/realtime HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("status %q, %v", status, err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" {
			break
		}
	}
	fmt.Fprint(conn, "ping\n")
	got, err := br.ReadString('\n')
	if err != nil || got != "echo:ping\n" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// ---- C12 ----------------------------------------------------------------

func TestUntilLiteLLMAnswersTheProgramAnswers503(t *testing.T) {
	lite := newFakeLite(t)
	p, err := New(Options{Upstream: lite.URL, Log: log.New(&syncBuf{}, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	door := httptest.NewServer(p.Handler())
	defer door.Close()
	for _, path := range []string{"/", "/health/liveliness", "/ui/", "/v1/models"} {
		resp, err := http.Get(door.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
			t.Fatalf("%s: %d, Retry-After %q", path, resp.StatusCode, resp.Header.Get("Retry-After"))
		}
	}
	p.Watch(t.Context(), 10*time.Millisecond)
	resp, err := http.Get(door.URL + "/health/liveliness")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("after LiteLLM answered: %d", resp.StatusCode)
	}
}

func TestWatchWaitsForLiteLLMToBeAlive(t *testing.T) {
	var mu sync.Mutex
	alive := false
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !alive {
			http.Error(w, "starting", 503)
		}
	}))
	defer up.Close()
	p, _ := New(Options{Upstream: up.URL, Log: log.New(&syncBuf{}, "", 0)})
	done := make(chan struct{})
	go func() { p.Watch(t.Context(), 10*time.Millisecond); close(done) }()
	time.Sleep(100 * time.Millisecond)
	if p.isReady() {
		t.Fatal("ready while LiteLLM answers 503")
	}
	mu.Lock()
	alive = true
	mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("never ready")
	}
}

func TestWhenLiteLLMStopsAnsweringTheProgramAnswers503(t *testing.T) {
	r := newRig(t)
	r.lite.Close()
	resp, _ := r.nav("/v1/models", "")
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("%d, Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
}

// ---- C14 ----------------------------------------------------------------

var fromLine = regexp.MustCompile(`(?m)^FROM\s+ghcr\.io/berriai/litellm-non_root:(\S+)`)
var recordedVersion = regexp.MustCompile("(?m)^LiteLLM version read: `([^`]+)`")

func TestTheLiteLLMTagIsTheOneTheLoginWasReadAt(t *testing.T) {
	df, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	m := fromLine.FindSubmatch(df)
	if m == nil {
		t.Fatal("the Dockerfile has no FROM line for ghcr.io/berriai/litellm-non_root")
	}
	specs, _ := filepath.Glob(filepath.Join("docs", "specs", "litellm-spec-*.md"))
	var recorded string
	for _, s := range specs {
		b, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		if v := recordedVersion.FindSubmatch(b); v != nil {
			recorded = string(v[1])
		}
	}
	if recorded == "" {
		t.Fatal("no spec under docs/specs/ records the LiteLLM version its login was read at (a line starting \"LiteLLM version read:\")")
	}
	if string(m[1]) != recorded {
		t.Fatalf("the Dockerfile's LiteLLM tag is %s but the login was read at %s. "+
			"Re-read LiteLLM's login at the new tag (the files the spec lists: /login, the token cookie, what the UI reads), "+
			"update the spec in docs/specs/ and the line \"LiteLLM version read:\" in it, change login.go if the login changed, "+
			"and run the container check of the CI.", m[1], recorded)
	}
}
