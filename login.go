package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// loginClient signs in to LiteLLM's admin UI the way its login form does:
// a form post of username and password to /login, answered by a redirect
// that sets the "token" cookie. See the spec litellm-spec-001. The
// password never leaves this process except in that post.
type loginClient struct {
	upstream string // LiteLLM's address, no trailing slash
	username string
	password string
	client   *http.Client // does not follow redirects
	now      func() time.Time
	pause    time.Duration // after a refusal, how long before trying again

	mu        sync.Mutex
	notBefore time.Time
}

func newLoginClient(upstream, username, password string, now func() time.Time) *loginClient {
	return &loginClient{
		upstream: strings.TrimSuffix(upstream, "/"),
		username: username,
		password: password,
		now:      now,
		pause:    time.Minute,
		client: &http.Client{
			Timeout:       15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

var errPaused = errors.New("paused after a refusal")

// login signs in and returns the Set-Cookie lines LiteLLM issued, as they
// are. host and proto are the browser's, so that LiteLLM builds its
// answer for the address the person uses. After LiteLLM refuses, no new
// attempt is made for a while: LiteLLM counts failed sign-ins by source
// address, and every attempt here and every person's own login share this
// program's address.
func (l *loginClient) login(host, proto string) ([]string, error) {
	l.mu.Lock()
	if l.now().Before(l.notBefore) {
		l.mu.Unlock()
		return nil, errPaused
	}
	l.mu.Unlock()

	form := url.Values{"username": {l.username}, "password": {l.password}}
	req, err := http.NewRequest(http.MethodPost, l.upstream+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.New("cannot build the login request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if host != "" {
		req.Host = host
	}
	if proto != "" {
		req.Header.Set("X-Forwarded-Proto", proto)
	}
	resp, err := l.client.Do(req)
	if err != nil {
		// err can quote the request; say only that it failed.
		return nil, errors.New("LiteLLM did not answer the login")
	}
	defer resp.Body.Close()

	cookies := resp.Header.Values("Set-Cookie")
	if resp.StatusCode/100 == 3 && hasToken(resp.Cookies()) {
		return cookies, nil
	}
	l.mu.Lock()
	l.notBefore = l.now().Add(l.pause)
	l.mu.Unlock()
	return nil, fmt.Errorf("LiteLLM refused the login (status %d); not trying again for %s", resp.StatusCode, l.pause)
}

func hasToken(cs []*http.Cookie) bool {
	for _, c := range cs {
		if c.Name == "token" && c.Value != "" {
			return true
		}
	}
	return false
}
