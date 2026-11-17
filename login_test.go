package main

import (
	"strings"
	"testing"
	"time"
)

func TestTheLoginPostsTheFormAndKeepsEveryCookieAsIssued(t *testing.T) {
	r := newRig(t)
	l := newLoginClient(r.lite.URL, "admin", sentinelPassword, time.Now)
	lines, err := l.login("litellm.example.com", "https")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "token="+r.lite.lastIssued()+";") {
		t.Fatalf("cookies %q, issued %q", lines, r.lite.lastIssued())
	}
	var login recorded
	for _, q := range r.lite.requests() {
		if q.Path == "/login" {
			login = q
		}
	}
	if login.Host != "litellm.example.com" || login.Form.Get("username") != "admin" {
		t.Fatalf("login seen as %+v", login)
	}
}

func TestARefusedLoginIsNotRepeatedForAWhile(t *testing.T) {
	r := newRig(t)
	now := time.Now()
	l := newLoginClient(r.lite.URL, "admin", "wrong", func() time.Time { return now })
	for i, want := range []string{"refused", "paused", "paused"} {
		_, err := l.login("h", "")
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), want) {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if err != nil && strings.Contains(err.Error(), "wrong") {
			t.Fatalf("the error quotes the password: %v", err)
		}
	}
	if r.lite.logins() != 1 {
		t.Fatalf("logins: %d", r.lite.logins())
	}
	now = now.Add(2 * time.Minute)
	_, _ = l.login("h", "")
	if r.lite.logins() != 2 {
		t.Fatalf("logins after the pause: %d", r.lite.logins())
	}
}

func TestALoginAnswerWithoutASessionIsARefusal(t *testing.T) {
	up := newFakeLite(t)
	up.mu.Lock()
	up.refuse = true
	up.mu.Unlock()
	l := newLoginClient(up.URL, "admin", sentinelPassword, time.Now)
	if _, err := l.login("h", ""); err == nil {
		t.Fatal("a refusal was taken for a login")
	}
}
