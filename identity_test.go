package main

import (
	"strings"
	"testing"
	"time"
)

func TestOnlyAPlatformShapedBearerIsLookedAt(t *testing.T) {
	s := newSigner(t, "k1")
	for name, tok := range map[string]string{
		"an API key":    "sk-1234",
		"two parts":     "a.b",
		"HS256":         s.mint("HS256", map[string]any{}),
		"none":          s.mint("none", map[string]any{}),
		"not base64":    "!!!.b.c",
		"not an object": "bm90anNvbg.b.c",
	} {
		if looksLikeToken(tok) {
			t.Errorf("%s was taken for a platform token", name)
		}
	}
	if !looksLikeToken(s.mint("EdDSA", map[string]any{})) {
		t.Error("an EdDSA token was not recognized")
	}
}

func TestVerifyChecksSignatureIssuerAudienceAndExpiry(t *testing.T) {
	r := newRig(t)
	v := r.prog.verifier
	good := r.token(nil)
	if c, err := v.verify(good); err != nil || !c.mayAdminister() {
		t.Fatalf("a good token: %v", err)
	}
	// The claims of one token under the signature of another.
	a := strings.Split(good, ".")
	b := strings.Split(r.token(map[string]any{"roles": []string{"developer"}}), ".")
	for name, tc := range map[string]struct{ tok, says string }{
		"tampered":       {a[0] + "." + b[1] + "." + a[2], "signature"},
		"expired":        {r.token(map[string]any{"exp": r.clock.Now().Unix()}), "expired"},
		"wrong audience": {r.token(map[string]any{"aud": "x"}), "audience"},
		"wrong issuer":   {r.token(map[string]any{"iss": "x"}), "issuer"},
		"not yet valid":  {r.token(map[string]any{"nbf": r.clock.Now().Add(time.Hour).Unix()}), "not valid yet"},
	} {
		if _, err := v.verify(tc.tok); err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTheKeysAreFetchedWhenNeededAndOnlyAfterTheMinimumInterval(t *testing.T) {
	r := newRig(t)
	if r.jwks.fetches() != 0 {
		t.Fatalf("keys fetched at start: %d", r.jwks.fetches())
	}
	v := r.prog.verifier
	if _, err := v.verify(r.token(nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.verify(r.token(nil)); err != nil {
		t.Fatal(err)
	}
	if r.jwks.fetches() != 1 {
		t.Fatalf("fetches: %d", r.jwks.fetches())
	}
	// Old keys are looked at again, once the interval allows.
	r.clock.Advance(11 * time.Minute)
	if _, err := v.verify(r.token(nil)); err != nil {
		t.Fatal(err)
	}
	if r.jwks.fetches() != 2 {
		t.Fatalf("fetches after the keys aged: %d", r.jwks.fetches())
	}
	// A refresh that fails leaves the keys held in use.
	r.jwks.set(func(j *fakeJWKS) { j.down = true })
	r.clock.Advance(11 * time.Minute)
	if _, err := v.verify(r.token(nil)); err != nil {
		t.Fatalf("held keys were dropped: %v", err)
	}
}
