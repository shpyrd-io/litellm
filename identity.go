package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// claims is what the program reads from the platform's token.
type claims struct {
	Issuer    string   `json:"iss"`
	Audience  string   `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	Roles     []string `json:"roles"`
	Realm     string   `json:"realm"`
	Preview   bool     `json:"preview"`
}

// mayAdminister says the token belongs to a person who may be signed in to
// LiteLLM as its admin: a real visit (not an "Open as" preview, not a
// project calling) by someone with the admin or developer role.
func (c *claims) mayAdminister() bool {
	if c.Preview || c.Realm == "service" {
		return false
	}
	for _, r := range c.Roles {
		if r == "admin" || r == "developer" {
			return true
		}
	}
	return false
}

// verifier checks the platform's tokens (EdDSA, Ed25519) against the keys
// the issuer publishes. The keys are fetched when first needed, not at
// start, and again when a key id is unknown or the copy is old, never more
// often than minRefresh: a client sending unknown key ids cannot make the
// program fetch on every request.
type verifier struct {
	issuer     string // the expected iss, and where the keys live
	audience   string // the expected aud: this project
	client     *http.Client
	now        func() time.Time
	minRefresh time.Duration
	maxAge     time.Duration
	logf       func(format string, args ...any)

	mu        sync.Mutex
	keys      map[string]ed25519.PublicKey
	fetchedAt time.Time
	attemptAt time.Time
	fetches   int
}

func newVerifier(issuer, audience string, client *http.Client, now func() time.Time, logf func(string, ...any)) *verifier {
	return &verifier{
		issuer:     strings.TrimSuffix(issuer, "/"),
		audience:   audience,
		client:     client,
		now:        now,
		minRefresh: 30 * time.Second,
		maxAge:     10 * time.Minute,
		logf:       logf,
	}
}

// looksLikeToken says the bearer has the shape of a platform token: three
// parts and an EdDSA header. Anything else (an API key, a malformed value)
// is not the program's business and costs nothing, not even a key fetch.
func looksLikeToken(raw string) bool {
	_, ok := parseHeader(raw)
	return ok
}

type tokenHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

func parseHeader(raw string) (tokenHeader, bool) {
	var h tokenHeader
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return h, false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(b, &h) != nil {
		return h, false
	}
	return h, h.Alg == "EdDSA" && h.Kid != ""
}

// verify returns the claims of a token whose signature, issuer, audience
// and expiry hold.
func (v *verifier) verify(raw string) (*claims, error) {
	h, ok := parseHeader(raw)
	if !ok {
		return nil, errors.New("not an EdDSA token")
	}
	parts := strings.Split(raw, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("bad signature encoding")
	}
	key, err := v.key(h.Kid)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, errors.New("signature does not verify")
	}
	var c claims
	if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil || json.Unmarshal(b, &c) != nil {
		return nil, errors.New("bad claims")
	}
	now := v.now().Unix()
	switch {
	case c.Issuer != v.issuer:
		return nil, errors.New("wrong issuer")
	case c.Audience != v.audience:
		return nil, errors.New("wrong audience")
	case c.ExpiresAt <= now:
		return nil, errors.New("token expired")
	case c.NotBefore > now:
		return nil, errors.New("token not valid yet")
	}
	return &c, nil
}

func (v *verifier) key(kid string) (ed25519.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	k, known := v.keys[kid]
	fresh := !v.fetchedAt.IsZero() && v.now().Sub(v.fetchedAt) < v.maxAge
	if known && fresh {
		return k, nil
	}
	if v.attemptAt.IsZero() || v.now().Sub(v.attemptAt) >= v.minRefresh {
		v.attemptAt = v.now()
		if err := v.refresh(); err != nil {
			// The copy already held stays good: it verified these keys.
			if !known {
				return nil, err
			}
			v.logf("ui sign-in: cannot refresh the platform's keys, using the ones already held: %v", err)
			return k, nil
		}
		k, known = v.keys[kid]
	}
	if !known {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	return k, nil
}

// refresh fetches the key set. v.mu is held.
func (v *verifier) refresh() error {
	v.fetches++
	resp, err := v.client.Get(v.issuer + "/.well-known/jwks.json")
	if err != nil {
		return fmt.Errorf("the platform's keys at %s/.well-known/jwks.json are unreachable", v.issuer)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the platform's keys answered %s", resp.Status)
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&set); err != nil {
		return errors.New("the platform's keys are not valid JSON")
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid == "" || err != nil || len(x) != ed25519.PublicKeySize {
			continue
		}
		keys[k.Kid] = ed25519.PublicKey(x)
	}
	if len(keys) == 0 {
		return errors.New("the platform's keys hold no Ed25519 key")
	}
	v.keys, v.fetchedAt = keys, v.now()
	return nil
}
