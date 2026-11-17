---
id: litellm-dec-001
type: decision
title: A program in front of LiteLLM signs in people the platform has identified
status: accepted
date: 2026-11-17
related: [litellm-spec-001]
governs: [main.go, program.go, identity.go, login.go, supervisor.go, shpyrd-entrypoint.sh, Dockerfile]
---

## Context

The project is installed from the catalog with the access `identified`, so
a person opens `/ui` already signed in to the platform and then meets
LiteLLM's own login as well. Two ways to avoid that exist: LiteLLM's
Enterprise single sign-on, and a program of our own in front of it, which
is how the other agent projects of the platform avoid a login of their
own.

## Decision

1. **A program of our own, `litellm-door`**, listens on `PORT` and runs
   LiteLLM on loopback behind it. Everything passes through untouched
   (the method, path, query, body, `Authorization` and the response,
   streams and WebSockets included), except a browser navigation to
   `/ui` by a person the platform identified as an admin or developer of
   the project. No LiteLLM Enterprise feature is used.
2. **That person is signed in as LiteLLM's default admin**
   (`UI_USERNAME` / `UI_PASSWORD`, kept on the server), by doing what the
   login form does (litellm-spec-001). LiteLLM does not tell them apart:
   everyone signed in this way acts as the same admin. Everyone else, and
   every failure, meets LiteLLM's own login as before, and the user and
   password given at install still work there.
3. **The platform's token is verified, the headers are not trusted.** The
   `X-Shpyrd-*` headers cannot tell an "Open as" preview from a real
   visit, and other workloads of the cluster may reach the pod and send
   any header, while what is handed out is LiteLLM's full admin session.
   The program verifies the bearer JWT (Ed25519, by key id, from the
   issuer's published keys; issuer, audience and expiry) and reads the
   roles and the `preview` claim from it. It needs `SHPYRD_ISSUER` and
   `SHPYRD_PROJECT`; without them, or without `UI_USERNAME` or
   `UI_PASSWORD`, it signs nobody in and says so in the log.
4. **Only navigations carry the platform's token.** A request with a
   bearer that is not the platform's is not the program's business: API
   calls with a key never touch the keys fetch or the login. The project's
   access stays `identified`.
5. **If LiteLLM ends, the program ends** with a non-zero status, and the
   platform starts the container again. Until LiteLLM answers, the
   program answers 503 with `Retry-After`.
6. **The tag is pinned to what was read.** A test fails when the
   `Dockerfile`'s LiteLLM tag differs from the version litellm-spec-001
   was read at.

## Consequences

- A person who logs out of LiteLLM and navigates to `/ui` is signed in
  again at once; they cannot reach LiteLLM's login form as a different
  LiteLLM user while signed in to the platform with those roles. They can
  still do so from a private window, or with a role that does not qualify.
- A platform personal token with the developer role is the same JWT and
  qualifies too.
- The program is the container's first process and LiteLLM its child.
