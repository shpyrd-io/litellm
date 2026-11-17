---
id: litellm-spec-001
type: spec
title: How LiteLLM's admin UI login works, and how the door signs in to it
status: active
date: 2026-11-17
related: [litellm-dec-001]
governs: [login.go, program.go, Dockerfile]
---

## Purpose

The door (`litellm-door`, see litellm-dec-001) signs a person in to
LiteLLM's admin UI by doing what LiteLLM's own login form does, on the
server. That only works for as long as LiteLLM's login works the way this
document says. It was read from LiteLLM's source, not assumed, at one
release, and a test (`TestTheLiteLLMTagIsTheOneTheLoginWasReadAt`) fails
when the `FROM` line of the `Dockerfile` names a different one.

LiteLLM version read: `v1.109.1`

## Where it was read

The repository is `BerriAI/litellm`, at the tag above. Paths are relative
to its root.

| File | What it settles |
| --- | --- |
| `litellm/proxy/proxy_server.py` | the `POST /login` route (`login`), `POST /v2/login`, the redirect, the static mount of `/ui` |
| `litellm/proxy/management_endpoints/ui_sso.py` | `set_session_token_cookie`: the cookie's name and attributes |
| `litellm/proxy/auth/login_utils.py` | `authenticate_user`, `get_ui_credentials`, `encode_ui_session_jwt`: who the default admin is, the session's lifetime |
| `litellm/proxy/auth/ip_address_utils.py` | `is_request_https`: when the cookie is marked `Secure` |
| `litellm/proxy/common_utils/html_forms/ui_login.py` | the login form: field names and where it posts |
| `ui/litellm-dashboard/src/app/(dashboard)/hooks/useAuthorized.ts` | what the dashboard reads from the cookie: the `exp` and the `key` claim it uses as the API bearer |
| `ui/litellm-dashboard/src/utils/cookieUtils.ts` | how the cookie is read and cleared |

## The login

- **Endpoint:** `POST /login`. It is the `action` of LiteLLM's login form.
  (`POST /v2/login` takes JSON and answers JSON with the token in the
  body; the door does not use it.)
- **Request:** `Content-Type: application/x-www-form-urlencoded`, fields
  `username` and `password`.
- **Who:** when the pair equals `UI_USERNAME` and `UI_PASSWORD`
  (`UI_USERNAME` defaults to `admin`; `UI_PASSWORD` defaults to the master
  key), the person is LiteLLM's default admin, the proxy admin. Any other
  pair is looked up among the users in the database. The comparison of the
  default pair is constant-time.
- **Success:** `303 See Other`, `Location` is the proxy's own address
  built from the request's `Host` plus `/ui?login=success`, and a
  `Set-Cookie` for the session (below). The body is empty.
- **Failure:** a `ProxyException`: status 401 with a JSON error for a wrong
  pair, 403 when username and password login is disabled while SSO is
  configured, 500 when no master key is set, and an HTML page with 429 when
  too many failed sign-ins came from one source address. There is no
  `Set-Cookie`.
- **Throttle:** failed sign-ins are counted per source address
  (`LoginThrottle.from_request`). Behind the door every sign-in, the
  person's own included, comes from the door's loopback address, so the
  door does not repeat a refused login for a minute.

## The session

- **One cookie:** `token`.
- **Value:** a JWT signed HS256 with the master key. Its claims are the
  session's user, the session's virtual `key` and `exp`, the session's end:
  `LITELLM_UI_SESSION_DURATION` from the login, 24 hours by default.
- **Attributes:** `Path=/`, `SameSite=lax`, not `HttpOnly` (the dashboard
  reads it from `document.cookie`), no `Max-Age` or `Expires` (a browser
  session cookie). `Secure` only when LiteLLM believes the public address
  is https: `PROXY_BASE_URL` starts with `https`, or the request came from a
  configured trusted proxy with `X-Forwarded-Proto: https`, or the
  request's own scheme is https. Behind the door none of those holds, so
  the door adds `Secure` to the cookie it passes on when the browser's
  request was https (`X-Forwarded-Proto`).

## What the UI reads

The admin UI is a static Next.js export, served from `/ui`. Its pages
decide in the browser (`src/app/(dashboard)/hooks/useAuthorized.ts`, with
`src/utils/cookieUtils.ts` and `src/utils/jwtUtils.ts`): the dashboard
reads the `token` cookie, decodes the JWT, and treats a missing or expired
one (`exp`) as signed out, sending the person to its login page under
`/ui`.

The cookie itself is not the credential for the API. The JWT carries a
`key` claim, a virtual key (`sk-...`) minted for the session at login, and
the dashboard uses that claim as its access token: it calls the API with
`Authorization: Bearer <the key claim>` (the header name is the
`auth_header_name` claim, `Authorization` by default). Sending the whole
cookie JWT as the bearer is refused by LiteLLM with a 401 ("Virtual Key
expected"). The other claims it reads are `user_id`, `user_role`,
`login_method`, `premium_user`, `auth_header_name`,
`disabled_non_admin_personal_key_creation` and `password_reset_required`.
Nothing is read from the redirect's `?login=success`. So a navigation that
arrives with the cookie is the UI signed in, and the server-side login only
has to put the cookie in the browser; the proof that LiteLLM accepts the
session is a call made with the cookie's `key` claim.

## How the door uses it

1. A GET of `/ui` or below it, asking for `text/html`, from a person whose
   platform token verifies (litellm-dec-001) and has the `admin` or
   `developer` role, with no unexpired `token` cookie.
2. The door posts `username` and `password` to `POST /login` on loopback,
   with the browser's `Host` (so that LiteLLM builds its answer for the
   address the person uses), not following the redirect.
3. It takes the `Set-Cookie` lines of the answer as they are (`Secure`
   added over https) and answers the browser `303` to the page it asked
   for, with `Cache-Control: no-store`. The `Location` LiteLLM gave is
   dropped: the door's own is a path under `/ui` of the same host.
4. Anything else, including every failure, goes on to LiteLLM untouched.

## When the version changes

Bumping the tag in the `Dockerfile` makes `go test` fail until this
document is read again against the new tag: the route, the form, the
cookie (name, attributes, lifetime) and what the dashboard reads from it.
Update this document, then the line `LiteLLM version read:` above, then
`login.go` if the login changed. The CI job `container` runs the real
login against the built image and fails if LiteLLM does not accept the
session.
