# LiteLLM on shpyrd

[LiteLLM](https://docs.litellm.ai) by BerriAI, packaged as a project for
[shpyrd](https://github.com/shpyrd-io/shpyrd), installed from the
catalog. The official image, plus a script and a small program in front of
it: the script gives LiteLLM its keys in the shape it asks for, and the
program signs in to the admin UI the people the platform has already
identified.

LiteLLM is a gateway: one OpenAI-compatible address in front of the model
providers (OpenAI, Anthropic, Bedrock, Vertex, a local server and many
more), with virtual keys, budgets, spend per key and team, and an admin
UI.

## What the person sees

1. The project is installed from the catalog. The install asks the admin
   user's name and password, and creates a Postgres database for the
   project.
2. The project's access is set to **Named people** (`identified`), once:
   `shpyrd access set identified --project litellm`. See "Access" below
   for why.
3. `/ui` is the admin UI. A person signed in to the platform with the
   `admin` or `developer` role on the project opens it already signed in,
   as LiteLLM's default admin (see "Signing in" below), adds the models
   with their provider keys, and creates virtual keys for the
   applications.
4. Applications call the project's address as they would call OpenAI,
   with a virtual key as the bearer.

## Signing in

A person who is signed in to the platform and has the `admin` or
`developer` role on the project opens `/ui` already signed in: no second
login. They are LiteLLM's default admin (the `UI_USERNAME` given at
install).

Everyone else sees LiteLLM's own login: people with another role,
anyone the platform has not identified, and an "Open as" preview, which is
never signed in whatever roles it shows. The user and password given at
install still work on that screen, for anyone who has them.

Things to know:

- **Before any team or project member exists**, every signed-in person of
  the workspace counts as a platform admin, and is therefore signed in as
  LiteLLM's admin. To narrow that, give people roles on the project
  (add members or teams with `shpyrd members`): from then on only the
  `admin` and `developer` roles qualify.
- **Everyone signed in this way acts in LiteLLM as the same default
  admin.** LiteLLM does not tell them apart: its spend, audit and key
  ownership show one user.
- After logging out of LiteLLM, a person with those roles who opens `/ui`
  is signed in again at once. To sign in as another LiteLLM user, open a
  private window or use a person without those roles.
- The check is on the platform's signed token, not on its headers, so a
  header cannot grant it. The access stays `identified` (below) and API
  clients are not affected: a request with a key goes to LiteLLM exactly
  as it is.
- If the program cannot sign anyone in (the platform's keys are not
  reachable, `UI_USERNAME` or `UI_PASSWORD` is not set, or LiteLLM refuses
  the login), nobody is signed in and LiteLLM's own login keeps working;
  the container's log says why.

## Access

LiteLLM authenticates its own clients: a key, sent as
`Authorization: Bearer sk-…`. The platform's front door passes a bearer
that is not its own on to the application only when the project's access
is `identified` (public, signed-in visitors identified). With the default,
`authenticated`, an API client is asked to sign in and the admin UI cannot
talk to its own API; with `public`, the header is blanked.

So the project is open to the internet and LiteLLM's keys are what
protect it. Choose a strong admin password, and give each application a
virtual key of its own.

Another project of the workspace calls LiteLLM at its public address, not
at `http://litellm.internal`: on an internal call the platform puts the
caller's identity in `Authorization`, where LiteLLM looks for its key.

## How it runs

`shpyrd-entrypoint.sh` is the container's entrypoint. It prepares LiteLLM's
keys, then starts `litellm-door`, a Go program (standard library only,
built by the `Dockerfile`) that listens on `PORT` and runs LiteLLM behind
itself on `127.0.0.1:4001`. The program passes every request on to LiteLLM
untouched (streams and WebSockets included), and answers 503 with
`Retry-After` until LiteLLM answers. If LiteLLM ends, the program ends with
a non-zero status and the platform starts the container again. When the
container is given arguments, the script runs them as a one-off LiteLLM
command, without the program.

The program reads `SHPYRD_ISSUER` and `SHPYRD_PROJECT`, which the platform
sets, to verify the platform's token; and `UI_USERNAME` and `UI_PASSWORD`,
which the catalog sets at install, to sign in. The password stays on the
server. How LiteLLM's login works, and what was read to know, is in
`docs/specs/litellm-spec-001-ui-login.md`; why the program exists, in
`docs/decisions/litellm-dec-001-door-in-front-of-litellm.md`.

The script's part: the catalog
generates two secrets at install, `MASTER_KEY_SEED` and `SALT_KEY_SEED`,
random bytes as hex. The script makes LiteLLM's keys from them:

| LiteLLM reads | Made from |
| --- | --- |
| `LITELLM_MASTER_KEY` | `sk-` + `MASTER_KEY_SEED` |
| `LITELLM_SALT_KEY` | `sk-` + `SALT_KEY_SEED` |

LiteLLM wants the master key to start with `sk-`, and the catalog
generates plain hex: that prefix is the reason for the script. A key set
by hand in the project's secrets, under LiteLLM's own name, is kept as it
is.

The master key is the administrator's API key: it can do everything. To
use it, read `MASTER_KEY_SEED` from the project's secrets and put `sk-`
in front. The salt key encrypts the provider keys kept in the database:
it must never change once a model is added, or the stored keys cannot be
read.

The rest comes from the platform and from the image:

- `DATABASE_URL`, from the Postgres the catalog creates and attaches.
  LiteLLM runs its migrations at start. The script refuses to start
  without it, in words.
- `PORT`, injected by the platform; 4000 otherwise.
- `STORE_MODEL_IN_DB=True`: models, keys and spend live in the database,
  so there is no config file and nothing is lost with a fresh container.
- `LITELLM_MIGRATION_DIR=/tmp/litellm-migrations`: the image runs as a
  user (65534), and its own folders are not that user's to write.

LiteLLM asks for 1 CPU and 4Gi of memory per instance; the catalog entry
sets the memory.

## Updating LiteLLM

The release is the tag on the `FROM` line of the `Dockerfile`. Change it
to a newer release of `ghcr.io/berriai/litellm-non_root` and push: the
projects installed from the catalog follow this repository's `main`.

Read LiteLLM's release notes first: a release may migrate the database,
and going back is then not a matter of the tag alone.

The program signs in the way LiteLLM's login form does, so a new release
can break it. `go test` therefore fails when the tag on the `FROM` line
differs from the release the login was last read at. To go on: read
LiteLLM's login again at the new tag (the route `/login`, the `token`
cookie and what the dashboard reads from it, the files listed in
`docs/specs/litellm-spec-001-ui-login.md`), update that spec and its
`LiteLLM version read:` line, change `login.go` if the login changed, and
let the CI job `container` confirm that LiteLLM accepts the session. If the
login breaks, the person meets LiteLLM's own login; nothing else is lost.
