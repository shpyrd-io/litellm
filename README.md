# LiteLLM on shpyrd

[LiteLLM](https://docs.litellm.ai) by BerriAI, packaged as a project for
[shpyrd](https://github.com/shpyrd-io/shpyrd), installed from the
catalog. The official image, plus one script in front of it: it gives
LiteLLM its keys in the shape it asks for.

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
3. `/ui` is the admin UI. The person signs in with the user and password
   given at install, adds the models with their provider keys, and
   creates virtual keys for the applications.
4. Applications call the project's address as they would call OpenAI,
   with a virtual key as the bearer.

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

`shpyrd-entrypoint.sh` is the container's entrypoint. The catalog
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
