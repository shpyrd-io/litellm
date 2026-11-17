#!/bin/sh
# The start of LiteLLM on shpyrd.
#
# The catalog generates two values at install, MASTER_KEY_SEED and
# SALT_KEY_SEED: random bytes as hex. LiteLLM wants its master key to
# start with "sk-", so the keys are made from the seeds here. A key set
# by hand (LITELLM_MASTER_KEY, LITELLM_SALT_KEY) is kept as it is.
set -eu

if [ -z "${LITELLM_MASTER_KEY:-}" ]; then
  if [ -z "${MASTER_KEY_SEED:-}" ]; then
    echo "LiteLLM needs a master key: set MASTER_KEY_SEED (random hex) or LITELLM_MASTER_KEY (starting with sk-) in the project's secrets." >&2
    exit 1
  fi
  export LITELLM_MASTER_KEY="sk-${MASTER_KEY_SEED}"
fi

# The salt key encrypts the provider keys kept in the database. It must
# never change once a model is added: the stored keys would be unreadable.
if [ -z "${LITELLM_SALT_KEY:-}" ]; then
  if [ -z "${SALT_KEY_SEED:-}" ]; then
    echo "LiteLLM needs a salt key: set SALT_KEY_SEED (random hex) or LITELLM_SALT_KEY in the project's secrets." >&2
    exit 1
  fi
  export LITELLM_SALT_KEY="sk-${SALT_KEY_SEED}"
fi

if [ -z "${DATABASE_URL:-}" ]; then
  echo "LiteLLM needs a database: attach a Postgres to the project, so DATABASE_URL is set." >&2
  exit 1
fi

# No arguments: the door, which listens on the port the platform gave and
# runs the proxy behind itself. Arguments are passed on to LiteLLM as they
# are (a one-off command, another component), without the door.
if [ "$#" -eq 0 ]; then
  export PORT="${PORT:-4000}"
  exec /usr/local/bin/litellm-door
fi

exec /app/docker/prod_entrypoint.sh "$@"
