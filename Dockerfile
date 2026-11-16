# LiteLLM for shpyrd: the official image, with one script in front of it.
# The platform injects PORT, attaches the project's database as
# DATABASE_URL, and hands the catalog's generated values to the script,
# which gives LiteLLM its keys in the shape it asks for.

# The LiteLLM release. Bumping this tag is how LiteLLM is updated. The
# non_root image is the one that runs as a user: the platform runs images
# as a user, never root.
FROM ghcr.io/berriai/litellm-non_root:v1.109.1

COPY shpyrd-entrypoint.sh /usr/local/bin/shpyrd-entrypoint.sh

USER 65534:65534

# Models, keys and spend live in the database, so nothing is lost with a
# fresh container and no config file is needed. Migrations are prepared
# in /tmp: the image's own folders are not the user's to write.
ENV PORT=4000 \
    STORE_MODEL_IN_DB=True \
    LITELLM_MIGRATION_DIR=/tmp/litellm-migrations

EXPOSE 4000

# Through sh, so the script runs whatever its file mode is.
ENTRYPOINT ["/bin/sh", "/usr/local/bin/shpyrd-entrypoint.sh"]
