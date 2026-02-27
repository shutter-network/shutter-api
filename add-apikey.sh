#!/usr/bin/env bash

# This writes a new apikey to the keysfile and the configuration
docker run --rm -it -v $(pwd)/apikeys/apikeys.py:/apikeys.py:ro -v $(pwd)/data:/data -e KEYS_FILE=/data/keys.csv -e CADDY_SNIPPET=/data/apikeys.caddy ghcr.io/astral-sh/uv:python3.13-alpine uv run --script /apikeys.py

echo "Activating new API key by restarting caddy"
tail -1 data/keys.csv

docker compose -f docker-compose.yml -f docker-compose.rate_limit.yaml restart caddy
