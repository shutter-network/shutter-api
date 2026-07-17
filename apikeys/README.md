# API key management

Bearer tokens are enforced by Caddy, not the Go service. `apikeys.py` maintains
`keys.csv` (`username,apikey` rows, the source of truth) and compiles it into the
Caddy snippet `apikeys.caddy`. Both live in the data directory
(`${DATA_DIR:-./data}`). Caddy only reads the snippet at startup, so every change
needs a caddy restart.

## Create a key

```bash
KEYS_FILE=./data/keys.csv CADDY_SNIPPET=./data/apikeys.caddy python3 apikeys/apikeys.py
```

Enter a unique reference (e.g. the user's email) at the prompt. This appends the
key to `keys.csv` and recompiles the snippet. Then:

```bash
docker compose -f docker-compose.yml -f docker-compose.rate_limit.yaml restart caddy
tail -1 data/keys.csv | cut -d, -f2   # the new token
curl -H "Authorization: Bearer <token>" https://<api-host>/check_authentication
```

## Revoke a key

Delete its row from `data/keys.csv`, then recompile and restart caddy:

```bash
KEYS_FILE=./data/keys.csv CADDY_SNIPPET=./data/apikeys.caddy python3 apikeys/apikeys.py --compile
docker compose -f docker-compose.yml -f docker-compose.rate_limit.yaml restart caddy
```