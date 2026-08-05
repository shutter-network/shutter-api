# API key management

Bearer tokens and rate limits are enforced by Caddy, not the Go service.
`apikeys.py` reads two files and compiles them into the Caddy snippet
`apikeys.caddy`:

- **`keys.csv`** — `username,apikey,tier` rows, the source of truth for who has a
  key and which tier it is on. Lives in the data directory (`${DATA_DIR:-./data}`).
- **`limits.yaml`** — the rate limits for every tier and endpoint. Lives here, in
  the repo, because it is policy rather than per-deployment state.

You do not run the compile step by hand. The `compiler` service does it, and caddy
waits on it (`service_completed_successfully`), so the snippet is regenerated from
both files on every deploy. It prints the resulting limits — read them in the
compiler's logs to confirm a change landed.

Caddy only reads the snippet at startup, so a change needs caddy restarted.

## Tiers

Every key sits on a tier, which decides its rate limits. `limits.yaml` defines
them — currently `standard` (what every key gets) and `premium` (raised limits for
customers running continuously). A row with no tier column reads as `standard`, so
a `keys.csv` written before tiers existed still works.

Limits are `base × multiplier`: each endpoint has one base number, each tier one
multiplier. The compiler prints the resolved table, so read that rather than doing
the arithmetic.

## Create a key

This is the only step with no deploy equivalent, since it prompts. Run it through
the compiler service so the host needs nothing but docker. The rate-limit override
is required — the `compiler` service is defined there and nowhere else:

```bash
docker compose -f docker-compose.yml -f docker-compose.rate_limit.yaml \
  run --rm -it compiler uv run --script /apikeys.py
```

It asks for a unique reference (e.g. the user's email) and then which tier to put
the key on, defaulting to `standard`. `-it` matters: without it the prompts don't
reach you. The key is appended to `keys.csv` and the snippet recompiled.

Restart caddy, then:

```bash
tail -1 data/keys.csv | cut -d, -f2   # the new token
curl -H "Authorization: Bearer <token>" https://<api-host>/check_authentication
```

## Move a key between tiers

Edit the `tier` column of its row in `keys.csv` and redeploy. The token does not
change, so there is nothing to re-issue to the customer.

## Change a tier's limits

Edit `limits.yaml` and redeploy. Check the compiler's printed table to confirm you
changed what you meant to.

## Revoke a key

Delete its row from `keys.csv` and redeploy.