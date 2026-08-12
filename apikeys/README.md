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
them — currently `standard` and `premium`, the latter for customers running
continuously.

A row with no tier column reads as `standard`, so a `keys.csv` written before tiers
existed still works untouched — and a deploy stays reversible, since the previous
version cannot read a three-column file. Add the column when you first promote
someone, not before.

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

## Tests

```bash
pytest apikeys/ -v
```

Needs `pytest` and `pyyaml`.

Nothing runs these automatically yet, so run them after changing `apikeys.py`.

`testdata/` holds a saved copy of the snippet the compiler should produce, and the
test compares its output against that copy. So if you change how the snippet is
built, that test fails and the diff shows you exactly what changed in the config
caddy receives. Read the diff. If the change was intended, re-save the copy:

```bash
UPDATE_GOLDEN=1 pytest apikeys/ -k compile
```

## Verifying a tier change against a deployment

`test_apikeys.py` covers the generator. To check that a deployment really enforces
different limits per tier, compile from a temporary policy with tiny numbers instead
of making thousands of requests, and never edit `limits.yaml` to do it:

```bash
# a copy of limits.yaml with window: 1m and base: 1 on every endpoint
docker compose <overrides> run --rm \
  -v /tmp/limits.test.yaml:/limits.test.yaml -e LIMITS_FILE=/limits.test.yaml compiler
# restart caddy, then burst a key of each tier and note where the 429 lands
```

With multipliers of 1 / 3 / 6, anonymous should 429 on request 2, a standard key on 4
and a premium key on 7. Restoring is a normal compile, since the real `limits.yaml` was
never touched.

Burst a read endpoint — `get_data_for_encryption` or `get_decryption_key` — so no
transaction is submitted and no gas is spent. Caddy counts the request before proxying,
so it is counted even when the API answers with an error.