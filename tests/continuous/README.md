# Continuous round monitor

Runs the time-based decryption round against a **deployed** Shutter API, repeatedly,
for a configurable duration.

Each round:

1. `get_data_for_encryption` → eon, identity, eon key
2. encrypt a fixed plaintext to that identity, locally
3. `register_identity` with a decryption timestamp `DECRYPTION_LEAD` ahead
4. sleep until the timestamp, then poll `get_decryption_key`
5. decrypt with the released key and assert the plaintext matches

Step 5 is the point: a round passes only if the key is **correct**, not merely that
one came back.

It is a black-box monitor — HTTPS to the deployed API, no internal packages. Two uses
from the same code: a bounded soak (`TEST_DURATION=26h`) and an unbounded monitor
(`TEST_DURATION=0`).

## Running

```bash
export API_BASE_URL=https://shutter-api.shutter.network
export API_SIGNER_ADDRESS=0x228DefCF37Da29475F0EE2B9E4dfAeDc3b0746bc
export API_AUTH_TOKEN=<a bearer token from keys.csv>
export TEST_DURATION=26h

go test -tags=live -run TestContinuous -timeout 0 -v ./tests/continuous
```

`-timeout 0` and `-v` are both required. Without `-timeout 0` Go's default
ten-minute test timeout kills the run; without `-v` output is buffered until the run
ends, so a long run prints nothing.

## Environment

| Variable | Default | Notes |
|---|---|---|
| `API_BASE_URL` | — | **Required.** No default on purpose, so a run can't silently hit the wrong network. |
| `API_SIGNER_ADDRESS` | — | **Required.** The API's own signer — identities derive from it, so this must be the API's address and not yours. |
| `API_AUTH_TOKEN` | none | Bearer token. Without it you hit the unauthenticated limits (20 `get_decryption_key`/day) and the run dies in round two. |
| `TEST_DURATION` | `0` | `0` runs until stopped. `26h` for a day-long soak. |
| `ROUND_INTERVAL` | `1m` | Minimum gap between round *starts*. A round that overruns starts the next immediately; rounds never overlap. |
| `DECRYPTION_LEAD` | `1m` | How far ahead the decryption timestamp is set. Minimum 15s — a shorter lead risks the registration not being visible on chain before the timestamp passes, which reports as a failure that isn't one. |
| `POLL_INTERVAL` | `2s` | Gap between `get_decryption_key` attempts, after the timestamp. |
| `POLL_TIMEOUT` | `2m` | Give up this long past the timestamp. |
| `METRICS_PORT` | `9300` | Port for the `/metrics` endpoint a vmagent scrapes. `0` disables it; the monitor still logs every round. |
| `ALLOWED_FAILURES` | `0` | Failed rounds tolerated before the test reports failure. A long soak may reasonably accept one or two transient failures. |

A failed round is recorded and the run continues. That is deliberate — this is built
to run for a day, and one transient failure must not end it.

## Rate limit budget

At `ROUND_INTERVAL=1m` a 24-hour run is ~1,440 rounds, which costs roughly:

- 1,440 `register_identity` — each one an on-chain transaction (~46,860 gas)
- 1,440 `get_data_for_encryption`
- 2,000–6,000 `get_decryption_key`, depending on release latency

Check those against the limits on the key you use. Polling only starts *after* the
decryption timestamp specifically to keep the last figure down — polling from
registration instead would be roughly 12 calls per round.

## Metrics

The monitor exposes `/metrics` on `METRICS_PORT` and a **vmagent scrapes it and
remote-writes** to the central VictoriaMetrics — the same pattern the keypers use, so
`instance`, `network`, `deployment` and `deployment_type` are applied by vmagent
rather than by this code. That also means the monitor does not need to share a docker
network with `vm`, so it can run on any host.

```
shutter_api_continuous_rounds_total{result="pass|fail"}
shutter_api_continuous_round_failures_total{stage="..."}
shutter_api_continuous_release_latency_seconds        # histogram
shutter_api_continuous_last_success_timestamp_seconds
```

`round_failures_total` is labelled by the stage that broke — `register_identity`,
`poll_decryption_key`, `decrypt` and so on — so a failure spike tells you *where*
without reading logs.

`last_success_timestamp_seconds` is the one to alert on. It fires whether the API
stopped serving keys or the monitor itself died, which is what you want from a
liveness signal:

```yaml
- alert: ShutterAPIRoundsStalled
  expr: time() - shutter_api_continuous_last_success_timestamp_seconds > 600
  for: 5m
```

Check `docker compose logs vmalert` after adding it — one invalid expression takes all
alerting down.

Scrape config for the vmagent alongside it:

```yaml
scrape_configs:
  - job_name: shutter-api-continuous
    static_configs:
      - targets: ["continuous:9300"]
```

## Deploying

Self-contained: its own compose file, no database, no shared network, no dependency on
the metrics stack. On any host with docker and a checkout of this repo:

```bash
cd tests/continuous
cp .env.example .env          # fill in the three required values
docker compose up -d
docker compose logs -f
```

That is the whole deployment. The build context is the repository root because the
Dockerfile needs the Go module; the compose file handles that for you.

Set `TEST_DURATION=26h` in `.env` for a bounded soak, or `0` to leave it running as a
monitor. `restart: unless-stopped` brings it back after a reboot either way.

**Start with `METRICS_PORT=0`.** The monitor logs every round and is fully useful
without metrics; turning them on means standing up a vmagent, which is a separate
decision. Add them once you have seen a run behave.

Use one of **your own** API tokens, not a customer's — a 24-hour run would otherwise
consume their daily quota.

### Enabling metrics

The compose file carries a `vmagent` service behind a `pushmetrics` profile, matching
the keyper deployments:

```bash
docker compose --profile pushmetrics up -d
```

It needs a `vmagent.yaml` scrape config pointing at `continuous:9300` and
`REMOTE_WRITE_URL` in `.env`. Copy both from `shutter-keyper-deployment` so the labels
come out consistent with everything else.

**Whether you need it at all depends on where this runs.** On the API's own host, skip
it — add one scrape target for `continuous:9300` to the API's existing vmagent instead.
On a separate host you need this one, and that is the case worth paying for: a monitor
sharing a host with the thing it monitors dies with it, and then you cannot tell "the
API is broken" from "the box is gone".

### Watch and stop

```bash
docker compose logs -f continuous              # one line per round
docker compose logs continuous | grep -c PASS
docker compose logs continuous | grep FAIL
docker compose logs continuous | grep -o 'latency=[0-9.]*' | sort | uniq -c
```

```bash
docker compose stop -t 60 continuous
```

The `-t 60` matters. `docker stop` allows 10 seconds by default, which can kill the
container before it prints the summary — the monitor handles SIGTERM but only stops
after the current round's poll finishes.