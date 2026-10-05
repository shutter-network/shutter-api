# Time-based API stress runner

Drives the time-based decryption endpoints of a **deployed** Shutter API at
user-selected concurrency and arrival rate, so you can see how the API, keypers,
and anything in front of them (the new RPC/WS loadbalancer in front of Gnosis /
Chiado, specifically) behave under load.

Same shape as [`tests/continuous/`](../continuous/README.md): a black-box runner
behind the `live` build tag, env-config, metrics endpoint for vmagent to scrape.
Different in two ways: a worker pool instead of one sequential round, and two
modes — one that stresses the whole stack and one that isolates the read path.

## Modes

### `full`

Each worker runs the full round, same as the continuous monitor:

1. `get_data_for_encryption` → eon, identity, eon key
2. encrypt locally
3. `register_identity` with a decryption timestamp `DECRYPTION_LEAD` ahead
4. sleep until the timestamp, then poll `get_decryption_key`
5. decrypt with the released key and assert the plaintext matches

Correct-under-load, but each round costs an on-chain tx. Sustained throughput
is bounded by the API's own tx submission path (nonce lock + gas), so this
caps out well before the keypers' RPC/WS fan-out starts to notice.

### `read-only`

A one-time setup registers `POOL_SIZE` identities with a short lead, waits for
their decryption keys to land, then workers loop over the pool calling only
`get_data_for_encryption` and `get_decryption_key`. No on-chain tx per round,
so this is the mode to use when the goal is pure RPC/WS pressure on the API
and anything behind it.

## Running

```bash
export API_BASE_URL=https://shutter-api.chiado.staging.shutter.network
export API_SIGNER_ADDRESS=0xd150bbf86C686de1a25820A94c2C2397e0bC54ab
export API_AUTH_TOKEN=                      # Chiado is unlimited; empty is fine
export STRESS_MODE=read-only
export WORKERS=20
export TARGET_RPS=10
export TEST_DURATION=10m

go test -tags=live -run TestTimeStress -timeout 0 -v ./tests/time_stress
```

Both `-timeout 0` and `-v` are required. Without `-timeout 0` Go's default
10-minute test timeout kills the run; without `-v`, test output is buffered to
the end so a long run looks silent.

## Environment

| Variable | Default | Notes |
|---|---|---|
| `API_BASE_URL` | — | **Required.** No default on purpose. |
| `API_SIGNER_ADDRESS` | — | **Required.** The API's own signer — identities derive from it. Chiado: `0xd150bbf86C686de1a25820A94c2C2397e0bC54ab`. Gnosis: `0x228DefCF37Da29475F0EE2B9E4dfAeDc3b0746bc`. |
| `API_AUTH_TOKEN` | none | Bearer token. On Chiado this is optional. On Gnosis, hitting unauthenticated limits dies in seconds under any real load. |
| `STRESS_MODE` | `full` | `full` or `read-only`. |
| `WORKERS` | `4` | Upper bound on in-flight rounds. |
| `TARGET_RPS` | `0` | Round starts per second, token-bucket paced. `0` means uncapped — workers loop as fast as the API allows. |
| `TEST_DURATION` | `0` | `0` runs until stopped. |
| `DECRYPTION_LEAD` | `30s` | How far ahead the decryption timestamp is set, in `full` mode. Minimum 15s — a shorter lead risks the registration not being visible on chain before the timestamp passes, which reports as a failure that isn't one. |
| `POLL_INTERVAL` | `2s` | Gap between `get_decryption_key` attempts. |
| `POLL_TIMEOUT` | `2m` | Give up this long past the decryption timestamp. |
| `POOL_SIZE` | `10` | Number of pre-registered identities for `read-only` mode. |
| `POOL_SETUP_LEAD` | `45s` | Decryption-timestamp lead used while building the pool. |
| `POOL_SETUP_POLL` | `3m` | Give up on pool setup if a key never arrives this long after its timestamp. |
| `HTTP_TIMEOUT` | `30s` | Per-request timeout. A loadbalancer hiccup should surface as a slow request, not an immediate error. |
| `METRICS_PORT` | `9301` | `/metrics` port for a vmagent to scrape. `0` disables. |
| `ALLOWED_FAILURES` | `0` | Failed rounds tolerated before the test reports failure. For a stress run against a new LB, start with `0` and tune up only if the failures look like noise, not signal. |

## Suggested starting loads (Chiado)

Start small, confirm the pipeline runs, then push.

**Smoke** — read-only, light:

```bash
STRESS_MODE=read-only WORKERS=4 TARGET_RPS=4 TEST_DURATION=2m POOL_SIZE=4
```

**Moderate read-path load** — a reasonable baseline for an LB validation:

```bash
STRESS_MODE=read-only WORKERS=20 TARGET_RPS=20 TEST_DURATION=10m POOL_SIZE=10
```

**Heavier read-path load** — if moderate is clean, try doubling up:

```bash
STRESS_MODE=read-only WORKERS=50 TARGET_RPS=50 TEST_DURATION=10m POOL_SIZE=20
```

**End-to-end under load** — correctness-under-pressure, bounded by on-chain tx
submission:

```bash
STRESS_MODE=full WORKERS=4 TARGET_RPS=0.2 TEST_DURATION=15m
```

Each full-mode round registers an identity (one on-chain tx), so stay well
inside the API's observed tx throughput — the registry nonce lock serialises
these.

## Metrics

```
shutter_api_time_stress_rounds_total{result="pass|fail"}
shutter_api_time_stress_round_failures_total{stage="..."}
shutter_api_time_stress_round_latency_seconds       # histogram
shutter_api_time_stress_stage_latency_seconds{stage="..."}   # histogram
shutter_api_time_stress_in_flight_rounds            # gauge
shutter_api_time_stress_last_success_timestamp_seconds
```

`stage_latency_seconds` is the one to watch for LB validation — slow stages
isolate the problem to a specific endpoint rather than "the API felt slow".
`in_flight_rounds` saturating `WORKERS` tells you concurrency is the bottleneck.

The runner also prints a per-stage percentile report at the end of a run, in the
same format, for runs without a metrics stack hooked up.

## Watching a run

Even without metrics, every round logs one line:

```
2026/10/05 14:02:11 w=3 round=57 PASS latency=312ms get_data_for_encryption=84ms get_decryption_key=215ms identity=0x…
2026/10/05 14:02:11 w=5 round=58 FAIL stage=get_decryption_key err=http=502 … last_poll="http=502 Bad Gateway"
```

A `FAIL stage=` combined with the `last_poll` body is usually enough to tell
"keyper didn't release" from "LB returned a 5xx" from "connection reset".

## Stopping

```bash
# running under `go test` directly
Ctrl-C

# running in docker (if you add a compose file like continuous/)
docker compose stop -t 60 time_stress
```

SIGTERM / SIGINT cancels the run and prints the summary.
