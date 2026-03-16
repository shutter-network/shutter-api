# Event Smoke

Live smoke tests for event-based identity registration and decryption key generation.

## Classification

- This suite is a **smoke test** by intent.
- It is also a **live integration test** by execution model.
- It is intended to run against a **reachable RPC endpoint** and a **running keyper set** (with DKG completed for the target eon).
- It is excluded from default test runs via `//go:build live`.

## Tooling

- To run the live tests: `cast`, `openssl`
- To deploy the playground contract with the helper script: `forge`

## .env support

The live test auto-loads `.env` from:

- `tests/event_smoke/.env`

## Deploy playground contract

For Chiado, a playground contract is already deployed at:

`0x0B05BC0BCe48efb0Dd0777C057D87f9Bf66839b4`

You can reuse it directly:

```bash
export PLAYGROUND_ADDR=0x0B05BC0BCe48efb0Dd0777C057D87f9Bf66839b4
```

If you want a fresh deployment, run:

```bash
PRIVATE_KEY=0x... RPC_URL=https://rpc.chiadochain.net \
./tests/event_smoke/scripts/deploy_event_playground.sh
```

Use the returned address as PLAYGROUND_ADDR.

## Run

```bash
go test -tags=live ./tests/event_smoke -v
```

Run selected cases only:

```bash
CASES=transfer_like,indexed_dynamic_note_eq go test -tags=live ./tests/event_smoke -v
```

## Required env vars

- `API_BASE_URL`
- `RPC_URL`
- `PRIVATE_KEY`
- `PLAYGROUND_ADDR`
- `DEST_ADDR`

## Optional env vars

- `FROM_ADDR`
- `TRANSFER_VALUE`
- `TTL`
- `POLL_SECONDS`
- `POLL_INTERVAL`
- `VERBOSE`
- `WAIT_REGISTRATION_RECEIPT`
- `REGISTRATION_DELAY_SECONDS`
- `MAX_CONSEC_TIMEOUTS`
- `AUTH_HEADER`
- `CASES_FILE` (default: `testdata/cases.chiado.json`)