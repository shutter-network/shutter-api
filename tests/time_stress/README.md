# time_stress

Stress tests for time-based decryption key registration. Registers N identities in parallel for the same decryption timestamp and asserts that all receive distinct keys once the timestamp is reached.

## Setup

Copy the example env file and set the API URL:

```sh
cp env.example .env
# edit .env
```

## Run

```sh
go test -count=1 -tags=live ./tests/time_stress -v
```

Run a specific case:

```sh
CASES=stress_100 go test -count=1 -tags=live ./tests/time_stress -v
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `API_BASE_URL` | required | Base URL of the Shutter API |
| `AUTH_HEADER` | | Optional auth header, format `Key:Value` |
| `TIME_DECRYPTION_OFFSET_SECONDS` | `90` | How far in the future to set the decryption timestamp |
| `REG_CONCURRENCY` | `1` | Max parallel registration requests |
| `REGISTRATION_DELAY_SECONDS` | `2` | Sleep after all registrations are submitted |
| `POLL_SECONDS` | `130` | Total time to poll for decryption keys |
| `POLL_INTERVAL` | `2` | Seconds between poll attempts |
| `MAX_CONSEC_TIMEOUTS` | `5` | Abort a case after this many consecutive API timeouts |
| `VERBOSE` | `true` | Log individual HTTP requests and responses |
| `CASES_FILE` | `testdata/cases.json` | Path to the test cases file |
