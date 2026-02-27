#!/usr/bin/env bash
set -euo pipefail

# - set vars here or via env before running
# - run forge create
# - optionally verify via sourcify

RPC_URL="${RPC_URL:-https://rpc.chiadochain.net}"
PK="${PK:-${PRIVATE_KEY:-}}"
CHAIN="${CHAIN:-chiado}"
VERIFY="${VERIFY:-false}"

if [[ -z "$PK" ]]; then
  echo "set PK or PRIVATE_KEY" >&2
  exit 1
fi

contracts_root_dir="$(git rev-parse --show-toplevel)"
cd "$contracts_root_dir"

CONTRACT_PATH="tests/event_smoke/contracts/EventPlayground.sol"
CONTRACT_FQN="${CONTRACT_PATH}:EventPlayground"

out="$(
  forge create \
    --rpc-url "$RPC_URL" \
    --private-key "$PK" \
    "$CONTRACT_FQN" \
    --broadcast -vvvv
)"

echo "$out"

PLAYGROUND_ADDR="$(echo "$out" | awk '/Deployed to:/{print $3}' | tail -n1)"
if [[ -z "$PLAYGROUND_ADDR" ]]; then
  echo "could not parse deployed address" >&2
  exit 1
fi

if [[ "$VERIFY" == "true" ]]; then
  forge verify-contract \
    --root "$contracts_root_dir" \
    --verifier sourcify \
    --chain "$CHAIN" \
    "$PLAYGROUND_ADDR" \
    "$CONTRACT_FQN"
fi

echo
echo "PLAYGROUND_ADDR=$PLAYGROUND_ADDR"
echo "export PLAYGROUND_ADDR=$PLAYGROUND_ADDR"