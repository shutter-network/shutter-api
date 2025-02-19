# Integration Tests

The integration tests are designed to verify the internal system and its interactions, ensuring that everything is working as expected from both the API and Keyper side.

## Requirements

Before running the tests, ensure that you have the following environment variables set:

- `DB_URL` – The local Keyper database URL.
- `SIGNING_KEY` – The key used for sending registration transactions.
- `KEYPER_HTTP_URL` – The HTTP URL for the fallback Keyper.
- `RPC_URL` – The execution client RPC URL.
- `TOTAL_BULK_REQUESTS` - Number of bulk requests for testing bulk decryption key requests
- `SHUTTER_REGISTRY_CONTRACT_ADDRESS`
- `KEY_BROADCAST_CONTRACT_ADDRESS`
- `KEYPER_SET_MANAGER_CONTRACT_ADDRESS`
- `P2P_BOOTSTRAP_ADDRESSES` - The addresses of the Keyper nodes to bootstrap the P2P network.
- `P2P_DISCOVERY_NAMESPACE` - The discovery namespace for the P2P network.

## Prerequisites

- Ensure that the Keypers are up and running.
- Make sure that the Distributed Key Generation (DKG) process is completed before running the tests.

## Running the Tests

Once the environment variables are set and the Keypers are running, follow these steps to run the integration tests:

```bash
go test
```

This will run the integration tests and verify the system's internal functionality and interactions.

## Testing fallback mechanism
If you want to test the fallback mechanism for decryption key retrieval, you can shutdown the keyper who's `DB_URL` you passed in the enviroment variable. Now run the tests again, all of them should still pass.

## Troubleshooting

- If you encounter issues with connecting to the database, verify the `DB_URL` environment variable.
- Ensure that all Keyper services are correctly configured and that the DKG process is completed before testing.