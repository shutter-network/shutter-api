# Shutter API Documentation for dApp Developers

## Disclaimer

This software is in its early stages of development. Users are strongly advised to exercise caution and not entrust any assets or sensitive information of high value to this API until further maturity and decentralization are achieved.

Please note that all threshold cryptography systems and multi-party computation (MPC) frameworks inherently rely on a threshold trust assumption. While the Shutter API currently utilizes a decentralized set of keypers, the network is not fully decentralized at this time. We expect additional keypers to join and enhance the network's resilience shortly.

This project is released as open source and provided "as is" without any warranties, express or implied. The developers and contributors assume no liability for any issues, losses, or damages arising from the use or misuse of this API. Use at your own risk.

---

## Welcome to the **Shutter API** documentation!

This guide will help you integrate Shutter's Commit and Reveal Scheme into your decentralized application (dApp). The Shutter system provides a secure, decentralized, and tamper-proof commit-and-reveal workflow, ensuring integrity and confidentiality in your application.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Endpoints](#endpoints)
   - [Identity Registration](#1-identity-registration)
     - [Register an Identity with Time-based Decryption Triggers](#1a-register-an-identity-with-time-based-decryption-triggers)
     - [Compile an Event Trigger Definition](#1b-compile-an-event-trigger-definition)
     - [Register an Identity with Event-based Decryption Triggers](#1c-register-an-identity-with-event-based-decryption-triggers)
     - [Get Event Trigger Identity Registration Expiration Block](#1d-get-event-trigger-identity-registration-expiration-block)
   - [Encryption Operations](#2-encryption-operations)
     - [Retrieve the Encryption Data](#2a-retrieve-the-encryption-data)
   - [Decryption Operations](#3-decryption-operations)
     - [Retrieve the Decryption Key](#3a-retrieve-the-decryption-key)
     - [Decrypt Commitments](#3b-decrypt-commitments)
4. [Future features](#future-features)
5. [FAQs](#faqs)
6. [Swagger Documentation](#swagger-documentation)
7. [Support](#support)

---

## Overview

The Shutter system leverages threshold encryption, distributed cryptographic operations, and a decentralized infrastructure to handle commitments securely. Core components include:

- **Registry Contract**: An on-chain contract where clients register identities and specify time-based decryption triggers.
- **Keypers**: A distributed set of nodes that monitor the registry contract, handle cryptographic operations such as distributed key generation, and release decryption keys securely.
- **API**: An API that simplifies interaction with the Shutter system by exposing endpoints for encryption and decryption operations.

This documentation will guide you through:
- Setting up identities with time-based or event-based decryption triggers.
- Compiling event trigger definitions for event-based triggers.
- Retrieving encryption data and decryption keys.
- Decrypting encrypted commitments.
- Querying event identity registration expiration block.

---

## Prerequisites

- **API Access**:
  At the moment, the access is free of charge, but rate limited for Gnosis Mainnet. You only need to query the API endpoints at the addresses below:
  - **Chiado**: `https://shutter-api.chiado.staging.shutter.network/api/[ADD_ENDPOINT]`
  - **Mainnet**: `https://shutter-api.shutter.network/api/[ADD_ENDPOINT]`

- **Address of the Shutter Registry Contract**:
  - **Chiado Address**: `0x2693a4Fb363AdD4356e6b80Ac5A27fF05FeA6D9F`
  - **Gnosis Address**: `0x694e5de9345d39C148DA90e6939A3fd2142267D9`

- **Address of the API**:
  - **Chiado Address**: `0xb9C303443c9af84777e60D5C987AbF0c43844918`
  - **Gnosis Address**: `0x228DefCF37Da29475F0EE2B9E4dfAeDc3b0746bc`

### Rate limits / Authorization

For unauthorized access, the API on Gnosis Mainnet is rate limited with these limits per endpoint and remote ip:

  - `/time/register_identity` 5 requests per 24 hours
  - `/time/get_data_for_encryption` 10 requests per 24 hours
  - `/time/get_decryption_key` 20 requests per 24 hours
  - `/event/compile_trigger_definition` 20 requests per 24 hours
  - `/event/register_identity` 5 requests per 24 hours
  - `/event/get_data_for_encryption` 10 requests per 24 hours
  - `/event/get_trigger_expiration_block` 20 requests per 24 hours
  - `/event/get_decryption_key` 20 requests per 24 hours
  - `/decrypt_commitment` 10 requests per 24 hours

We recommend using Chiado for development, because there are no rate limits in place.

If you need higher limits, contact [loring@brainbot.com](mailto:loring@brainbot.com) to request an API key.

Authorized requests have these limits:

  - `/time/register_identity` 500 requests per 24 hours
  - `/time/get_data_for_encryption` 1000 requests per 24 hours
  - `/time/get_decryption_key` 2000 requests per 24 hours
  - `/event/compile_trigger_definition` 2000 requests per 24 hours
  - `/event/register_identity` 500 requests per 24 hours
  - `/event/get_data_for_encryption` 1000 requests per 24 hours
  - `/event/get_trigger_expiration_block` 2000 requests per 24 hours
  - `/event/get_decryption_key` 2000 requests per 24 hours
  - `/decrypt_commitment` 1000 requests per 24 hours

Authorization is done by using an `Authorization: Bearer $API_KEY` header, when calling the API.

Use the `/check_authentication` endpoint, to test your API key.

---

## Endpoints

### 1. Identity Registration

#### 1.A Register an Identity with Time-based Decryption Triggers

To begin using the Shutter system, register an identity and specify a time-based decryption trigger. This step links an identity to a decryption key and sets the release conditions for the key to a Unix timestamp.

Refer to the `/time/register_identity` endpoint in the Swagger documentation for details on parameters and responses.

> **Note**: When registering identities through our API, the API account address is used to compute the identity that will be returned. If you want to use your own address, you need to submit the registration directly to the registry contract. The contract's definition can be found here:
> [ShutterRegistry.sol](https://github.com/shutter-network/contracts/blob/main/src/shutter-service/ShutterRegistry.sol#L1C1-L86C2).
> We follow Gnosis Mainnet block timestamps for `decryptionTimestamp`. The identities will be released on the basis of Gnosis Timestamp only (~every 5 seconds).

#### Example Request
```bash
curl -X POST https://<API_BASE_URL>/time/register_identity \
-H "Content-Type: application/json" \
-d '{
  "decryptionTimestamp": 1735044060,
  "identityPrefix": "0x79bc8f6b4fcb02c651d6a702b7ad965c7fca19e94a9646d21ae90c8b54c030a0"
}'
```

#### Example Response
```json
{
  "eon": 1,
  "eon_key": "0x57af5437a84ef50e5ed75772c18ae38b168bb07c50cadb65fc6136604e662255",
  "identity": "0x8c232eae4f957259e9d6b68301d529e9851b8642874c8f59d2bd0fb84a570c75",
  "identity_prefix": "0x79bc8f6b4fcb02c651d6a702b7ad965c7fca19e94a9646d21ae90c8b54c030a0",
  "tx_hash": "0x3026ad202ca611551377eef069fb6ed894eae65329ce73c56f300129694f12ba"
}
```

### 1.B Compile an Event Trigger Definition

An alternative to time-based decryption triggers are "event-based" decryption triggers. This is very similar to the time-based release conditions discussed above. However, here the decryption key is produced only when a specific EVM event has been observed by the keypers.

Before registering an identity with event-based decryption triggers, you need to compile an event trigger definition. This endpoint takes an event signature and arguments to create an event trigger definition that will be understood by keypers supporting event-based decryption triggers.

The trigger condition is specified by a `contract address` (mandatory), the event's signature (mandatory), and a number of additional arguments. Event data can be matched as `byte-equals` or numeric comparisons (`lt, lte, eq, gte, gt`) over an uint256-cast of the specified event data fields.

Refer to the `/event/compile_trigger_definition` endpoint in the Swagger documentation for details on parameters and responses.

#### Example Request
```bash
curl -X POST https://<API_BASE_URL>/event/compile_trigger_definition \
-H "Content-Type: application/json" \
-d '{
  "contract": "0x3465a347342B72BCf800aBf814324ba4a803c32b",
  "eventSig": "Transfer(indexed from address, indexed to address, amount uint256)",
  "arguments": [
    {
      "name": "from",
      "op": "eq",
      "bytes": "0x456d9347342B72BCf800bBf117391ac2f807c6bF"
    },
    {
      "name": "amount",
      "op": "gte",
      "number": 25433
    }
  ]
}'
```

#### Example Response
```json
{
  "trigger_definition": "0x01f86694953a0425accee2e05f22e78999c595ed2ee7183cf84fe480e205a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efe401e205a0000000000000000000000000812a6755975485c6e340f97de6790b34a94d1430c404c20402"
}
```

> **Note**: The object format for the "arguments" list is:
> - `name`: The matching argument name from the event signature
> - `op`: One of `lt`, `lte`, `eq`, `gte`, `gt` for comparison operations
> - `number`: Integer argument for numeric comparisons
> - `bytes`: Hex-encoded byte argument for non-numeric matches with `op == "eq"`
> 
> The resulting condition for the trigger is a logical AND of all arguments given.

### 1.C Register an Identity with Event-based Decryption Triggers

An alternative to time-based decryption triggers is "event-based" decryption triggers. This is very similar to the time-based release conditions discussed above. However, here the decryption key is produced only when a specific EVM event has been observed by the keypers.

The trigger condition is specified by a compiled event trigger definition (created using `/event/compile_trigger_definition`, see above). Registered event-based decryption triggers are bound by a time-to-live (`ttl`). The decryption keys are only released once and only if:

- the release condition has not been met before (since registration)
- the `ttl` timer has not run out, and
- *all* conditions of the trigger definition were fulfilled.

Refer to the `/event/register_identity` endpoint in the Swagger documentation for details on parameters and responses.

> **Note**: When registering identities through our API, the API account address is used to compute the identity that will be returned. For the time being, it is **not** possibly to register event based decryption triggers directly with the contract. The contract's definition can be found here:
> [ShutterEventTriggerRegistry.sol](https://github.com/shutter-network/contracts/blob/main/src/shutter-service/ShutterEventTriggerRegistry.sol#L35-L40)

#### Example Request
```bash
curl -X POST https://<API_BASE_URL>/event/register_identity \
-H "Content-Type: application/json" \
-d '{
  "triggerDefinition": "0x01f86694953a0425accee2e05f22e78999c595ed2ee7183cf84fe480e205a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efe401e205a0000000000000000000000000812a6755975485c6e340f97de6790b34a94d1430c404c20402",
  "identityPrefix": "0x32fdbd2ca52e171f77db2757ff6200cd8446350f927a3ad46c0565483dd8b41c",
  "ttl": 100
}'
```

> **Note**: The encoding of `eventDefinition` is specified in [rolling-shutter](https://github.com/shutter-network/rolling-shutter/blob/main/docs/spec.md). It is a concatenation of contract address and the rlp encoding of all conditions. Event definitions should be constructed by using provided tooling (i.e. `/compile_event_trigger_definition` endpoint or `etdc` utility).

#### Example Response
```json
{
  "eon": 1,
  "eon_key": "0x9348cbe5372c1b467bfe60d6c678bbe1aed74a90b93f857b2db1b6a5dac5cd95",
  "identity": "0xdfb9b97b2ff057a1fdff173e10e974ffb16c28105f0524b33e8a6906c6c81dc0",
  "identity_prefix": "0x32fdbd2ca52e171f77db2757ff6200cd8446350f927a3ad46c0565483dd8b41c",
  "tx_hash": "0xf7cb7ef13edee67735bba17d5ff84546a1ac7547b3d2a9f1d15e4d1b2e9f303c"
}
```

> **Note**: The encoding of `triggerDefinition` is specified [in rolling-shutter](https://github.com/shutter-network/rolling-shutter/blob/main/docs/event.md). It is a concatenation of contract address, topic0 and the RLP encoding of the other conditions. Event definitions should be constructed using the `/event/compile_trigger_definition` endpoint.

### 1.D Get Event Trigger Identity Registration Expiration Block

Retrieve the expiration block number for a given event trigger identity registration. This endpoint allows you to check the expiration block number for an event-based identity registration.

Refer to the `/event/get_trigger_expiration_block` endpoint in the Swagger documentation for details on parameters and responses.

#### Example Request
```bash
curl -X GET "https://<API_BASE_URL>/event/get_trigger_expiration_block?eon=1&identityPrefix=0x32fdbd2ca52e171f77db2757ff6200cd8446350f927a3ad46c0565483dd8b41c"
```

#### Example Response
```json
{
  "expiration_block_number": 5678967
}
```

> **Note**: If the event identity registration is not found, the endpoint will return a 404 error.

### 2. Encryption Operations

#### 2.A Retrieve the Encryption Data

To encrypt commitments, obtain the encryption data associated with your identity. There are two endpoints:

- **Time-based**: `/time/get_data_for_encryption` — parameters `address` (required) and `identityPrefix` (optional). Use the address that will register the identity (your account if self-registering, or the API address: Gnosis `0x228DefCF37Da29475F0EE2B9E4dfAeDc3b0746bc`, Chiado `0xb9C303443c9af84777e60D5C987AbF0c43844918`).
- **Event-based**: `/event/get_data_for_encryption` — parameters `triggerDefinition` (required) and `identityPrefix` (optional).

Refer to the Swagger documentation for specifics on these endpoints.

#### Example Request (Time-based)
```bash
curl -X GET "https://<API_BASE_URL>/time/get_data_for_encryption?address=0xb9C303443c9af84777e60D5C987AbF0c43844918&identityPrefix=0x79bc8f6b4fcb02c651d6a702b7ad965c7fca19e94a9646d21ae90c8b54c030a0"
```

#### Example Request (Event-based)
```bash
curl -X GET "https://<API_BASE_URL>/event/get_data_for_encryption?identityPrefix=0x79bc8f6b4fcb02c651d6a702b7ad965c7fca19e94a9646d21ae90c8b54c030a0&triggerDefinition=0x01f86694953a0425accee2e05f22e78999c595ed2ee7183cf84fe480e205a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efe401e205a0000000000000000000000000812a6755975485c6e340f97de6790b34a94d1430c404c20402"
```

#### Example Response
```json
{
"eon": 1,
"eon_key": "0x57af5437a84ef50e5ed75772c18ae38b168bb07c50cadb65fc6136604e662255",
"identity": "0x8c232eae4f957259e9d6b68301d529e9851b8642874c8f59d2bd0fb84a570c75",
"identity_prefix": "0x79bc8f6b4fcb02c651d6a702b7ad965c7fca19e94a9646d21ae90c8b54c030a0",
"epoch_id": "0x88f2495d1240f9c5523db589996a50a4984ee7a08a8a8f4b269e4345b383310abd2dc1cd9c9c2b8718ed3f486d5242f5"
}
```

#### Encrypting Commitments in Go

The following Go code demonstrates how to use the encryption data retrieved from the Shutter API to encrypt commitments:

```go
// NOTE: This example requires the "github.com/shutter-network/shutter/shlib/shcrypto" package.
// Make sure to install it in your Go environment before running this code.
package main

import (
  "crypto/rand"
  "encoding/hex"
  "fmt"
  "log"
  "strings"

  "github.com/shutter-network/shutter/shlib/shcrypto"
)

func main() {
  // Encryption data provided by the Shutter API
  identityHex := "0x8c232eae4f957259e9d6b68301d529e9851b8642874c8f59d2bd0fb84a570c75"
  eonPublicKeyHex := "0x57af5437a84ef50e5ed75772c18ae38b168bb07c50cadb65fc6136604e662255"
  message := []byte("please hide this message")

  identityHex = strings.TrimPrefix(identityHex, "0x")
  eonPublicKeyHex = strings.TrimPrefix(eonPublicKeyHex, "0x")

  // Convert hex strings to bytes
  identity, err := hex.DecodeString(identityHex)
  if err != nil {
    log.Fatalf("Failed to decode identity: %v", err)
  }

  eonPublicKeyBytes, err := hex.DecodeString(eonPublicKeyHex)
  if err != nil {
    log.Fatalf("Failed to decode eon public key: %v", err)
  }

  // Create EonPublicKey struct from bytes
  eonPublicKey := &shcrypto.EonPublicKey{}
  if err := eonPublicKey.Unmarshal(eonPublicKeyBytes); err != nil {
    log.Fatalf("Failed to unmarshal EonPublicKey: %v", err)
  }

  // Compute the Epoch ID from the identity
  epochID := shcrypto.ComputeEpochID(identity)

  // Generate a random sigma
  sigma, err := shcrypto.RandomSigma(rand.Reader)
  if err != nil {
    log.Fatalf("Failed to generate random sigma: %v", err)
  }

  // Encrypt the message
  encryptedCommitment := shcrypto.Encrypt(message, eonPublicKey, epochID, sigma)

  // Marshal the encrypted commitment into bytes
  encryptedCommitmentBytes := encryptedCommitment.Marshal()

  // Convert to hex string
  encryptedCommitmentHex := "0x" + hex.EncodeToString(encryptedCommitmentBytes)

  // Print the encrypted commitment
  fmt.Printf("Encrypted Commitment: %s\n", encryptedCommitmentHex)
}
```

#### Encrypting Commitments in TypeScript

You can also use our [Shutter TypeScript SDK](https://github.com/shutter-network/shutter-sdk) to easily encrypt commitments:

```ts
import { encryptData } from "@shutter-network/shutter-sdk";
import { stringToHex } from "viem";

// Encryption data provided by the Shutter API
const eonKeyHex = "0x57af5437a84ef50e5ed75772c18ae38b168bb07c50cadb65fc6136604e662255";
const identityPreimageHex = "0x8c232eae4f957259e9d6b68301d529e9851b8642874c8f59d2bd0fb84a570c75";
const msgHex = stringToHex("please hide this message")

// some random sigma
const sigmaHex = "0x312c10b186086d502ba683cffc2ae650d53b508904b3c430df8e7d5aa336c0f5";

// Encrypt the message
const encryptedCommitment = await encryptData(message, eonPublicKey, identityPreimageHex, sigma);
// Print the encrypted commitment
console.log("Encrypted Commitment:", encryptedCommitment);
```

### 3. Decryption Operations

#### 3.A Retrieve the Decryption Key

After the decryption trigger conditions are met (e.g., the specified timestamp has passed, or the event has fired), retrieve the decryption key using `/time/get_decryption_key` or, for event based decryption triggers, `/event/get_decryption_key`.

Refer to the Swagger documentation for detailed usage.

#### Example Request (Time-Based)
```bash
curl -X GET "https://<API_BASE_URL>/time/get_decryption_key?identity=0x8c232eae4f957259e9d6b68301d529e9851b8642874c8f59d2bd0fb84a570c75"
```

#### Example Response (Time-Based)
```json
{
  "decryption_key": "0x99a805fc26812c13041126b25e91eccf3de464d1df7a95d1edca8831a9ec02dd",
  "decryption_timestamp": 1735044061,
  "identity": "0x8c232eae4f957259e9d6b68301d529e9851b8642874c8f59d2bd0fb84a570c75"
}
```

#### Example Request (Event-Based)
```bash
curl -X GET "https://<API_BASE_URL>/event/get_decryption_key?identity=0x8c232eae4f957259e9d6b68301d529e9851b8642874c8f59d2bd0fb84a570c75&eon=1"
```
Note: If eon is not passed, the api will use the current eon.

#### Example Response (Event-Based)
```json
{
  "decryption_key": "0x99a805fc26812c13041126b25e91eccf3de464d1df7a95d1edca8831a9ec02dd",
  "decryption_timestamp": 0,
  "identity": "0x8c232eae4f957259e9d6b68301d529e9851b8642874c8f59d2bd0fb84a570c75"
}
```

#### 3.B Decrypt Commitments

Once you have the decryption key, use it to decrypt commitments encrypted with the Shutter system. The `/decrypt_commitment` endpoint enables this process.

Refer to the Swagger documentation for endpoint details.

#### Example Request
```bash
curl -X GET "https://<API_BASE_URL>/decrypt_commitment?identity=0x8c232eae4f957259e9d6b68301d529e9851b8642874c8f59d2bd0fb84a570c75&encryptedCommitment=0x03b5685a460a95ba628e04b24155d6722f7c4e376a1627f714a4ae9cecd2982e005eff12ac8150b8842c29f8d5eaf4d0da0b626f762b4826d779d8969b577acb28df96cab026aa57c00cd74b07ca51e8c0c1a59933e29a728311900ebfc26c6804260914c96cb10dbd6d2ed3f6cb77788a74b5aae5f4ce6f40be53310a0524d42d5a6f03b5c1517ec097553733e228276fcdfc4b569f7ef4311a461d68819d634c"
```

#### Example Response
```json
{
  "decrypted_message": "0x706c6561736520686964652074686973206d657373616765"
}
```

The decrypted message is returned in its hex format. To get the initial message, convert the decrypted message to string.

> **Note**: Replace `<API_BASE_URL>` in all example requests with the actual base URL for the API, found in the pre-requisite section, such as `https://shutter-api.shutter.network/api`.

## Future Features

- **Block-Based Triggers**
  Future versions of the Shutter system will support block-based decryption triggers for enhanced functionality.

- **Real-Time Notifications**
  Planned updates include WebSocket-based notifications for real-time key releases, improving user experience and interactivity.

## FAQs

### What happens if a keyper experiences downtime?
The keyper set is designed to handle downtime gracefully. Any missed decryption key releases will be sent upon recovery.

### How secure is the Shutter system?
The Shutter system uses threshold encryption and distributed cryptographic operations to ensure that no single entity can compromise the security of commitments.

### Why is my decryption key not released after the given timestamp has elapsed?
This is probably because the decryption timestamp is not aligned to a Gnosis Chain block timestamp. We strictly follow Gnosis Chain block timestamps to release decryption keys i.e. every 5 seconds. In this case simply try again a few seconds later. 

## Swagger Documentation

For detailed API specifications, including parameters, responses, and error codes, visit the Swagger Documentation:

- [Chiado Swagger Documentation](https://shutter-api.chiado.staging.shutter.network/docs/index.html)
- [Mainnet Swagger Documentation](https://shutter-api.shutter.network/docs/index.html)

## Support

For additional support or inquiries:
- Contact the Shutter development team.
- Open an issue on our GitHub repository.

---

Thank you for using Shutter! Together, we are building a more secure and decentralized future.
