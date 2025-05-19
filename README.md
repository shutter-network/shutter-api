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
   - [Register an Identity with a Decryption Trigger](#1-register-an-identity-with-a-decryption-trigger)
   - [Retrieve the Encryption Data](#2-retrieve-the-encryption-data)
   - [Retrieve the Decryption Key](#3-retrieve-the-decryption-key)
   - [Decrypt Commitments](#4-decrypt-commitments)
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
- Setting up identities and time-based decryption triggers.
- Retrieving encryption data and decryption keys.
- Decrypting encrypted commitments.

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

  - `/register_identity` 5 requests per 24 hours
  - `/get_data_for_encryption` 10 requests per 24 hours
  - `/get_decryption_key` 20 requests per 24 hours
  - `/decrypt_commitment` 10 requests per 24 hours

We recommend using Chiado for development, because there are no rate limits in place.

If you need higher limits, contact [loring@brainbot.com](mailto:loring@brainbot.com) to request an API key.

Authorized requests have these limits:

  - `/register_identity` 500 requests per 24 hours
  - `/get_data_for_encryption` 1000 requests per 24 hours
  - `/get_decryption_key` 2000 requests per 24 hours
  - `/decrypt_commitment` 1000 requests per 24 hours

Authorization is done by using an `Authorization: Bearer $API_KEY` header, when calling the API.

---

## Endpoints

### 1. Register an Identity with a Decryption Trigger

To begin using the Shutter system, register an identity and specify a time-based decryption trigger. This step links an identity to a decryption key and sets the release conditions for the key to a Unix timestamp.

Refer to the `/register_identity` endpoint in the Swagger documentation for details on parameters and responses.

> **Note**: When registering identities through our API, the API account address is used to compute the identity that will be returned. If you want to use your own address, you need to submit the registration directly to the registry contract. The contract's definition can be found here:  
> [ShutterRegistry.sol](https://github.com/shutter-network/contracts/blob/main/src/shutter-service/ShutterRegistry.sol#L1C1-L86C2).

#### Example Request
```bash
curl -X POST https://<API_BASE_URL>/register_identity \
-H "Content-Type: application/json" \
-d '{
  "decryptionTimestamp": 1735044061,
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

### 2. Retrieve the Encryption Data

To encrypt commitments, obtain the encryption data associated with your identity. Use the `/get_data_for_encryption` endpoint to retrieve all necessary encryption data.

Refer to the Swagger documentation for specifics on this endpoint.

#### Example Request
```bash
curl -X GET "https://<API_BASE_URL>/get_data_for_encryption?address=0xb9C303443c9af84777e60D5C987AbF0c43844918&identityPrefix=0x79bc8f6b4fcb02c651d6a702b7ad965c7fca19e94a9646d21ae90c8b54c030a0"
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

### 3. Retrieve the Decryption Key

After the decryption trigger conditions are met (i.e., the specified timestamp has passed), retrieve the decryption key using the `/get_decryption_key` endpoint.

Refer to the Swagger documentation for detailed usage.

#### Example Request
```bash
curl -X GET "https://<API_BASE_URL>/get_decryption_key?identity=0x8c232eae4f957259e9d6b68301d529e9851b8642874c8f59d2bd0fb84a570c75"
```

#### Example Response
```json
{
  "decryption_key": "0x99a805fc26812c13041126b25e91eccf3de464d1df7a95d1edca8831a9ec02dd",
  "decryption_timestamp": 1735044061,
  "identity": "0x8c232eae4f957259e9d6b68301d529e9851b8642874c8f59d2bd0fb84a570c75"
}
```

### 4. Decrypt Commitments

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

- **Event-Based and Block-Based Triggers**  
  Future versions of the Shutter system will support event-based and block-based decryption triggers for enhanced functionality.

- **Real-Time Notifications**  
  Planned updates include WebSocket-based notifications for real-time key releases, improving user experience and interactivity.

## FAQs

### What happens if a keyper experiences downtime?
The keyper set is designed to handle downtime gracefully. Any missed decryption key releases will be sent upon recovery.

### How secure is the Shutter system?
The Shutter system uses threshold encryption and distributed cryptographic operations to ensure that no single entity can compromise the security of commitments.

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
