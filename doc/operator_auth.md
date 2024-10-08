 Authentication protocol for VM owner
=======================================

This custom protocol allows a user (owner of a VM) to securely authenticate to a CRN, using their Ethereum or Solana
wallet. This scheme was designed in a way that's convenient to be integrated into the console web page.

It allows the user to control their VM. e.g: stop, reboot, view their log, etc.

## Motivations

This protocol ensures secure authentication between a blockchain wallet owner and an aleph.im compute node.

Signing operations are typically gated by prompts requiring manual approval for each operation. With hardware wallets,
users are prompted both by the software on their device and the hardware wallet itself.

## Overview

The client generates a [JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517) (JWK) key pair and signs the public key
with their Ethereum or Solana account. The signed public key is sent in the `X-SignedPubKey` header. The client also
signs the operation payload with the private JWK, sending it in the `X-SignedOperation` header. The server verifies both
the public key and payload signatures, ensuring the request's integrity and authenticity. If validation fails (e.g.,
expired key or invalid signature), the server returns a 401 Unauthorized error.


## Authentication Method for HTTP Endpoints

Two custom headers are added to each authenticated request:

- **X-SignedPubKey**: This contains the public key and its associated metadata (such as the sender’s address, chain, and
  expiration date), along with a signature that ensures its authenticity.
- **X-SignedOperation**: This includes the payload of the operation and its cryptographic signature, ensuring that the
  operation itself has not been tampered with.

### 1. Generate an ephemeral keys and Sign Public Key

An ephemeral key pair (as JWK) is generated using elliptic curve cryptography (EC, P-256).

The use of a temporary JWK key allows the user to delegate limited control to the console without needing to sign every
individual request with their Ethereum or Solana wallet. This is crucial for improving the user experience, as
constantly signing each operation would be cumbersome and inefficient. By generating a temporary key, the user can
provide permission for a set period of time (until the key expires), enabling the console to perform actions like
stopping or rebooting the VM on their behalf. This maintains security while streamlining interactions with the console,
as the server verifies each operation using the temporary key without requiring ongoing involvement from the user's
wallet.

The generated public key is converted into a JSON structure with additional metadata:

- **`pubkey`**: The public key information.
- **`alg`**: The signing algorithm, ECDSA.
- **`domain`**: The domain for which the key is valid.
- **`address`**: The wallet address of the sender, binding the temporary key to this identity.
- **`chain`**: Indicates the blockchain used for signing (`ETH` or `SOL`). Defaults to `ETH`.
- **`expires`**: The expiration time of the key.

Example:

```json
{
  "pubkey": {
    "crv": "P-256",
    "kty": "EC",
    "x": "hbslLmhG3h2RwuzBYNVeQ7WCbU-tUzMjSpCFO2i5-tA",
    "y": "KI4FJARKwyYcRy6xz1J9lu8OItV87Fw91eThe2hnnuc"
  },
  "alg": "ECDSA",
  "domain": "localhost",
  "address": "0x8Dd070629F107e7946dD68BDcb8ABE8475F47B0E",
  "chain": "ETH",
  "expires": "2010-12-26T17:05:55Z"
}
```

This public key is signed using either the Ethereum or Solana account, depending on the `chain` parameter. The resulting
signature is combined with the public key into a payload and sent as the `X-SignedPubKey` header.

### 2. Sign Operation Payload

#### Operation Payload Format

The operation payload is a JSON object that encapsulates the details of an API request. It ensures that the request's
integrity can be verified through signing. Below are the fields included:

- **`time`**: (string, ISO 8601 format) The timestamp for when the operation is valid, including the timezone is mandatory (`Z`
  indicates UTC). This helps prevent replay attacks (capturing the packet and replying it multiple time). e.g. `"2010-12-25T17:05:55Z"`
- **`method`**: (string) The HTTP method used for the operation (e.g., `GET`, `POST`).
- **`path`**: (string) The endpoint path of the request (e.g., `/`).
- **`domain`**: (string) The domain associated with the request. This ensures the request is valid for the intended
  CRN. (e.g., `localhost`).

Example:

```json
{
  "time": "2010-12-25T17:05:55Z",
  "method": "GET",
  "path": "/",
  "domain": "localhost"
}
```

It is sent serialized as a hex string.

#### Signature


- The operation payload (containing details such as time, method, path, and domain) is JSON serialized and converted into a
  hex string.
- The ephemeral key  (private key) is used to sign this operation payload, ensuring its integrity. This signature is then included
  in the `X-SignedOperation` header.

### 3. Include Authentication Headers

These two headers are to be added to the HTTP request:

1. **`X-SignedPubKey` Header**:
    - This header contains the public key payload and the signature of the public key generated by the Ethereum or
      Solana account.

   Example:

   ```json
   {
     "payload": "<hexadecimal string of the public key payload>",
     "signature": "<Ethereum or Solana signed public key>"
   }
   ```

2. **`X-SignedOperation` Header**:
    - This header contains the operation payload and the signature of the operation payload generated using the private
      JWK.

   Example:

   ```json
   {
     "payload": "<hexadecimal string of the operation payload>",
     "signature": "<JWK signed operation payload>"
   }
   ```

### Expiration and Validation

- The public key has an expiration date, ensuring that keys are not used indefinitely.
- Both the public key and the operation signature are validated for authenticity and integrity at the server side,
  taking into account the specified blockchain (Ethereum or Solana).
- Requests failing verification or expired keys are rejected with `401 Unauthorized` status, providing an error message
  indicating the reason.

## WebSocket Authentication Protocol

In the WebSocket variant of the authentication protocol, the client establishes a connection and authenticates through
an initial message that includes their Ethereum or Solana-signed identity, ensuring secure communication.

Due to web browsers not allowing custom HTTP headers in WebSocket connections, the two headers are sent in one JSON
packet, under the `auth` key.

Example authentication packet:

```json
{
    "auth": {
        "X-SignedPubKey": {
            "payload": "7b227075626b6579223a207b22637276223a2022502d323536222c20226b7479223a20224543222c202278223a20223962446f34754949686b735a5272677a31477972325050656d4334364e735f4730577144364d4d6a774673222c202279223a20226f48343342786c7854334f3065733336685967713143372d61325a535a71456d5f6b56356e636c79667a59227d2c2022616c67223a20224543445341222c2022646f6d61696e223a20226c6f63616c686f7374222c202261646472657373223a2022307862413236623135333539314434363230666432413734304130463165463730644164363532336230222c202265787069726573223a2022323031302d31322d32365431373a30353a35355a227d",
            "signature": "0xea99ef5f1a10f2d103f94dce4f8650730315246e6d15cf9e5862c11adfd6482703cd1ec684a4f3dffb36ae5c4a57b08a47108fe55e3b2454e45f6e63342e0f471b"
        },
        "X-SignedOperation": {
            "payload": "7b2274696d65223a2022323031302d31322d32355431373a30353a35355a222c20226d6574686f64223a2022474554222c202270617468223a20222f222c2022646f6d61696e223a20226c6f63616c686f7374227d",
            "signature": "6f737654cd00e4d4155d387509978e7a9a4d27f5b59c9492ac1dec7b09f9aecc58c9365526bbddd6211b65f40f4956c50ab26f395f7170ce1698c11e28e25d3a"
        }
    }
}
```

If the  authentication  succeed the server will answer with
```json
{
  "status": "connected"
}
```

In case of failed auth the server will respond with await `{"status": "failed", "reason": "string describing the reason"})` and close the connexion  
