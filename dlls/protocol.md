Matryoshka Network Protocol Specification

Version: 1.0 Module: Core Cryptography & Circuit Builder (Person 4)
1. Overview

The Matryoshka network uses a Hybrid Encryption Scheme to maximize performance and security.

    Asymmetric: RSA-2048 with OAEP Padding (Used for encrypting session keys).

    Symmetric: AES-256 CBC Mode (Used for encrypting the actual payload).

    Transport: JSON-formatted text messages.

2. Packet Structure (Wire Format)

When a Relay receives a packet from a Client or previous Relay, it receives a JSON object containing the cipher block.
JSON

{
  "cipher": {
    "enc_key": "<Base64 encoded encrypted AES-256 key>",
    "enc_iv": "<Base64 encoded AES Initialization Vector>",
    "enc_payload": "<Base64 encoded encrypted data blob>"
  }
}

3. Decryption Logic (For Relay Nodes)

Do not implement this manually. Use the provided matryoshka.dll and decrypt_layer function.

    Extract Keys: The enc_key and enc_iv are decrypted using the Relay's RSA Private Key.

    Decrypt Payload: The enc_payload is decrypted using the extracted AES key/IV.

    Parse Result: The decrypted bytes form a JSON object containing routing instructions.

Decrypted Output Format

The decrypt_layer function returns this structure:
JSON

{
  "next_hop": "192.168.1.5:8001",
  "remaining_payload_b64": "<Base64 encoded blob for the next hop>"
}

4. Error Codes (Library)

If the C++ library returns a non-zero code:

    -1 to -2: Invalid Input / Memory Error.

    -3: Crypto Failure (Wrong Private Key or Corrupted Data).

    -4: Parse Error (Decrypted data was not valid JSON).