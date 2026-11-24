# CDK Payment Processor

The cdk-payment-processor is a Rust crate that provides both a binary and a library for handling payments to and from a cdk mint. 

## Overview

### Library Components
- **Payment Processor Server**: Handles interaction with payment processor backend implementations
- **Client**: Used by mintd to query the server for payment information
- **Backend Implementations**: Supports CLN, LND, and a fake wallet (for testing)

### Features
- Modular backend system supporting multiple payment backend implementations
- Extensible design allowing for custom backend implementations

## Building from Source

### Prerequisites
1. Install Nix package manager
2. Enter development environment (use `.#regtest` for full stack including CLN/LND):
```sh
nix develop
# or for full stack:
nix develop .#regtest
```

### Configuration

The server requires different environment variables depending on your chosen payment backend.

#### Core Settings
```sh
# Choose backend: CLN, LND, or FAKEWALLET
export CDK_PAYMENT_PROCESSOR_BACKEND="CLN"

# Server configuration
export CDK_PAYMENT_PROCESSOR_LISTEN_HOST="127.0.0.1"
export CDK_PAYMENT_PROCESSOR_LISTEN_PORT="8090"
```

When mintd connects with a TLS directory, the directory must contain
`ca.pem`, `client.pem`, and `client.key`. The CA certificate verifies the
payment processor, and the client certificate and private key authenticate
mintd to an mTLS-enabled processor. Configured TLS does not fall back to an
unauthenticated client connection when either client identity file is missing.

Mintd can explicitly opt into a plaintext connection with
`[grpc_processor].allow_insecure = true`, including for a non-loopback address.
This is unsafe on an untrusted network because the connection has no transport
authentication or encryption and can be intercepted or modified. Use plaintext
only on a trusted, isolated network or through a separately authenticated and
encrypted tunnel; prefer mTLS even for internal deployments.

#### Call deadline

The client waits at most 15 seconds for the answer of each call, except the send
(`MakePayment`). A send has no deadline, because the result of a dropped send is
unknown. For the event stream, the deadline covers the opening of the stream.
The value is a constant (`CALL_DEADLINE`).

A call past its deadline answers an error, as a call to an unreachable processor
does:

| Call | Effect in the mint |
| --- | --- |
| Settings at the mint start | The mint does not start |
| Settings, create payment | No mint quote |
| Payment quote | No melt quote |
| Check incoming payment | The mint quote does not change; the next check asks again |
| Check outgoing payment | The melt and its proofs stay pending; the next check asks again |
| Event stream | The mint opens the stream again after its backoff |

A late answer is dropped. The client opens two connections. The send has its own
connection, because a server can close a connection with many calls past their
deadline.

#### Backend-Specific Configuration

##### Core Lightning (CLN)
```sh
# Path to CLN RPC socket
export CDK_PAYMENT_PROCESSOR_CLN_RPC_PATH="/path/to/lightning-rpc"
```

##### Lightning Network Daemon (LND)
```sh
# LND connection details
export CDK_PAYMENT_PROCESSOR_LND_ADDRESS="localhost:10009"
export CDK_PAYMENT_PROCESSOR_LND_CERT_FILE="/path/to/tls.cert"
export CDK_PAYMENT_PROCESSOR_LND_MACAROON_FILE="/path/to/macaroon"
```

### Building and Running

Build and run the binary with your chosen backend:

```sh
# For CLN backend
cargo run --bin cdk-payment-processor --no-default-features --features cln

# For LND backend
cargo run --bin cdk-payment-processor --no-default-features --features lnd

# For fake wallet (testing only)
cargo run --bin cdk-payment-processor --no-default-features --features fake
```

## Development

To implement a new backend:
1. Create a new module implementing the payment processor traits
2. Add appropriate feature flags
3. Update the binary to support the new backend

For library usage examples and API documentation, refer to the crate documentation.
