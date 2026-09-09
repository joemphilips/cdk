//! CDK mint proto types

tonic::include_proto!("cdk_mint_management_v1");

mod peer_policy;

/// Keyset administration service
pub mod keyset {
    tonic::include_proto!("cdk_mint_keyset_v1");
}

mod server;

/// Protocol version for gRPC Mint RPC communication
pub use cdk_common::MINT_RPC_PROTOCOL_VERSION as PROTOCOL_VERSION;
pub use peer_policy::{PeerPolicy, PeerPolicyError};
pub use server::MintRPCServer;
