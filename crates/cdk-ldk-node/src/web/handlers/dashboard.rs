use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Html;
use ldk_node::bitcoin::secp256k1::PublicKey;
use ldk_node::lightning::chain::channelmonitor::BalanceSource;
use ldk_node::lightning::ln::types::ChannelId;
use ldk_node::payment::{PaymentDirection, PaymentKind, PaymentStatus};
use ldk_node::{ChannelDetails, LightningBalance, PendingSweepBalance};
use maud::html;

use crate::web::handlers::AppState;
use crate::web::templates::{format_sats_as_btc, is_node_running, layout_with_status};

#[derive(Debug)]
pub struct UsageMetrics {
    pub lightning_inflow_24h: u64,
    pub lightning_outflow_24h: u64,
    pub lightning_inflow_all_time: u64,
    pub lightning_outflow_all_time: u64,
    pub onchain_inflow_24h: u64,
    pub onchain_outflow_24h: u64,
    pub onchain_inflow_all_time: u64,
    pub onchain_outflow_all_time: u64,
}

/// Calculate usage metrics from payment history
fn calculate_usage_metrics(payments: &[ldk_node::payment::PaymentDetails]) -> UsageMetrics {
    use web_time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let twenty_four_hours_ago = now.saturating_sub(24 * 60 * 60);

    let mut metrics = UsageMetrics {
        lightning_inflow_24h: 0,
        lightning_outflow_24h: 0,
        lightning_inflow_all_time: 0,
        lightning_outflow_all_time: 0,
        onchain_inflow_24h: 0,
        onchain_outflow_24h: 0,
        onchain_inflow_all_time: 0,
        onchain_outflow_all_time: 0,
    };

    for payment in payments {
        if payment.status != PaymentStatus::Succeeded {
            continue;
        }

        let amount_sats = payment.amount_msat.unwrap_or(0) / 1000;
        let is_recent = payment.latest_update_timestamp >= twenty_four_hours_ago;

        match &payment.kind {
            PaymentKind::Bolt11 { .. }
            | PaymentKind::Bolt12Offer { .. }
            | PaymentKind::Bolt12Refund { .. }
            | PaymentKind::Spontaneous { .. }
            | PaymentKind::Bolt11Jit { .. } => match payment.direction {
                PaymentDirection::Inbound => {
                    metrics.lightning_inflow_all_time += amount_sats;
                    if is_recent {
                        metrics.lightning_inflow_24h += amount_sats;
                    }
                }
                PaymentDirection::Outbound => {
                    metrics.lightning_outflow_all_time += amount_sats;
                    if is_recent {
                        metrics.lightning_outflow_24h += amount_sats;
                    }
                }
            },
            PaymentKind::Onchain { .. } => match payment.direction {
                PaymentDirection::Inbound => {
                    metrics.onchain_inflow_all_time += amount_sats;
                    if is_recent {
                        metrics.onchain_inflow_24h += amount_sats;
                    }
                }
                PaymentDirection::Outbound => {
                    metrics.onchain_outflow_all_time += amount_sats;
                    if is_recent {
                        metrics.onchain_outflow_24h += amount_sats;
                    }
                }
            },
        }
    }

    metrics
}

/// The Lightning balance of the ready channels, in sats.
///
/// `total_lightning_balance_sats` covers every channel monitor. A monitor
/// exists before the funding transaction confirms, and it stays when the peer
/// drops the channel. Thus a peer can add a push that never confirms to that
/// total. This sum covers only a channel that the node lists as ready and with
/// a confirmation. A connected peer is not necessary.
fn ready_channel_balance_sats(channels: &[ChannelDetails], balances: &[LightningBalance]) -> u64 {
    let is_ready = |channel_id: &ChannelId, counterparty_node_id: &PublicKey| {
        channels.iter().any(|channel| {
            channel.channel_id == *channel_id
                && channel.counterparty_node_id == *counterparty_node_id
                && channel.is_channel_ready
                && channel.confirmations.is_some_and(|count| count >= 1)
        })
    };

    balances
        .iter()
        .map(|balance| match balance {
            // As in the total, a forwarded HTLC in flight still counts.
            LightningBalance::ClaimableOnChannelClose {
                channel_id,
                counterparty_node_id,
                amount_satoshis,
                ..
            }
            | LightningBalance::MaybeTimeoutClaimableHTLC {
                channel_id,
                counterparty_node_id,
                amount_satoshis,
                outbound_payment: false,
                ..
            } => {
                if is_ready(channel_id, counterparty_node_id) {
                    *amount_satoshis
                } else {
                    0
                }
            }
            // As in the total, these HTLCs do not count: the peer can still claim
            // them, or this node does not know their preimage.
            LightningBalance::MaybeTimeoutClaimableHTLC {
                outbound_payment: true,
                ..
            }
            | LightningBalance::MaybePreimageClaimableHTLC { .. } => 0,
            // The commitment transaction is on chain: the channel is closed.
            LightningBalance::ClaimableAwaitingConfirmations { .. }
            | LightningBalance::ContentiousClaimable { .. }
            | LightningBalance::CounterpartyRevokedOutputClaimable { .. } => 0,
        })
        .sum()
}

/// The funds of closed channels that the on-chain wallet does not count, in sats.
///
/// It covers an output of a force close from the first confirmation of the
/// commitment transaction until the node broadcasts its sweep. LDK reports
/// these two states only for a transaction in a block. An amount that the
/// wallet can also count is not included, so that the sum of the ready, the
/// closing and the on-chain balance counts no amount twice.
fn closing_channel_balance_sats(
    lightning_balances: &[LightningBalance],
    sweeps: &[PendingSweepBalance],
) -> u64 {
    let awaiting_confirmations = lightning_balances.iter().map(|balance| match balance {
        LightningBalance::ClaimableAwaitingConfirmations {
            amount_satoshis,
            source,
            ..
        } => match source {
            // The output needs a sweep to the on-chain wallet. The exception is
            // the penalty claim of a revoked commitment: LDK gives it the same
            // source, and the wallet also counts it, for at most 6 blocks.
            BalanceSource::HolderForceClosed | BalanceSource::CounterpartyForceClosed => {
                *amount_satoshis
            }
            // The output pays to the on-chain wallet. LDK also reports this
            // state when a peer spends an outpoint that never funded a channel.
            BalanceSource::CoopClose => 0,
            // The claim can pay to the on-chain wallet.
            BalanceSource::Htlc => 0,
        },
        // The closing transaction has no confirmation, or the channel is open.
        LightningBalance::ClaimableOnChannelClose { .. } => 0,
        // The peer can still take these amounts, and the claim pays to the
        // on-chain wallet.
        LightningBalance::ContentiousClaimable { .. }
        | LightningBalance::MaybeTimeoutClaimableHTLC { .. }
        | LightningBalance::MaybePreimageClaimableHTLC { .. }
        | LightningBalance::CounterpartyRevokedOutputClaimable { .. } => 0,
    });
    let sweeps = sweeps.iter().map(|sweep| match sweep {
        PendingSweepBalance::PendingBroadcast {
            amount_satoshis, ..
        } => *amount_satoshis,
        // The sweep transaction pays to the on-chain wallet.
        PendingSweepBalance::BroadcastAwaitingConfirmation { .. }
        | PendingSweepBalance::AwaitingThresholdConfirmations { .. } => 0,
    });
    awaiting_confirmations.chain(sweeps).sum()
}

pub async fn dashboard(State(state): State<AppState>) -> Result<Html<String>, StatusCode> {
    let node = &state.node.inner;

    let node_id = node.node_id().to_string();
    let alias = node
        .node_alias()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "No alias set".to_string());

    let listening_addresses: Vec<String> = state
        .node
        .inner
        .announcement_addresses()
        .as_ref()
        .unwrap_or(&vec![])
        .iter()
        .map(|a| a.to_string())
        .collect();

    let (num_peers, num_connected_peers) =
        node.list_peers()
            .iter()
            .fold((0, 0), |(mut peers, mut connected), p| {
                if p.is_connected {
                    connected += 1;
                }
                peers += 1;
                (peers, connected)
            });

    let channels = node.list_channels();
    let (num_active_channels, num_inactive_channels) =
        channels
            .iter()
            .fold((0, 0), |(mut active, mut inactive), c| {
                if c.is_usable {
                    active += 1;
                } else {
                    inactive += 1;
                }
                (active, inactive)
            });

    let balances = node.list_balances();
    let ready_channel_balance = ready_channel_balance_sats(&channels, &balances.lightning_balances);
    let closing_channel_balance = closing_channel_balance_sats(
        &balances.lightning_balances,
        &balances.pending_balances_from_channel_closures,
    );

    // Calculate payment metrics for dashboard
    let all_payments = node.list_payments_with_filter(|_| true);
    let metrics = calculate_usage_metrics(&all_payments);

    let content = html! {
        h2 style="text-align: center; margin-bottom: 3rem;" { "Dashboard" }

        // Balance Summary as metric cards
        div class="card" {
            h2 style="font-size: 0.875rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; opacity: 0.5; padding-bottom: 1rem; border-bottom: 1px solid hsl(var(--border)); margin-bottom: 0;" { "Balance Summary" }
            div class="metrics-container" style="margin-top: 1.5rem;" {
                div class="metric-card" {
                    div class="metric-value" { (format_sats_as_btc(balances.total_lightning_balance_sats)) }
                    div class="metric-label" { "Lightning Balance" }
                }
                div class="metric-card" {
                    div class="metric-value" { (format_sats_as_btc(ready_channel_balance)) }
                    div class="metric-label" { "Ready Channel Balance" }
                }
                div class="metric-card" {
                    div class="metric-value" { (format_sats_as_btc(closing_channel_balance)) }
                    div class="metric-label" { "Closing Channel Balance" }
                }
                div class="metric-card" {
                    div class="metric-value" { (format_sats_as_btc(balances.total_onchain_balance_sats)) }
                    div class="metric-label" { "On-chain Balance" }
                }
                div class="metric-card" {
                    div class="metric-value" { (format_sats_as_btc(balances.spendable_onchain_balance_sats)) }
                    div class="metric-label" { "Spendable Balance" }
                }
                div class="metric-card" {
                    div class="metric-value" { (format_sats_as_btc(balances.total_lightning_balance_sats + balances.total_onchain_balance_sats)) }
                    div class="metric-label" { "Combined Total" }
                }
            }
        }

        // Node Information - new layout based on Figma design
        section class="node-info-section" {
            div class="node-info-main-container" {
                // Left side - Node avatar and info
                div class="node-info-left" {
                    div class="node-avatar" {
                        img src="/static/images/nut.png" alt="Node Avatar" class="avatar-image";
                    }
                    div class="node-details" {
                        h2 class="node-name" { (alias.clone()) }
                        p class="node-address" {
                            "Node ID: " (node_id)
                        }
                        p class="node-address" {
                            "Listening Address: "
                            (listening_addresses.first().unwrap_or(&"127.0.0.1:8090".to_string()))
                        }
                    }
                }

                // Middle - Gray container with spinning globe animation
                div class="node-content-box" {
                    div class="globe-container" {
                        svg aria-hidden="true" style="position: absolute; width: 0; height: 0; overflow: hidden;" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" {
                            defs {
                                symbol id="icon-world" viewBox="0 0 216 100" {
                                    title { "world" }
                                    g fill-rule="nonzero" {
                                        path d="M48 94l-3-4-2-14c0-3-1-5-3-8-4-5-6-9-4-11l1-4 1-3c2-1 9 0 11 1l3 2 2 3 1 2 8 2c1 1 2 2 0 7-1 5-2 7-4 7l-2 3-2 4-2 3-2 1c-2 2-2 9 0 10v1l-3-2zM188 90l3-2h1l-4 2zM176 87h2l-1 1-1-1zM195 86l3-2-2 2h-1zM175 83l-1-2-2-1-6 1c-5 1-5 1-5-2l1-4 2-2 4-3c5-4 9-5 9-3 0 3 3 3 4 1s1-2 1 0l3 4c2 4 1 6-2 10-4 3-7 4-8 1zM100 80c-2-4-4-11-3-14l-1-6c-1-1-2-3-1-4 0-2-4-3-9-3-4 0-5 0-7-3-1-2-2-4-1-7l3-6 3-3c1-2 10-4 11-2l6 3 5-1c3 1 4 0 5-1s-1-2-2-2l-4-1c0-1 3-3 6-2 3 0 3 0 2-2-2-2-6-2-7 0l-2 2-1 2-3-2-3-3c-1 0-1 1 1 2l1 2-2-1c-4-3-6-2-8 1-2 2-4 3-5 1-1-1 0-4 2-4l2-2 1-2 3-2 3-2 2 1c3 0 7-3 5-4l-1-3h-1l-1 3-2 2h-1l-2-1c-2-1-2-1 1-4 5-4 6-4 11-3 4 1 4 1 2 2v1l3-1 6-1c5 0 6-1 5-2l2 1c1 2 2 2 2 1-2-4 12-7 14-4l11 1 29 3 1 2-3 3c-2 0-2 0-1 1l1 3h-2c-1-1-2-3-1-4h-4l-6 2c-1 1-1 1 2 2 3 2 4 6 1 8v3c1 3 0 3-3 0s-4-1-2 3c3 4 3 7-2 8-5 2-4 1-2 5 2 3 0 5-3 4l-2-1-2-2-1-1-1-1-2-2c-1-2-1-2-4 0-2 1-3 4-3 5-1 3-1 3-3 1l-2-4c0-2-1-3-2-3l-1-1-4-2-6-1-4-2c-1 1 3 4 5 4h2c1 1 0 2-1 4-3 2-7 4-8 3l-7-10 5 10c2 2 3 3 5 2 3 0 2 1-2 7-4 4-4 5-4 8 1 3 1 4-1 6l-2 3c0 2-6 9-8 9l-3-2zm22-51l-2-3-1-1v-1c-2 0-2 2-1 4 2 3 4 4 4 1z" {}
                                        path d="M117 75c-1-2 0-6 2-7h2l-2 5c0 2-1 3-2 1zM186 64h-3c-2 0-6-3-5-5 1-1 6 1 7 3l2 3-2-1zM160 62h2c1 1 0 1-1 1l-1-1zM154 57l-1-2c2 2 3 1 2-2l-2-3 2 2 1 4 1 3v2l-3-4zM161 59c-1-1-1-2 1-4 3-3 4-3 4 0 0 4-2 6-5 4zM167 59l1-1 1 1-1 1-1-1zM176 59l1-1v2l-1-1zM141 52l1-1v2l-1-1zM170 52l1-1v2l-1-1zM32 50c-1-2-4-3-6-4-4-1-5-3-7-6l-3-5-2-2c-1-3-1-6 2-9 1-1 2-3 1-5 0-4-3-5-8-4H4l2-2 1-1 1-1 2-1c1-2 7-2 23-1 12 1 12 1 12-1h1c1 1 2 2 3 1l1 1-3 1c-2 0-8 4-8 5l2 1 2 3 4-3c3-4 4-4 5-3l3 1 1 2 1 2c3 0-1 2-4 2-2 0-2 0-2 2 1 1 0 2-2 2-4 1-12 9-12 12 0 2 0 2-1 1 0-2-2-3-6-2-3 0-4 1-4 3-2 4 0 6 3 4 3-1 3-1 2 1s-1 2 1 2l1 2 1 3 1 1-3-2zm8-24l1-1c0-1-4-3-5-2l1 1v2c-1 1-1 1 0 0h3zM167 47v-3l1 2c1 2 0 3-1 1z" {}
                                        path d="M41 43h2l-1 1-1-1zM37 42v-1l2 1h-2zM16 38l1-1v2l-1-1zM172 32l2-3h1c1 2 0 4-3 4v-1zM173 26h2l-1 1-1-1zM56 22h2l-2 1v-1zM87 19l1-2 1 3-1 1-1-2zM85 19l1-1v1l-1 1v-1zM64 12l1-3c2 0-1-4-3-4s-2 0 0-1V3l-6 2c-3 1-3 1-2-1 2-1 4-2 15-2h14c0 2-6 7-10 9l-5 2-2 1-2-2zM53 12l1-1c2 0-1-3-3-3-2-1-1-1 1-1l4 2c2 1 2 1 1 3-2 1-4 2-4 0zM80 12l1-1 1 1-1 1-1-1zM36 8h-2V7c1-1 7 0 7 1h-5zM116 7l1-1v1l-1 1V7zM50 5h2l-1 1-1-1zM97 5l2-1c0-1 1-1 0 0l-2 1z" {}
                                    }
                                }
                                symbol id="icon-repeated-world" viewBox="0 0 432 100" {
                                    use href="#icon-world" x="0" {}
                                    use href="#icon-world" x="189" {}
                                }
                            }
                        }
                        span class="world" {
                            span class="images" {
                                svg { use href="#icon-repeated-world" {} }
                            }
                        }
                    }
                }
            }

            // Right side - Connections metrics
            aside class="node-metrics" {
                div class="card" {
                    h3 style="font-size: 0.875rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; opacity: 0.5; padding-bottom: 1rem; border-bottom: 1px solid hsl(var(--border)); margin-bottom: 0;" { "Connections" }
                    div class="metrics-container" style="margin-top: 1.5rem;" {
                        div class="metric-card" {
                            div class="metric-value" { (format!("{}/{}", num_connected_peers, num_peers)) }
                            div class="metric-label" { "Connected Peers" }
                        }
                        div class="metric-card" {
                            div class="metric-value" { (format!("{}/{}", num_active_channels, num_active_channels + num_inactive_channels)) }
                            div class="metric-label" { "Active Channels" }
                        }
                    }
                }
            }
        }

        // Activity Sections - Side by Side Layout
        div class="card" {
            h2 style="font-size: 0.875rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; opacity: 0.5; padding-bottom: 1rem; margin-bottom: 0;" { "Activity Overview" }

            div class="activity-grid" {
                // Lightning Network Activity
                div class="activity-section" {
                    div class="activity-header" {
                        div class="activity-icon-box" {
                            svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round" {
                                path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z" {}
                            }
                        }
                        h3 class="activity-title" { "Lightning Network Activity" }
                    }

                    div class="activity-metrics" {
                        div class="activity-metric-card" {
                            div class="activity-metric-label" { "24h Inflow" }
                            div class="activity-metric-value" { (format_sats_as_btc(metrics.lightning_inflow_24h)) }
                        }
                        div class="activity-metric-card" {
                            div class="activity-metric-label" { "24h Outflow" }
                            div class="activity-metric-value" { (format_sats_as_btc(metrics.lightning_outflow_24h)) }
                        }
                        div class="activity-metric-card" {
                            div class="activity-metric-label" { "All-time Inflow" }
                            div class="activity-metric-value" { (format_sats_as_btc(metrics.lightning_inflow_all_time)) }
                        }
                        div class="activity-metric-card" {
                            div class="activity-metric-label" { "All-time Outflow" }
                            div class="activity-metric-value" { (format_sats_as_btc(metrics.lightning_outflow_all_time)) }
                        }
                    }
                }

                // On-chain Activity
                div class="activity-section" {
                    div class="activity-header" {
                        div class="activity-icon-box" {
                            svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round" {
                                path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" {}
                                path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" {}
                            }
                        }
                        h3 class="activity-title" { "On-chain Activity" }
                    }

                    div class="activity-metrics" {
                        div class="activity-metric-card" {
                            div class="activity-metric-label" { "24h Inflow" }
                            div class="activity-metric-value" { (format_sats_as_btc(metrics.onchain_inflow_24h)) }
                        }
                        div class="activity-metric-card" {
                            div class="activity-metric-label" { "24h Outflow" }
                            div class="activity-metric-value" { (format_sats_as_btc(metrics.onchain_outflow_24h)) }
                        }
                        div class="activity-metric-card" {
                            div class="activity-metric-label" { "All-time Inflow" }
                            div class="activity-metric-value" { (format_sats_as_btc(metrics.onchain_inflow_all_time)) }
                        }
                        div class="activity-metric-card" {
                            div class="activity-metric-label" { "All-time Outflow" }
                            div class="activity-metric-value" { (format_sats_as_btc(metrics.onchain_outflow_all_time)) }
                        }
                    }
                }
            }
        }
    };

    let is_running = is_node_running(&state.node.inner);
    Ok(Html(
        layout_with_status("Dashboard", content, is_running).into_string(),
    ))
}

#[cfg(test)]
mod tests {
    use ldk_node::bitcoin::hashes::Hash;
    use ldk_node::bitcoin::{BlockHash, Txid};
    use ldk_node::config::ChannelConfig;
    use ldk_node::lightning_types::payment::{PaymentHash, PaymentPreimage};
    use ldk_node::UserChannelId;

    use super::*;

    const PEER: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const OTHER_PEER: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const CHANNEL: ChannelId = ChannelId([1; 32]);
    const OTHER_CHANNEL: ChannelId = ChannelId([2; 32]);

    fn peer(node_id: &str) -> PublicKey {
        node_id.parse().expect("node ID")
    }

    /// A confirmed, ready channel with a connected peer.
    fn ready_channel(channel_id: ChannelId) -> ChannelDetails {
        ChannelDetails {
            channel_id,
            counterparty_node_id: peer(PEER),
            funding_txo: None,
            short_channel_id: Some(42),
            outbound_scid_alias: None,
            inbound_scid_alias: None,
            channel_value_sats: 500_000,
            unspendable_punishment_reserve: Some(5_000),
            user_channel_id: UserChannelId(1),
            feerate_sat_per_1000_weight: 253,
            outbound_capacity_msat: 245_000_000,
            inbound_capacity_msat: 245_000_000,
            confirmations_required: Some(3),
            confirmations: Some(6),
            is_outbound: false,
            is_channel_ready: true,
            is_usable: true,
            is_announced: false,
            cltv_expiry_delta: None,
            counterparty_unspendable_punishment_reserve: 5_000,
            counterparty_outbound_htlc_minimum_msat: None,
            counterparty_outbound_htlc_maximum_msat: None,
            counterparty_forwarding_info_fee_base_msat: None,
            counterparty_forwarding_info_fee_proportional_millionths: None,
            counterparty_forwarding_info_cltv_expiry_delta: None,
            next_outbound_htlc_limit_msat: 0,
            next_outbound_htlc_minimum_msat: 0,
            force_close_spend_delay: None,
            inbound_htlc_minimum_msat: 1,
            inbound_htlc_maximum_msat: None,
            config: ChannelConfig::default(),
        }
    }

    /// The balance that the channel monitor of an open channel reports.
    fn open_balance(channel_id: ChannelId, amount_satoshis: u64) -> LightningBalance {
        LightningBalance::ClaimableOnChannelClose {
            channel_id,
            counterparty_node_id: peer(PEER),
            amount_satoshis,
            transaction_fee_satoshis: 0,
            outbound_payment_htlc_rounded_msat: 0,
            outbound_forwarded_htlc_rounded_msat: 0,
            inbound_claiming_htlc_rounded_msat: 0,
            inbound_htlc_rounded_msat: 0,
        }
    }

    #[test]
    fn a_ready_channel_counts() {
        assert_eq!(
            ready_channel_balance_sats(
                &[ready_channel(CHANNEL)],
                &[open_balance(CHANNEL, 250_000)]
            ),
            250_000
        );
    }

    #[test]
    fn an_offline_confirmed_channel_counts() {
        let offline = ChannelDetails {
            is_usable: false,
            ..ready_channel(CHANNEL)
        };
        assert_eq!(
            ready_channel_balance_sats(&[offline], &[open_balance(CHANNEL, 250_000)]),
            250_000
        );
    }

    /// The monitor of an inbound channel reports the push before the funding
    /// transaction confirms. The peer can open such a channel at no cost.
    #[test]
    fn an_inbound_pending_channel_with_a_push_counts_nothing() {
        let pending = ChannelDetails {
            short_channel_id: None,
            confirmations: Some(0),
            is_channel_ready: false,
            is_usable: false,
            ..ready_channel(OTHER_CHANNEL)
        };
        assert_eq!(
            ready_channel_balance_sats(
                &[ready_channel(CHANNEL), pending],
                &[
                    open_balance(CHANNEL, 250_000),
                    open_balance(OTHER_CHANNEL, 249_000)
                ],
            ),
            250_000
        );
    }

    #[test]
    fn each_condition_of_a_ready_channel_is_necessary() {
        for (case, channel) in [
            (
                "confirmed, but not ready",
                ChannelDetails {
                    is_channel_ready: false,
                    ..ready_channel(CHANNEL)
                },
            ),
            (
                "ready without a confirmation",
                ChannelDetails {
                    confirmations: Some(0),
                    ..ready_channel(CHANNEL)
                },
            ),
            (
                "ready with an unknown confirmation count",
                ChannelDetails {
                    confirmations: None,
                    ..ready_channel(CHANNEL)
                },
            ),
        ] {
            assert_eq!(
                ready_channel_balance_sats(&[channel], &[open_balance(CHANNEL, 250_000)]),
                0,
                "{case}"
            );
        }
    }

    /// The peer dropped an unfunded channel: the node lists it no more, but its
    /// monitor and the push stay.
    #[test]
    fn a_dropped_channel_whose_monitor_remains_counts_nothing() {
        assert_eq!(
            ready_channel_balance_sats(
                &[ready_channel(CHANNEL)],
                &[
                    open_balance(CHANNEL, 250_000),
                    open_balance(OTHER_CHANNEL, 249_000)
                ],
            ),
            250_000
        );
    }

    #[test]
    fn a_monitor_of_another_peer_counts_nothing() {
        let other = ChannelDetails {
            counterparty_node_id: peer(OTHER_PEER),
            ..ready_channel(CHANNEL)
        };
        assert_eq!(
            ready_channel_balance_sats(&[other], &[open_balance(CHANNEL, 250_000)]),
            0
        );
    }

    /// The amounts of one channel follow `total_lightning_balance_sats`: an
    /// in-flight HTLC of a payment of this node does not count, a forwarded one does.
    #[test]
    fn in_flight_htlcs_count_as_in_the_total() {
        let htlc =
            |amount_satoshis, outbound_payment| LightningBalance::MaybeTimeoutClaimableHTLC {
                channel_id: CHANNEL,
                counterparty_node_id: peer(PEER),
                amount_satoshis,
                claimable_height: 100,
                payment_hash: PaymentHash([3; 32]),
                outbound_payment,
            };
        assert_eq!(
            ready_channel_balance_sats(
                &[ready_channel(CHANNEL)],
                &[
                    open_balance(CHANNEL, 200_000),
                    htlc(7_000, true),
                    htlc(30, false),
                    LightningBalance::MaybePreimageClaimableHTLC {
                        channel_id: CHANNEL,
                        counterparty_node_id: peer(PEER),
                        amount_satoshis: 900,
                        expiry_height: 100,
                        payment_hash: PaymentHash([4; 32]),
                    },
                ],
            ),
            200_030
        );
    }

    /// The balance of a channel whose closing transaction has a confirmation.
    fn closed_balance(source: BalanceSource, amount_satoshis: u64) -> LightningBalance {
        LightningBalance::ClaimableAwaitingConfirmations {
            channel_id: CHANNEL,
            counterparty_node_id: peer(PEER),
            amount_satoshis,
            confirmation_height: 144,
            source,
        }
    }

    /// The three states of the sweep of one output.
    fn sweep_states(amount_satoshis: u64) -> [PendingSweepBalance; 3] {
        let channel_id = Some(CHANNEL);
        let latest_spending_txid = Txid::all_zeros();
        [
            PendingSweepBalance::PendingBroadcast {
                channel_id,
                amount_satoshis,
            },
            PendingSweepBalance::BroadcastAwaitingConfirmation {
                channel_id,
                latest_broadcast_height: 150,
                latest_spending_txid,
                amount_satoshis,
            },
            PendingSweepBalance::AwaitingThresholdConfirmations {
                channel_id,
                latest_spending_txid,
                confirmation_hash: BlockHash::all_zeros(),
                confirmation_height: 151,
                amount_satoshis,
            },
        ]
    }

    #[test]
    fn no_channel_close_counts_nothing() {
        assert_eq!(closing_channel_balance_sats(&[], &[]), 0);
    }

    /// Before the confirmation, the monitor reports the same balance as for an
    /// open channel, also when the node lists the channel no more. The dropped
    /// channel whose funding never confirmed is in this state without an end.
    #[test]
    fn a_close_without_a_confirmation_counts_nothing() {
        for case in [
            "a cooperative close",
            "a force close",
            "a dropped unfunded channel",
        ] {
            let balance = open_balance(CHANNEL, 250_000);
            assert_eq!(closing_channel_balance_sats(&[balance], &[]), 0, "{case}");
        }
    }

    #[test]
    fn a_confirmed_force_close_of_either_side_counts() {
        for (case, source) in [
            ("this node", BalanceSource::HolderForceClosed),
            ("the peer", BalanceSource::CounterpartyForceClosed),
        ] {
            let balance = closed_balance(source, 249_000);
            assert_eq!(
                closing_channel_balance_sats(&[balance], &[]),
                249_000,
                "closed by {case}"
            );
        }
    }

    /// The output pays to an address of the on-chain wallet, which counts it.
    /// LDK also reports this state for an unfunded channel, when the peer
    /// spends the outpoint that it named as the funding output.
    #[test]
    fn a_confirmed_cooperative_close_counts_nothing() {
        let balance = closed_balance(BalanceSource::CoopClose, 250_000);
        assert_eq!(closing_channel_balance_sats(&[balance], &[]), 0);
    }

    /// Only an output without a sweep transaction is outside of the on-chain
    /// wallet. A sweep transaction pays to that wallet.
    #[test]
    fn an_output_counts_until_its_sweep_is_broadcast() {
        let [before, broadcast, confirmed] = sweep_states(248_000);
        assert_eq!(closing_channel_balance_sats(&[], &[before]), 248_000);
        assert_eq!(closing_channel_balance_sats(&[], &[broadcast]), 0);
        assert_eq!(closing_channel_balance_sats(&[], &[confirmed]), 0);
    }

    #[test]
    fn the_htlcs_and_penalties_of_a_closed_channel_count_nothing() {
        let channel_id = CHANNEL;
        let counterparty_node_id = peer(PEER);
        let payment_hash = PaymentHash([3; 32]);
        let balances = [
            closed_balance(BalanceSource::Htlc, 900),
            LightningBalance::ContentiousClaimable {
                channel_id,
                counterparty_node_id,
                amount_satoshis: 900,
                timeout_height: 200,
                payment_hash,
                payment_preimage: PaymentPreimage([4; 32]),
            },
            LightningBalance::MaybeTimeoutClaimableHTLC {
                channel_id,
                counterparty_node_id,
                amount_satoshis: 900,
                claimable_height: 200,
                payment_hash,
                outbound_payment: false,
            },
            LightningBalance::MaybePreimageClaimableHTLC {
                channel_id,
                counterparty_node_id,
                amount_satoshis: 900,
                expiry_height: 200,
                payment_hash,
            },
            LightningBalance::CounterpartyRevokedOutputClaimable {
                channel_id,
                counterparty_node_id,
                amount_satoshis: 900,
            },
        ];
        assert_eq!(closing_channel_balance_sats(&balances, &[]), 0);
    }

    /// The two cards never count one amount twice.
    #[test]
    fn the_ready_and_closing_balances_do_not_overlap() {
        let closed = closed_balance(BalanceSource::HolderForceClosed, 249_000);
        let other = open_balance(OTHER_CHANNEL, 100_000);
        let balances = [closed, other];
        // The node can list the closed channel for a short time.
        let channels = [ready_channel(CHANNEL), ready_channel(OTHER_CHANNEL)];
        assert_eq!(ready_channel_balance_sats(&channels, &balances), 100_000);
        assert_eq!(closing_channel_balance_sats(&balances, &[]), 249_000);
    }
}
