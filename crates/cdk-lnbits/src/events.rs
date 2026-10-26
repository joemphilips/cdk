//! Websocket wake hints.
//!
//! A websocket message is never payment evidence. The channel has no message
//! authentication, so a message only names a payment hash to re-read through
//! the authenticated status endpoint. The mint deduplicates repeated credit
//! by payment id and recovers missed payments through its pending quote
//! status checks.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use cdk_common::payment::{Event, PaymentIdentifier};
use futures::{Stream, StreamExt};
use tokio_util::sync::CancellationToken;

use crate::api::{parse_hex32, WireHint};
use crate::error::Error;
use crate::transport::HintStream;
use crate::LNbits;

/// Clears the active flag when the owned stream ends or is dropped.
struct ActiveGuard(Arc<AtomicBool>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

struct EventState {
    hints: HintStream,
    lnbits: LNbits,
    cancel: CancellationToken,
    _active: ActiveGuard,
}

impl LNbits {
    pub(crate) async fn open_events(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = Event> + Send>>, Error> {
        if self.cancel.is_cancelled() {
            return Err(Error::StreamCancelled);
        }
        if self.stream_active.swap(true, Ordering::SeqCst) {
            return Err(Error::StreamAlreadyActive);
        }
        let active = ActiveGuard(Arc::clone(&self.stream_active));
        let hints = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => return Err(Error::StreamCancelled),
            hints = self.transport.connect_hints() => hints?,
        };
        tracing::info!("LNbits websocket connected");

        let state = EventState {
            hints,
            lnbits: self.clone(),
            cancel: self.cancel.clone(),
            _active: active,
        };
        Ok(Box::pin(futures::stream::unfold(state, next_event)))
    }
}

async fn next_event(mut state: EventState) -> Option<(Event, EventState)> {
    loop {
        let message = tokio::select! {
            biased;
            _ = state.cancel.cancelled() => {
                tracing::info!("LNbits websocket cancelled");
                return None;
            }
            message = state.hints.next() => message,
        };
        let text = match message {
            Some(Ok(text)) => text,
            Some(Err(error)) => {
                tracing::warn!(transport_error = %error, "LNbits websocket failed");
                return None;
            }
            None => {
                tracing::info!("LNbits websocket closed");
                return None;
            }
        };
        let Some(payment_hash) = parse_wake_hint(&text) else {
            tracing::debug!("dropping an LNbits websocket message that is not an incoming hint");
            continue;
        };

        let identifier = PaymentIdentifier::PaymentHash(payment_hash);
        let checked = tokio::select! {
            biased;
            _ = state.cancel.cancelled() => {
                tracing::info!("LNbits websocket cancelled");
                return None;
            }
            checked = state.lnbits.incoming_status(&identifier) => checked,
        };
        match checked {
            Ok(mut payments) => match payments.pop() {
                Some(payment) => return Some((Event::PaymentReceived(payment), state)),
                None => tracing::debug!(
                    payment_hash = %identifier,
                    "LNbits hint has no verified credit"
                ),
            },
            Err(error) => tracing::debug!(
                payment_hash = %identifier,
                %error,
                "LNbits hint could not be verified"
            ),
        }
    }
}

/// Extract the payment hash of an incoming wallet notification.
fn parse_wake_hint(text: &str) -> Option<[u8; 32]> {
    let hint: WireHint = serde_json::from_str(text).ok()?;
    if hint.payment.amount <= 0 {
        return None;
    }
    parse_hex32(&hint.payment.payment_hash)
}
