//! Exchange-rate oracle primitives for rate-quoted payment processors.

pub mod msat_converter;
pub mod oracle;
pub mod payment;
pub mod sources;
pub mod store;
pub mod types;

pub use msat_converter::{
    convert_incoming_response_to_sat, convert_outgoing_response_to_unit, sat_msat_backends,
    validate_incoming_responses, validate_outgoing_response, MsatSatConverter, SatMsatBackends,
    SatMsatConverter,
};
pub use oracle::{AggregatingRateOracle, AggregatorConfig, BackoffState, RateOracle, RateSource};
pub use payment::{
    convert_rate_melt_response, convert_rate_mint_payment, parked_payment_event_count,
    PaymentErrorAdapter, RateConvertingPayment, RateConvertingPaymentConfig,
    RateConvertingPaymentError, RateQuoteControlHandle, SharedMintPayment, UnitQuoteState,
    DEFAULT_RATE_QUOTE_TTL_SECS,
};
pub use store::{
    DynRateQuoteStore, InMemoryRateQuoteStore, ParkedPaymentRecord, RateQuoteRecord,
    RateQuoteSettlement, RateQuoteSide, RateQuoteStore, RateQuoteStoreError, UnitControlRecord,
};
pub use types::{AggregationMeta, RateOracleError, RateSnapshot, SourceReading};
