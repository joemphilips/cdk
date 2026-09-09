use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use cdk::mint::{Mint, MintKeySetInfo, MintQuote};
use cdk::nuts::nut04::MintMethodSettings;
use cdk::nuts::nut05::MeltMethodSettings;
use cdk::nuts::{CurrencyUnit, MintQuoteState, PaymentMethod};
use cdk::types::QuoteTTL;
use cdk::Amount;
use cdk_common::grpc::create_version_check_interceptor;
use cdk_common::payment::WaitPaymentResponse;
use thiserror::Error;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

use super::peer_policy::PeerPolicy;
use crate::cdk_mint_server::{CdkMint, CdkMintServer};
use crate::keyset::keyset_service_server::{KeysetService, KeysetServiceServer};
use crate::{
    ContactInfo, GetInfoRequest, GetInfoResponse, GetQuoteTtlRequest, GetQuoteTtlResponse,
    RotateNextKeysetRequest, RotateNextKeysetResponse, UpdateContactRequest,
    UpdateDescriptionRequest, UpdateIconUrlRequest, UpdateMotdRequest, UpdateNameRequest,
    UpdateNut04QuoteRequest, UpdateNut04Request, UpdateNut05Request, UpdateQuoteTtlRequest,
    UpdateResponse, UpdateTosUrlRequest, UpdateUrlRequest,
};

/// Error
#[derive(Debug, Error)]
pub enum Error {
    /// Parse error
    #[error(transparent)]
    Parse(#[from] std::net::AddrParseError),
    /// Transport error
    #[error(transparent)]
    Transport(#[from] tonic::transport::Error),
    /// Io error
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A peer identity policy requires a TLS listener.
    #[error("peer identity policy requires TLS configuration")]
    PeerPolicyRequiresTls,
}

fn create_management_interceptor(
    peer_policy: Option<PeerPolicy>,
) -> impl Fn(Request<()>) -> Result<Request<()>, Status> + Clone {
    let version_interceptor = create_version_check_interceptor(
        cdk_common::grpc::VERSION_HEADER,
        cdk_common::MINT_RPC_PROTOCOL_VERSION,
    );

    move |request| {
        if let Some(peer_policy) = peer_policy.as_ref() {
            peer_policy.validate_request(&request)?;
        }

        version_interceptor(request)
    }
}

/// CDK Mint RPC Server
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct MintRPCServer {
    socket_addr: SocketAddr,
    mint: Arc<Mint>,
    peer_policy: Option<PeerPolicy>,
    shutdown: Arc<Notify>,
    handle: Option<Arc<JoinHandle<Result<(), Error>>>>,
}

impl MintRPCServer {
    /// Creates a new MintRPCServer instance
    ///
    /// # Arguments
    /// * `addr` - The address to bind to
    /// * `port` - The port to listen on
    /// * `mint` - The Mint instance to serve
    pub fn new(addr: &str, port: u16, mint: Arc<Mint>) -> Result<Self, Error> {
        Ok(Self {
            socket_addr: format!("{addr}:{port}").parse()?,
            mint,
            peer_policy: None,
            shutdown: Arc::new(Notify::new()),
            handle: None,
        })
    }

    /// Configures the authenticated peer identity required by both RPC services.
    #[must_use]
    pub fn with_peer_policy(mut self, peer_policy: PeerPolicy) -> Self {
        self.peer_policy = Some(peer_policy);
        self
    }

    /// Starts the RPC server
    ///
    /// # Arguments
    /// * `tls_dir` - Optional directory containing TLS certificates
    ///
    /// If TLS directory is provided, it must contain:
    /// - server.pem: Server certificate
    /// - server.key: Server private key
    /// - ca.pem: CA certificate for client authentication
    pub async fn start(&mut self, tls_dir: Option<PathBuf>) -> Result<(), Error> {
        tracing::info!("Starting RPC server {}", self.socket_addr);

        if tls_dir.is_none() && self.peer_policy.is_some() {
            return Err(Error::PeerPolicyRequiresTls);
        }

        let interceptor = create_management_interceptor(self.peer_policy.clone());

        #[cfg(not(target_arch = "wasm32"))]
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }

        let server = match tls_dir {
            Some(tls_dir) => {
                tracing::info!("TLS configuration found, starting secure server");
                let server_pem_path = tls_dir.join("server.pem");
                let server_key_path = tls_dir.join("server.key");
                let ca_pem_path = tls_dir.join("ca.pem");

                if !server_pem_path.exists() {
                    tracing::error!(
                        "Server certificate file does not exist: {}",
                        server_pem_path.display()
                    );
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "Server certificate file not found: {}",
                            server_pem_path.display()
                        ),
                    )));
                }

                if !server_key_path.exists() {
                    tracing::error!(
                        "Server key file does not exist: {}",
                        server_key_path.display()
                    );
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Server key file not found: {}", server_key_path.display()),
                    )));
                }

                if !ca_pem_path.exists() {
                    tracing::error!(
                        "CA certificate file does not exist: {}",
                        ca_pem_path.display()
                    );
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("CA certificate file not found: {}", ca_pem_path.display()),
                    )));
                }

                let cert = std::fs::read_to_string(&server_pem_path)?;
                let key = std::fs::read_to_string(&server_key_path)?;
                let client_ca_cert = std::fs::read_to_string(&ca_pem_path)?;
                let client_ca_cert = Certificate::from_pem(client_ca_cert);
                let server_identity = Identity::from_pem(cert, key);
                let tls_config = ServerTlsConfig::new()
                    .identity(server_identity)
                    .client_ca_root(client_ca_cert);

                Server::builder()
                    .tls_config(tls_config)?
                    .add_service(CdkMintServer::with_interceptor(
                        self.clone(),
                        interceptor.clone(),
                    ))
                    .add_service(KeysetServiceServer::with_interceptor(
                        self.clone(),
                        interceptor.clone(),
                    ))
            }
            None => {
                tracing::warn!("No valid TLS configuration found, starting insecure server");
                Server::builder()
                    .add_service(CdkMintServer::with_interceptor(
                        self.clone(),
                        interceptor.clone(),
                    ))
                    .add_service(KeysetServiceServer::with_interceptor(
                        self.clone(),
                        interceptor,
                    ))
            }
        };

        let shutdown = self.shutdown.clone();
        let addr = self.socket_addr;

        self.handle = Some(Arc::new(tokio::spawn(async move {
            let server = server.serve_with_shutdown(addr, async {
                shutdown.notified().await;
            });

            server.await?;
            Ok(())
        })));

        Ok(())
    }

    /// Stops the RPC server gracefully
    pub async fn stop(&self) -> Result<(), Error> {
        self.shutdown.notify_one();
        if let Some(handle) = &self.handle {
            while !handle.is_finished() {
                tracing::info!("Waitning for mint rpc server to stop");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        tracing::info!("Mint rpc server stopped");
        Ok(())
    }

    /// Rotates to the next keyset for the given unit
    ///
    /// Shared by the legacy [`CdkMint`] service and [`KeysetService`] while
    /// both are served.
    async fn rotate_keyset(
        &self,
        unit: CurrencyUnit,
        amounts: Vec<u64>,
        input_fee_ppk: Option<u64>,
        use_keyset_v2: Option<bool>,
        final_expiry: Option<u64>,
    ) -> Result<MintKeySetInfo, Status> {
        self.mint
            .rotate_keyset(
                unit,
                amounts,
                input_fee_ppk.unwrap_or(0),
                use_keyset_v2.unwrap_or(true),
                final_expiry,
            )
            .await
            .map_err(|_| Status::invalid_argument("Could not rotate keyset".to_string()))
    }
}

impl Drop for MintRPCServer {
    fn drop(&mut self) {
        tracing::debug!("Dropping mint rpc server");
        self.shutdown.notify_one();
    }
}

#[tonic::async_trait]
impl CdkMint for MintRPCServer {
    /// Returns information about the mint
    async fn get_info(
        &self,
        _request: Request<GetInfoRequest>,
    ) -> Result<Response<GetInfoResponse>, Status> {
        let info = self
            .mint
            .mint_info()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        let total_issued = self
            .mint
            .total_issued()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        let total_issued: Amount = Amount::try_sum(total_issued.values().cloned())
            .map_err(|_| Status::internal("Overflow".to_string()))?;

        let total_redeemed = self
            .mint
            .total_redeemed()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        let total_redeemed: Amount = Amount::try_sum(total_redeemed.values().cloned())
            .map_err(|_| Status::internal("Overflow".to_string()))?;

        let contact = info
            .contact
            .unwrap_or_default()
            .into_iter()
            .map(|c| ContactInfo {
                method: c.method,
                info: c.info,
            })
            .collect();

        let response = Response::new(GetInfoResponse {
            name: info.name,
            description: info.description,
            long_description: info.description_long,
            version: info.version.map(|v| v.to_string()),
            contact,
            motd: info.motd,
            icon_url: info.icon_url,
            tos_url: info.tos_url,
            urls: info.urls.unwrap_or_default(),
            total_issued: total_issued.into(),
            total_redeemed: total_redeemed.into(),
        });

        Ok(response)
    }

    /// Updates the mint's message of the day
    async fn update_motd(
        &self,
        request: Request<UpdateMotdRequest>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let motd = request.into_inner().motd;
        let mut info = self
            .mint
            .mint_info()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        info.motd = Some(motd);

        self.mint
            .set_mint_info(info)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        Ok(Response::new(UpdateResponse {}))
    }

    /// Updates the mint's short description
    async fn update_short_description(
        &self,
        request: Request<UpdateDescriptionRequest>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let description = request.into_inner().description;
        let mut info = self
            .mint
            .mint_info()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        info.description = Some(description);

        self.mint
            .set_mint_info(info)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        Ok(Response::new(UpdateResponse {}))
    }

    /// Updates the mint's long description
    async fn update_long_description(
        &self,
        request: Request<UpdateDescriptionRequest>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let description = request.into_inner().description;
        let mut info = self
            .mint
            .mint_info()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        info.description_long = Some(description);

        self.mint
            .set_mint_info(info)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        Ok(Response::new(UpdateResponse {}))
    }

    /// Updates the mint's name
    async fn update_name(
        &self,
        request: Request<UpdateNameRequest>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let name = request.into_inner().name;
        let mut info = self
            .mint
            .mint_info()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        info.name = Some(name);

        self.mint
            .set_mint_info(info)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        Ok(Response::new(UpdateResponse {}))
    }

    /// Updates the mint's icon URL
    async fn update_icon_url(
        &self,
        request: Request<UpdateIconUrlRequest>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let icon_url = request.into_inner().icon_url;

        let mut info = self
            .mint
            .mint_info()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        info.icon_url = Some(icon_url);

        self.mint
            .set_mint_info(info)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        Ok(Response::new(UpdateResponse {}))
    }

    /// Updates the mint's terms of service URL
    async fn update_tos_url(
        &self,
        request: Request<UpdateTosUrlRequest>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let tos_url = request.into_inner().tos_url;

        let mut info = self
            .mint
            .mint_info()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        info.tos_url = Some(tos_url);

        self.mint
            .set_mint_info(info)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        Ok(Response::new(UpdateResponse {}))
    }

    /// Adds a URL to the mint's list of URLs
    async fn add_url(
        &self,
        request: Request<UpdateUrlRequest>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let url = request.into_inner().url;
        let mut info = self
            .mint
            .mint_info()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        let mut urls = info.urls.unwrap_or_default();
        urls.push(url);

        info.urls = Some(urls.clone());

        self.mint
            .set_mint_info(info)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        Ok(Response::new(UpdateResponse {}))
    }

    /// Removes a URL from the mint's list of URLs
    async fn remove_url(
        &self,
        request: Request<UpdateUrlRequest>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let url = request.into_inner().url;
        let mut info = self
            .mint
            .mint_info()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        let urls = info.urls;
        let mut urls = urls.clone().unwrap_or_default();

        urls.retain(|u| u != &url);

        let urls = if urls.is_empty() { None } else { Some(urls) };

        info.urls = urls;

        self.mint
            .set_mint_info(info)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        Ok(Response::new(UpdateResponse {}))
    }

    /// Adds a contact method to the mint's contact information
    async fn add_contact(
        &self,
        request: Request<UpdateContactRequest>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let request_inner = request.into_inner();
        let mut info = self
            .mint
            .mint_info()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        info.contact
            .get_or_insert_with(Vec::new)
            .push(cdk::nuts::ContactInfo::new(
                request_inner.method,
                request_inner.info,
            ));

        self.mint
            .set_mint_info(info)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        Ok(Response::new(UpdateResponse {}))
    }
    /// Removes a contact method from the mint's contact information
    async fn remove_contact(
        &self,
        request: Request<UpdateContactRequest>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let request_inner = request.into_inner();
        let mut info = self
            .mint
            .mint_info()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        if let Some(contact) = info.contact.as_mut() {
            let contact_info =
                cdk::nuts::ContactInfo::new(request_inner.method, request_inner.info);
            contact.retain(|x| x != &contact_info);

            self.mint
                .set_mint_info(info)
                .await
                .map_err(|err| Status::internal(err.to_string()))?;
        }
        Ok(Response::new(UpdateResponse {}))
    }

    /// Updates the mint's NUT-04 (mint) settings
    async fn update_nut04(
        &self,
        request: Request<UpdateNut04Request>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let mut info = self
            .mint
            .mint_info()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        let mut nut04_settings = info.nuts.nut04.clone();

        let request_inner = request.into_inner();

        let unit = CurrencyUnit::from_str(&request_inner.unit)
            .map_err(|_| Status::invalid_argument("Invalid unit".to_string()))?;

        let payment_method = PaymentMethod::from_str(&request_inner.method)
            .map_err(|_| Status::invalid_argument("Invalid method".to_string()))?;

        self.mint
            .get_payment_processor(unit.clone(), payment_method.clone())
            .map_err(|_| Status::invalid_argument("Unit payment method pair is not supported"))?;

        let current_nut04_settings = nut04_settings.remove_settings(&unit, &payment_method);

        let mut methods = nut04_settings.methods.clone();

        // Create options from the request
        let options = if let Some(options) = request_inner.options {
            Some(cdk::nuts::nut04::MintMethodOptions::Bolt11 {
                description: options.description,
            })
        } else if let Some(current_settings) = current_nut04_settings.as_ref() {
            current_settings.options.clone()
        } else {
            None
        };

        let updated_method_settings = MintMethodSettings {
            method: payment_method,
            unit,
            method_name: request_inner.method_name.or_else(|| {
                current_nut04_settings
                    .as_ref()
                    .and_then(|s| s.method_name.clone())
            }),
            min_amount: request_inner
                .min_amount
                .map(Amount::from)
                .or_else(|| current_nut04_settings.as_ref().and_then(|s| s.min_amount)),
            max_amount: request_inner
                .max_amount
                .map(Amount::from)
                .or_else(|| current_nut04_settings.as_ref().and_then(|s| s.max_amount)),
            options,
        };

        methods.push(updated_method_settings);

        nut04_settings.methods = methods;

        if let Some(disabled) = request_inner.disabled {
            nut04_settings.disabled = disabled;
        }

        info.nuts.nut04 = nut04_settings;

        self.mint
            .set_mint_info(info)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        Ok(Response::new(UpdateResponse {}))
    }

    /// Updates the mint's NUT-05 (melt) settings
    async fn update_nut05(
        &self,
        request: Request<UpdateNut05Request>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let mut info = self
            .mint
            .mint_info()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        let mut nut05_settings = info.nuts.nut05.clone();

        let request_inner = request.into_inner();

        let unit = CurrencyUnit::from_str(&request_inner.unit)
            .map_err(|_| Status::invalid_argument("Invalid unit".to_string()))?;

        let payment_method = PaymentMethod::from_str(&request_inner.method)
            .map_err(|_| Status::invalid_argument("Invalid method".to_string()))?;

        self.mint
            .get_payment_processor(unit.clone(), payment_method.clone())
            .map_err(|_| Status::invalid_argument("Unit payment method pair is not supported"))?;

        let current_nut05_settings = nut05_settings.remove_settings(&unit, &payment_method);

        let mut methods = nut05_settings.methods;

        // Create options from the request
        let options = if let Some(options) = request_inner.options {
            Some(cdk::nuts::nut05::MeltMethodOptions::Bolt11 {
                amountless: options.amountless,
            })
        } else if let Some(current_settings) = current_nut05_settings.as_ref() {
            current_settings.options.clone()
        } else {
            None
        };

        let updated_method_settings = MeltMethodSettings {
            method: payment_method,
            unit,
            method_name: request_inner.method_name.or_else(|| {
                current_nut05_settings
                    .as_ref()
                    .and_then(|s| s.method_name.clone())
            }),
            min_amount: request_inner
                .min_amount
                .map(Amount::from)
                .or_else(|| current_nut05_settings.as_ref().and_then(|s| s.min_amount)),
            max_amount: request_inner
                .max_amount
                .map(Amount::from)
                .or_else(|| current_nut05_settings.as_ref().and_then(|s| s.max_amount)),
            options,
        };

        methods.push(updated_method_settings);
        nut05_settings.methods = methods;

        if let Some(disabled) = request_inner.disabled {
            nut05_settings.disabled = disabled;
        }

        info.nuts.nut05 = nut05_settings;

        self.mint
            .set_mint_info(info)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        Ok(Response::new(UpdateResponse {}))
    }

    /// Updates the mint's quote time-to-live settings
    async fn update_quote_ttl(
        &self,
        request: Request<UpdateQuoteTtlRequest>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let current_ttl = self
            .mint
            .quote_ttl()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        let request = request.into_inner();

        let quote_ttl = QuoteTTL {
            mint_ttl: request.mint_ttl.unwrap_or(current_ttl.mint_ttl),
            melt_ttl: request.melt_ttl.unwrap_or(current_ttl.melt_ttl),
        };

        self.mint
            .set_quote_ttl(quote_ttl)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        Ok(Response::new(UpdateResponse {}))
    }

    /// Gets the mint's quote time-to-live settings
    async fn get_quote_ttl(
        &self,
        _request: Request<GetQuoteTtlRequest>,
    ) -> Result<Response<GetQuoteTtlResponse>, Status> {
        let ttl = self
            .mint
            .quote_ttl()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        Ok(Response::new(GetQuoteTtlResponse {
            mint_ttl: ttl.mint_ttl,
            melt_ttl: ttl.melt_ttl,
        }))
    }

    /// Updates a specific NUT-04 quote's state
    async fn update_nut04_quote(
        &self,
        request: Request<UpdateNut04QuoteRequest>,
    ) -> Result<Response<UpdateNut04QuoteRequest>, Status> {
        let request = request.into_inner();
        let quote_id = request
            .quote_id
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid quote id".to_string()))?;

        let state = MintQuoteState::from_str(&request.state)
            .map_err(|_| Status::invalid_argument("Invalid quote state".to_string()))?;

        let mint_quote = self
            .mint
            .localstore()
            .get_mint_quote(&quote_id)
            .await
            .map_err(|_| Status::invalid_argument("Could not find quote".to_string()))?
            .ok_or(Status::invalid_argument("Could not find quote".to_string()))?;

        match state {
            MintQuoteState::Paid => {
                // Create a dummy payment response
                let response = WaitPaymentResponse {
                    payment_id: mint_quote.request_lookup_id.to_string(),
                    payment_amount: mint_quote.clone().amount.unwrap_or(cdk::Amount::new(
                        mint_quote.amount_paid().value(),
                        mint_quote.unit.clone(),
                    )),
                    payment_identifier: mint_quote.request_lookup_id.clone(),
                };

                let localstore = self.mint.localstore();
                let mut tx = localstore
                    .begin_transaction()
                    .await
                    .map_err(|_| Status::internal("Could not start db transaction".to_string()))?;

                // Re-fetch the mint quote within the transaction to lock it
                let mut mint_quote = tx
                    .get_mint_quote(&quote_id)
                    .await
                    .map_err(|_| {
                        Status::internal("Could not get quote in transaction".to_string())
                    })?
                    .ok_or(Status::invalid_argument(
                        "Quote not found in transaction".to_string(),
                    ))?;

                let should_notify = self
                    .mint
                    .pay_mint_quote(&mut tx, &mut mint_quote, response)
                    .await
                    .map_err(|_| Status::internal("Could not process payment".to_string()))?;

                tx.commit()
                    .await
                    .map_err(|_| Status::internal("Could not commit db transaction".to_string()))?;

                // Publish notification AFTER transaction commits
                if should_notify {
                    self.mint
                        .pubsub_manager()
                        .mint_quote_payment(&mint_quote, mint_quote.amount_paid());
                }
            }
            _ => {
                // Create a new quote with the same values
                let quote = MintQuote::new(
                    Some(mint_quote.id.clone()),          // id
                    mint_quote.request.clone(),           // request
                    mint_quote.unit.clone(),              // unit
                    mint_quote.amount.clone(),            // amount
                    mint_quote.expiry,                    // expiry
                    mint_quote.request_lookup_id.clone(), // request_lookup_id
                    mint_quote.pubkey,                    // pubkey
                    mint_quote.amount_issued(),           // amount_issued
                    mint_quote.amount_paid(),             // amount_paid
                    mint_quote.payment_method.clone(),    // method
                    0,                                    // created_at
                    0,                                    // updated_at
                    vec![],                               // blinded_messages
                    vec![],                               // payment_ids
                    None,                                 // extra_json
                );

                let mint_store = self.mint.localstore();
                let mut tx = mint_store
                    .begin_transaction()
                    .await
                    .map_err(|_| Status::internal("Could not update quote".to_string()))?;
                tx.add_mint_quote(quote.clone())
                    .await
                    .map_err(|_| Status::internal("Could not update quote".to_string()))?;
                tx.commit()
                    .await
                    .map_err(|_| Status::internal("Could not update quote".to_string()))?;
            }
        }

        let mint_quote = self
            .mint
            .localstore()
            .get_mint_quote(&quote_id)
            .await
            .map_err(|_| Status::invalid_argument("Could not find quote".to_string()))?
            .ok_or(Status::invalid_argument("Could not find quote".to_string()))?;

        Ok(Response::new(UpdateNut04QuoteRequest {
            state: mint_quote.state().to_string(),
            quote_id: mint_quote.id.to_string(),
        }))
    }

    /// Rotates to the next keyset for the specified currency unit
    async fn rotate_next_keyset(
        &self,
        request: Request<RotateNextKeysetRequest>,
    ) -> Result<Response<RotateNextKeysetResponse>, Status> {
        let request = request.into_inner();

        let unit = CurrencyUnit::from_str(&request.unit)
            .map_err(|_| Status::invalid_argument("Invalid unit".to_string()))?;

        let keyset_info = self
            .rotate_keyset(
                unit,
                request.amounts,
                request.input_fee_ppk,
                request.use_keyset_v2,
                request.final_expiry,
            )
            .await?;

        Ok(Response::new(RotateNextKeysetResponse {
            id: keyset_info.id.to_string(),
            unit: keyset_info.unit.to_string(),
            amounts: keyset_info.amounts,
            input_fee_ppk: keyset_info.input_fee_ppk,
        }))
    }
}

#[tonic::async_trait]
impl KeysetService for MintRPCServer {
    /// Rotates to the next keyset for the specified currency unit
    async fn rotate_next_keyset(
        &self,
        request: Request<crate::keyset::RotateNextKeysetRequest>,
    ) -> Result<Response<crate::keyset::RotateNextKeysetResponse>, Status> {
        let request = request.into_inner();

        let unit = CurrencyUnit::from_str(&request.unit)
            .map_err(|_| Status::invalid_argument("Invalid unit".to_string()))?;

        let keyset_info = self
            .rotate_keyset(
                unit,
                request.amounts,
                request.input_fee_ppk,
                request.use_keyset_v2,
                request.final_expiry,
            )
            .await?;

        Ok(Response::new(crate::keyset::RotateNextKeysetResponse {
            id: keyset_info.id.to_string(),
            unit: keyset_info.unit.to_string(),
            amounts: keyset_info.amounts,
            input_fee_ppk: keyset_info.input_fee_ppk,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::net::{SocketAddr, TcpListener};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration as StdDuration;

    use bip39::Mnemonic;
    use bitcoin::hashes::{sha256, Hash};
    use cdk::mint::{Mint, MintBuilder, MintMeltLimits};
    use cdk::nuts::{CurrencyUnit, PaymentMethod};
    use cdk::types::QuoteTTL;
    use cdk_common::grpc::{VersionInterceptor, VERSION_HEADER};
    use cdk_common::nut00::KnownMethod;
    use cdk_common::nuts::Id;
    use cdk_fake_wallet::FakeWallet;
    use tempfile::TempDir;
    use tonic::codegen::InterceptedService;
    use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
    use tonic::{Code, Request};

    use super::*;
    use crate::cdk_mint_server::CdkMint;
    use crate::keyset::keyset_service_client::KeysetServiceClient;
    use crate::{CdkMintClient, GetInfoRequest, UpdateTosUrlRequest};

    type TestCdkClient = CdkMintClient<InterceptedService<Channel, VersionInterceptor>>;
    type TestKeysetClient = KeysetServiceClient<InterceptedService<Channel, VersionInterceptor>>;

    async fn create_test_rpc_server() -> MintRPCServer {
        let db = Arc::new(cdk_sqlite::mint::memory::empty().await.unwrap());

        let mut mint_builder = MintBuilder::new(db.clone());

        let fee_reserve = cdk::types::FeeReserve {
            min_fee_reserve: 1.into(),
            percent_fee_reserve: 1.0,
        };

        let ln_fake = FakeWallet::new(
            fee_reserve,
            HashMap::default(),
            HashSet::default(),
            2,
            CurrencyUnit::Sat,
        );

        mint_builder
            .add_payment_processor(
                CurrencyUnit::Sat,
                PaymentMethod::Known(KnownMethod::Bolt11),
                MintMeltLimits::new(1, 10_000),
                Arc::new(ln_fake),
            )
            .await
            .unwrap();

        let mnemonic = Mnemonic::generate(12).unwrap();

        mint_builder = mint_builder
            .with_name("test mint".to_string())
            .with_description("test mint".to_string());

        let mint = mint_builder
            .build_with_seed(db.clone(), &mnemonic.to_seed_normalized(""))
            .await
            .unwrap();

        mint.set_quote_ttl(QuoteTTL::new(10000, 10000))
            .await
            .unwrap();

        mint.start().await.unwrap();

        MintRPCServer {
            socket_addr: "127.0.0.1:0".parse().unwrap(),
            mint: Arc::new(mint),
            peer_policy: None,
            shutdown: Arc::new(Notify::new()),
            handle: None,
        }
    }

    struct TlsFixtures {
        dir: TempDir,
        ca_pem: PathBuf,
        client_pem: PathBuf,
        client_key: PathBuf,
        wrong_key_pem: PathBuf,
        wrong_key_key: PathBuf,
        wrong_san_pem: PathBuf,
        cn_only_pem: PathBuf,
        untrusted_client_pem: PathBuf,
        client_spki_pin: String,
    }

    impl TlsFixtures {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("create TLS fixture directory");

            fs::write(
                dir.path().join("server.ext"),
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n",
            )
            .expect("write server certificate extensions");
            fs::write(
                dir.path().join("client.ext"),
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:orchard\n",
            )
            .expect("write client certificate extensions");
            fs::write(
                dir.path().join("wrong-san.ext"),
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:other-client\n",
            )
            .expect("write wrong SAN certificate extensions");
            fs::write(
                dir.path().join("cn-only.ext"),
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n",
            )
            .expect("write CN-only certificate extensions");

            generate_ca(dir.path(), "ca.key", "ca.pem", "/CN=cdk-mint-rpc-test-ca");
            generate_ca(
                dir.path(),
                "untrusted-ca.key",
                "untrusted-ca.pem",
                "/CN=cdk-mint-rpc-untrusted-ca",
            );

            for leaf in [
                LeafSpec {
                    key: "server.key",
                    csr: "server.csr",
                    cert: "server.pem",
                    subject: "/CN=localhost",
                    extensions: "server.ext",
                    serial: "100",
                },
                LeafSpec {
                    key: "client.key",
                    csr: "client.csr",
                    cert: "client.pem",
                    subject: "/CN=orchard",
                    extensions: "client.ext",
                    serial: "101",
                },
                LeafSpec {
                    key: "wrong-key.key",
                    csr: "wrong-key.csr",
                    cert: "wrong-key.pem",
                    subject: "/CN=orchard",
                    extensions: "client.ext",
                    serial: "104",
                },
            ] {
                issue_leaf(dir.path(), leaf);
            }
            generate_csr(
                dir.path(),
                "client.key",
                "wrong-san.csr",
                "/CN=other-client",
            );
            sign_leaf(
                dir.path(),
                "wrong-san.csr",
                "wrong-san.pem",
                "wrong-san.ext",
                "ca.pem",
                "ca.key",
                "102",
            );
            generate_csr(dir.path(), "client.key", "cn-only.csr", "/CN=orchard");
            sign_leaf(
                dir.path(),
                "cn-only.csr",
                "cn-only.pem",
                "cn-only.ext",
                "ca.pem",
                "ca.key",
                "103",
            );

            generate_csr(
                dir.path(),
                "client.key",
                "untrusted-client.csr",
                "/CN=orchard",
            );
            sign_leaf(
                dir.path(),
                "untrusted-client.csr",
                "untrusted-client.pem",
                "client.ext",
                "untrusted-ca.pem",
                "untrusted-ca.key",
                "105",
            );

            let client_spki_pin = spki_sha256_pin(dir.path(), "client.pem");

            Self {
                ca_pem: dir.path().join("ca.pem"),
                client_key: dir.path().join("client.key"),
                client_pem: dir.path().join("client.pem"),
                cn_only_pem: dir.path().join("cn-only.pem"),
                untrusted_client_pem: dir.path().join("untrusted-client.pem"),
                wrong_key_key: dir.path().join("wrong-key.key"),
                wrong_key_pem: dir.path().join("wrong-key.pem"),
                wrong_san_pem: dir.path().join("wrong-san.pem"),
                client_spki_pin,
                dir,
            }
        }
    }

    fn openssl(dir: &Path, args: &[&str]) {
        let output = Command::new("openssl")
            .current_dir(dir)
            .args(args)
            .output()
            .expect("openssl must be available for real TLS tests");
        assert!(
            output.status.success(),
            "openssl command failed: {:?}: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn generate_ca(dir: &Path, key: &str, cert: &str, subject: &str) {
        let args = [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key,
            "-out",
            cert,
            "-days",
            "1",
            "-subj",
            subject,
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:1",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ];
        openssl(dir, &args);
    }

    struct LeafSpec<'a> {
        key: &'a str,
        csr: &'a str,
        cert: &'a str,
        subject: &'a str,
        extensions: &'a str,
        serial: &'a str,
    }

    fn issue_leaf(dir: &Path, leaf: LeafSpec<'_>) {
        generate_key_and_csr(dir, leaf.key, leaf.csr, leaf.subject);
        sign_leaf(
            dir,
            leaf.csr,
            leaf.cert,
            leaf.extensions,
            "ca.pem",
            "ca.key",
            leaf.serial,
        );
    }

    fn generate_key_and_csr(dir: &Path, key: &str, csr: &str, subject: &str) {
        openssl(dir, &["genrsa", "-out", key, "2048"]);
        generate_csr(dir, key, csr, subject);
    }

    fn generate_csr(dir: &Path, key: &str, csr: &str, subject: &str) {
        openssl(
            dir,
            &["req", "-new", "-key", key, "-out", csr, "-subj", subject],
        );
    }

    fn sign_leaf(
        dir: &Path,
        csr: &str,
        cert: &str,
        extensions: &str,
        ca_pem: &str,
        ca_key: &str,
        serial: &str,
    ) {
        openssl(
            dir,
            &[
                "x509",
                "-req",
                "-in",
                csr,
                "-CA",
                ca_pem,
                "-CAkey",
                ca_key,
                "-set_serial",
                serial,
                "-out",
                cert,
                "-days",
                "1",
                "-sha256",
                "-extfile",
                extensions,
            ],
        );
    }

    fn spki_sha256_pin(dir: &Path, cert: &str) -> String {
        openssl(
            dir,
            &[
                "x509",
                "-in",
                cert,
                "-pubkey",
                "-noout",
                "-out",
                "client.pub",
            ],
        );
        openssl(
            dir,
            &[
                "pkey",
                "-pubin",
                "-in",
                "client.pub",
                "-outform",
                "DER",
                "-out",
                "client.spki",
            ],
        );

        sha256::Hash::hash(&fs::read(dir.join("client.spki")).expect("read client SPKI DER"))
            .to_string()
    }

    async fn wait_for_server(addr: SocketAddr) {
        tokio::time::timeout(StdDuration::from_secs(5), async {
            for _ in 0..100 {
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    return;
                }
                tokio::time::sleep(StdDuration::from_millis(10)).await;
            }
            panic!("RPC server did not start at {addr}");
        })
        .await
        .expect("RPC server startup timed out");
    }

    async fn connect_test_clients(
        addr: SocketAddr,
        fixtures: &TlsFixtures,
        client_identity: Option<(&Path, &Path)>,
        server_name: &str,
        protocol_version: &str,
    ) -> Result<(TestCdkClient, TestKeysetClient), tonic::transport::Error> {
        let ca = Certificate::from_pem(
            fs::read_to_string(&fixtures.ca_pem).expect("read test CA certificate"),
        );
        let mut tls = ClientTlsConfig::new()
            .ca_certificate(ca)
            .domain_name(server_name);

        if let Some((client_pem, client_key)) = client_identity {
            tls = tls.identity(Identity::from_pem(
                fs::read_to_string(client_pem).expect("read test client certificate"),
                fs::read_to_string(client_key).expect("read test client key"),
            ));
        }

        let endpoint = Endpoint::from_shared(format!("https://127.0.0.1:{}", addr.port()))
            .expect("test endpoint URI");
        let channel = tokio::time::timeout(
            StdDuration::from_secs(5),
            endpoint.tls_config(tls)?.connect(),
        )
        .await
        .expect("TLS connection timed out")?;
        let interceptor = VersionInterceptor::new(VERSION_HEADER, protocol_version);

        Ok((
            CdkMintClient::with_interceptor(channel.clone(), interceptor.clone()),
            KeysetServiceClient::with_interceptor(channel, interceptor),
        ))
    }

    async fn mint_state(mint: &Arc<Mint>) -> (Option<String>, HashMap<CurrencyUnit, Id>) {
        (
            mint.mint_info().await.expect("read mint info").tos_url,
            mint.get_active_keysets(),
        )
    }

    type ClientIdentity<'a> = Option<(&'a Path, &'a Path)>;

    struct PolicyRejectionCase<'a> {
        case_name: &'a str,
        client_identity: ClientIdentity<'a>,
        server_name: &'a str,
        protocol_version: &'a str,
        expected_code: Code,
    }

    async fn assert_rejected_mutations(
        addr: SocketAddr,
        fixtures: &TlsFixtures,
        mint: &Arc<Mint>,
        case: PolicyRejectionCase<'_>,
    ) {
        let before = mint_state(mint).await;
        let (mut cdk_client, mut keyset_client) = connect_test_clients(
            addr,
            fixtures,
            case.client_identity,
            case.server_name,
            case.protocol_version,
        )
        .await
        .expect("TLS connection should reach the RPC interceptor");

        let cdk_error = tokio::time::timeout(
            StdDuration::from_secs(5),
            cdk_client.update_tos_url(Request::new(UpdateTosUrlRequest {
                tos_url: format!("https://unauthorized-{}.example", case.case_name),
            })),
        )
        .await
        .expect("CdkMint RPC timed out")
        .expect_err("rejected client must not update mint info");
        assert_eq!(
            cdk_error.code(),
            case.expected_code,
            "CdkMint: {}",
            case.case_name
        );

        let keyset_error = tokio::time::timeout(
            StdDuration::from_secs(5),
            keyset_client.rotate_next_keyset(Request::new(
                crate::keyset::RotateNextKeysetRequest {
                    unit: "sat".to_string(),
                    amounts: vec![1, 2, 4, 8],
                    input_fee_ppk: Some(1),
                    use_keyset_v2: Some(true),
                    final_expiry: None,
                },
            )),
        )
        .await
        .expect("KeysetService RPC timed out")
        .expect_err("rejected client must not rotate keysets");
        assert_eq!(
            keyset_error.code(),
            case.expected_code,
            "KeysetService: {}",
            case.case_name
        );

        assert_eq!(
            mint_state(mint).await,
            before,
            "state changed for {}",
            case.case_name
        );
    }

    struct TransportRejectionCase<'a> {
        case_name: &'a str,
        client_identity: ClientIdentity<'a>,
        server_name: &'a str,
    }

    async fn assert_transport_rejected(
        addr: SocketAddr,
        fixtures: &TlsFixtures,
        mint: &Arc<Mint>,
        case: TransportRejectionCase<'_>,
    ) {
        let before = mint_state(mint).await;
        let connection = connect_test_clients(
            addr,
            fixtures,
            case.client_identity,
            case.server_name,
            cdk_common::MINT_RPC_PROTOCOL_VERSION,
        )
        .await;
        if let Ok((mut cdk_client, mut keyset_client)) = connection {
            let cdk_result = tokio::time::timeout(
                StdDuration::from_secs(5),
                cdk_client.update_tos_url(Request::new(UpdateTosUrlRequest {
                    tos_url: format!("https://transport-rejected-{}.example", case.case_name),
                })),
            )
            .await
            .expect("transport-rejected CdkMint RPC timed out");
            assert!(
                cdk_result.is_err(),
                "CdkMint unexpectedly succeeded: {}",
                case.case_name
            );

            let keyset_result = tokio::time::timeout(
                StdDuration::from_secs(5),
                keyset_client.rotate_next_keyset(Request::new(
                    crate::keyset::RotateNextKeysetRequest {
                        unit: "sat".to_string(),
                        amounts: vec![1, 2, 4, 8],
                        input_fee_ppk: Some(1),
                        use_keyset_v2: Some(true),
                        final_expiry: None,
                    },
                )),
            )
            .await
            .expect("transport-rejected KeysetService RPC timed out");
            assert!(
                keyset_result.is_err(),
                "KeysetService unexpectedly succeeded: {}",
                case.case_name
            );
        }
        assert_eq!(
            mint_state(mint).await,
            before,
            "state changed for {}",
            case.case_name
        );
    }

    #[tokio::test]
    async fn test_peer_policy_refuses_plaintext_before_listener_start() {
        let policy = PeerPolicy::new("orchard", &"01".repeat(32)).unwrap();
        let mut server = create_test_rpc_server().await.with_peer_policy(policy);

        let error = server.start(None).await.unwrap_err();

        assert!(matches!(error, Error::PeerPolicyRequiresTls));
        assert!(server.handle.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_real_tls_peer_policy_covers_both_services_and_mutation_rejection() {
        let fixtures = TlsFixtures::new();
        let policy = PeerPolicy::new("orchard", &fixtures.client_spki_pin).unwrap();
        let mut server = create_test_rpc_server().await.with_peer_policy(policy);
        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve RPC test port");
        let addr = listener.local_addr().expect("read RPC test port");
        drop(listener);
        server.socket_addr = addr;
        let mint = server.mint.clone();

        server
            .start(Some(fixtures.dir.path().to_path_buf()))
            .await
            .expect("start production RPC server with TLS");
        wait_for_server(addr).await;

        let (mut cdk_client, mut keyset_client) = connect_test_clients(
            addr,
            &fixtures,
            Some((&fixtures.client_pem, &fixtures.client_key)),
            "localhost",
            cdk_common::MINT_RPC_PROTOCOL_VERSION,
        )
        .await
        .expect("correct mTLS client should connect");

        let info = tokio::time::timeout(
            StdDuration::from_secs(5),
            cdk_client.get_info(Request::new(GetInfoRequest {})),
        )
        .await
        .expect("CdkMint GetInfo timed out")
        .expect("CdkMint GetInfo should succeed")
        .into_inner();
        assert_eq!(info.name.as_deref(), Some("test mint"));

        tokio::time::timeout(
            StdDuration::from_secs(5),
            cdk_client.update_tos_url(Request::new(UpdateTosUrlRequest {
                tos_url: "https://authorized.example".to_string(),
            })),
        )
        .await
        .expect("CdkMint mutation timed out")
        .expect("CdkMint mutation should succeed for the pinned peer");
        assert_eq!(
            mint.mint_info().await.expect("read mint info").tos_url,
            Some("https://authorized.example".to_string())
        );

        let before_rotation = mint.get_active_keysets();
        tokio::time::timeout(
            StdDuration::from_secs(5),
            keyset_client.rotate_next_keyset(Request::new(
                crate::keyset::RotateNextKeysetRequest {
                    unit: "sat".to_string(),
                    amounts: vec![1, 2, 4, 8],
                    input_fee_ppk: Some(1),
                    use_keyset_v2: Some(true),
                    final_expiry: None,
                },
            )),
        )
        .await
        .expect("KeysetService mutation timed out")
        .expect("KeysetService mutation should succeed for the pinned peer");
        assert_ne!(mint.get_active_keysets(), before_rotation);

        let policy_rejections = [
            PolicyRejectionCase {
                case_name: "wrong-key",
                client_identity: Some((&fixtures.wrong_key_pem, &fixtures.wrong_key_key)),
                server_name: "localhost",
                protocol_version: cdk_common::MINT_RPC_PROTOCOL_VERSION,
                expected_code: Code::PermissionDenied,
            },
            PolicyRejectionCase {
                case_name: "wrong-san",
                client_identity: Some((&fixtures.wrong_san_pem, &fixtures.client_key)),
                server_name: "localhost",
                protocol_version: cdk_common::MINT_RPC_PROTOCOL_VERSION,
                expected_code: Code::PermissionDenied,
            },
            PolicyRejectionCase {
                case_name: "cn-only",
                client_identity: Some((&fixtures.cn_only_pem, &fixtures.client_key)),
                server_name: "localhost",
                protocol_version: cdk_common::MINT_RPC_PROTOCOL_VERSION,
                expected_code: Code::PermissionDenied,
            },
            PolicyRejectionCase {
                case_name: "wrong-version",
                client_identity: Some((&fixtures.client_pem, &fixtures.client_key)),
                server_name: "localhost",
                protocol_version: "0.0.0",
                expected_code: Code::FailedPrecondition,
            },
        ];
        for case in policy_rejections {
            assert_rejected_mutations(addr, &fixtures, &mint, case).await;
        }

        let transport_rejections = [
            TransportRejectionCase {
                case_name: "untrusted-ca",
                client_identity: Some((&fixtures.untrusted_client_pem, &fixtures.client_key)),
                server_name: "localhost",
            },
            TransportRejectionCase {
                case_name: "no-client-cert",
                client_identity: None,
                server_name: "localhost",
            },
            TransportRejectionCase {
                case_name: "wrong-server-target",
                client_identity: Some((&fixtures.client_pem, &fixtures.client_key)),
                server_name: "wrong-target",
            },
        ];
        for case in transport_rejections {
            assert_transport_rejected(addr, &fixtures, &mint, case).await;
        }

        tokio::time::timeout(StdDuration::from_secs(5), server.stop())
            .await
            .expect("RPC server stop timed out")
            .expect("stop production RPC server");
    }

    #[tokio::test]
    async fn test_get_info_tos_url_none_when_not_set() {
        let server = create_test_rpc_server().await;

        let response = server
            .get_info(Request::new(GetInfoRequest {}))
            .await
            .unwrap();

        assert!(response.into_inner().tos_url.is_none());
    }

    #[tokio::test]
    async fn test_get_info_includes_tos_url() {
        let server = create_test_rpc_server().await;
        let tos = "https://example.com/tos";

        let mut info = server.mint.mint_info().await.unwrap();
        info.tos_url = Some(tos.to_string());
        server.mint.set_mint_info(info).await.unwrap();

        let response = server
            .get_info(Request::new(GetInfoRequest {}))
            .await
            .unwrap();

        assert_eq!(response.into_inner().tos_url.unwrap(), tos);
    }

    #[tokio::test]
    async fn test_keyset_service_rotate_next_keyset() {
        let server = create_test_rpc_server().await;

        let response = KeysetService::rotate_next_keyset(
            &server,
            Request::new(crate::keyset::RotateNextKeysetRequest {
                unit: "sat".to_string(),
                amounts: vec![1, 2, 4, 8],
                input_fee_ppk: Some(1),
                use_keyset_v2: Some(true),
                final_expiry: None,
            }),
        )
        .await
        .unwrap();

        let response = response.into_inner();
        assert!(!response.id.is_empty());
        assert_eq!(response.unit, "sat");
        assert_eq!(response.amounts, vec![1, 2, 4, 8]);
        assert_eq!(response.input_fee_ppk, 1);
    }

    #[tokio::test]
    async fn test_update_tos_url() {
        let server = create_test_rpc_server().await;
        let tos = "https://example.com/terms";

        server
            .update_tos_url(Request::new(UpdateTosUrlRequest {
                tos_url: tos.to_string(),
            }))
            .await
            .unwrap();

        let response = server
            .get_info(Request::new(GetInfoRequest {}))
            .await
            .unwrap();

        assert_eq!(response.into_inner().tos_url.unwrap(), tos);
    }
}
