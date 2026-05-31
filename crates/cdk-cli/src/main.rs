//! CDK CLI

use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{bail, Result};
use bip39::rand::{thread_rng, Rng};
use bip39::Mnemonic;
use cdk::cdk_database;
use cdk::cdk_database::WalletDatabase;
use cdk::nuts::CurrencyUnit;
#[cfg(feature = "redb")]
use cdk_redb::WalletRedbDatabase;
use cdk_sqlite::WalletSqliteDatabase;
#[cfg(all(feature = "tor", not(target_arch = "wasm32")))]
use clap::ValueEnum;
use clap::{Parser, Subcommand};
use tracing::Level;
use tracing_subscriber::EnvFilter;
use url::Url;

mod nostr_storage;
mod sub_commands;
mod token_storage;
mod utils;

const DEFAULT_WORK_DIR: &str = ".cdk-cli";
const CARGO_PKG_VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

/// Simple CLI application to interact with cashu
#[cfg(all(feature = "tor", not(target_arch = "wasm32")))]
#[derive(Copy, Clone, Debug, ValueEnum)]
enum TorToggle {
    On,
    Off,
}

#[derive(Parser)]
#[command(name = "cdk-cli", author = "thesimplekid <tsk@thesimplekid.com>", version = CARGO_PKG_VERSION.unwrap_or("Unknown"), about, long_about = None)]
struct Cli {
    /// Database engine to use (sqlite/redb)
    #[arg(short, long, default_value = "sqlite")]
    engine: String,
    /// Database password for sqlcipher
    #[cfg(feature = "sqlcipher")]
    #[arg(long)]
    password: Option<String>,
    /// Path to working dir
    #[arg(short, long)]
    work_dir: Option<PathBuf>,
    /// Logging level
    #[arg(short, long, default_value = "error")]
    log_level: Level,
    /// NWS Proxy
    #[arg(short, long)]
    proxy: Option<Url>,
    /// Currency unit to use for the wallet
    #[arg(short, long, default_value = "sat")]
    unit: String,
    /// NpubCash API URL
    #[cfg(feature = "npubcash")]
    #[arg(long, default_value = "https://npubx.cash")]
    npubcash_url: String,
    /// Use Tor transport (only when built with --features tor). Defaults to 'on' when feature is enabled.
    #[cfg(all(feature = "tor", not(target_arch = "wasm32")))]
    #[arg(long = "tor", value_enum, default_value_t = TorToggle::On)]
    transport: TorToggle,
    /// Subcommand to run
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(
        about = "Decode a Cashu token",
        long_about = "Decode a Cashu token and print its contents without receiving it into the wallet."
    )]
    DecodeToken(sub_commands::decode_token::DecodeTokenSubCommand),
    #[command(
        about = "Show wallet balances",
        long_about = "Show available balances across all configured mints and currency units."
    )]
    Balance,
    #[command(
        about = "Pay a Lightning invoice",
        long_about = "Pay a BOLT11 invoice, BOLT12 offer, or BIP353 address by melting ecash from the wallet."
    )]
    Melt(sub_commands::melt::MeltSubCommand),
    #[command(
        about = "Claim paid mint quotes",
        long_about = "Check pending mint quotes and claim ecash for quotes that have been paid."
    )]
    MintPending,
    #[command(
        about = "Receive a Cashu token",
        long_about = "Receive a Cashu token into the wallet, including tokens locked with supported spending conditions."
    )]
    Receive(sub_commands::receive::ReceiveSubCommand),
    #[command(
        about = "Send ecash",
        long_about = "Create a Cashu token from wallet funds, optionally with memo, mint selection, transfer, or lock options."
    )]
    Send(sub_commands::send::SendSubCommand),
    #[command(
        about = "Move ecash between mints",
        long_about = "Transfer wallet funds from one mint to another by sending from the source mint and receiving at the target mint."
    )]
    Transfer(sub_commands::transfer::TransferSubCommand),
    #[command(
        about = "Recover pending proofs",
        long_about = "Check pending proofs with their mints and return proofs that are no longer pending to the spendable balance."
    )]
    CheckPending,
    #[command(
        about = "Show mint information",
        long_about = "Fetch and display information advertised by a Cashu mint, such as supported features and settings."
    )]
    MintInfo(sub_commands::mint_info::MintInfoSubcommand),
    #[command(
        about = "Mint ecash",
        long_about = "Create a mint quote, pay the Lightning invoice, and mint ecash into the wallet."
    )]
    Mint(sub_commands::mint::MintSubCommand),
    #[command(
        about = "Burn spent tokens",
        long_about = "Check spent or pending tokens and remove tokens that can no longer be recovered into the wallet."
    )]
    Burn(sub_commands::burn::BurnSubCommand),
    #[command(
        about = "Restore ecash from seed",
        long_about = "Scan a mint for recoverable proofs derived from the wallet seed and add them back to the wallet."
    )]
    Restore(sub_commands::restore::RestoreSubCommand),
    #[command(
        about = "Update a mint URL",
        long_about = "Replace an existing mint URL in the wallet with a new URL for the selected currency unit."
    )]
    UpdateMintUrl(sub_commands::update_mint_url::UpdateMintUrlSubCommand),
    #[command(
        about = "List wallet proofs",
        long_about = "List proofs currently stored in the wallet, grouped by mint and proof state."
    )]
    ListMintProofs,
    #[command(
        about = "Decode a payment request",
        long_about = "Decode a Cashu payment request and print the requested amount, unit, mints, and conditions."
    )]
    DecodeRequest(sub_commands::decode_request::DecodePaymentRequestSubCommand),
    #[command(
        about = "Pay a payment request",
        long_about = "Pay a Cashu payment request from a matching wallet mint and currency unit."
    )]
    PayRequest(sub_commands::pay_request::PayRequestSubCommand),
    #[command(
        about = "Create a payment request",
        long_about = "Create a Cashu payment request that another wallet can pay, including optional amount and memo."
    )]
    CreateRequest(sub_commands::create_request::CreateRequestSubCommand),
    #[command(
        about = "Mint blind auth proofs",
        long_about = "Authenticate with a protected mint and mint blind authentication proofs for future requests."
    )]
    MintBlindAuth(sub_commands::mint_blind_auth::MintBlindAuthSubCommand),
    #[command(
        about = "Log in with clear auth credentials",
        long_about = "Authenticate to a protected mint with username and password clear auth flow and store the resulting token."
    )]
    CatLogin(sub_commands::cat_login::CatLoginSubCommand),
    #[command(
        about = "Log in with device code auth",
        long_about = "Authenticate to a protected mint with the OAuth device code flow and store the resulting clear auth token."
    )]
    CatDeviceLogin(sub_commands::cat_device_login::CatDeviceLoginSubCommand),
    #[cfg(feature = "npubcash")]
    #[command(
        about = "Manage NpubCash integration",
        long_about = "Sync, subscribe to, and manage NpubCash quotes using Nostr keys derived from the wallet seed."
    )]
    NpubCash {
        /// Mint URL to use for npubcash operations
        #[arg(short, long)]
        mint_url: String,
        #[command(subcommand)]
        command: sub_commands::npubcash::NpubCashSubCommand,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Cli = Cli::parse();
    let default_filter = args.log_level;

    let filter = "rustls=warn,hyper_util=warn,reqwest=warn";

    let env_filter = EnvFilter::new(format!("{default_filter},{filter}"));

    // Parse input
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_ansi(false)
        .init();

    let work_dir = match &args.work_dir {
        Some(work_dir) => work_dir.clone(),
        None => {
            let home_dir = home::home_dir()
                .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
            home_dir.join(DEFAULT_WORK_DIR)
        }
    };

    // Create work directory if it doesn't exist
    if !work_dir.exists() {
        fs::create_dir_all(&work_dir)?;
    }

    let localstore: Arc<dyn WalletDatabase<cdk_database::Error> + Send + Sync> =
        match args.engine.as_str() {
            "sqlite" => {
                let sql_path = work_dir.join("cdk-cli.sqlite");
                #[cfg(not(feature = "sqlcipher"))]
                let sql = WalletSqliteDatabase::new(&sql_path).await?;
                #[cfg(feature = "sqlcipher")]
                let sql = {
                    match args.password {
                        Some(pass) => WalletSqliteDatabase::new((sql_path, pass)).await?,
                        None => bail!("Missing database password"),
                    }
                };

                Arc::new(sql)
            }
            "redb" => {
                #[cfg(feature = "redb")]
                {
                    let redb_path = work_dir.join("cdk-cli.redb");
                    Arc::new(WalletRedbDatabase::new(&redb_path)?)
                }
                #[cfg(not(feature = "redb"))]
                {
                    bail!("redb feature not enabled");
                }
            }
            _ => bail!("Unknown DB engine"),
        };

    let seed_path = work_dir.join("seed");

    let mnemonic = match fs::metadata(seed_path.clone()) {
        Ok(_) => {
            let contents = fs::read_to_string(seed_path.clone())?;
            Mnemonic::from_str(&contents)?
        }
        Err(_e) => {
            let mut rng = thread_rng();
            let random_bytes: [u8; 32] = rng.gen();

            let mnemonic = Mnemonic::from_entropy(&random_bytes)?;
            tracing::info!("Creating new seed");

            fs::write(seed_path, mnemonic.to_string())?;

            mnemonic
        }
    };
    let seed = mnemonic.to_seed_normalized("");

    // Parse currency unit from args
    let currency_unit = CurrencyUnit::from_str(&args.unit)
        .unwrap_or_else(|_| CurrencyUnit::Custom(args.unit.clone()));

    // Create WalletRepository using builder pattern
    let wallet_repository = {
        let mut builder = cdk::wallet::WalletRepositoryBuilder::new()
            .localstore(localstore.clone())
            .seed(seed);

        if let Some(proxy_url) = &args.proxy {
            builder = builder.proxy_url(proxy_url.clone());
        }

        #[cfg(all(feature = "tor", not(target_arch = "wasm32")))]
        if matches!(args.transport, TorToggle::On) {
            builder = builder.tor();
        }

        builder.build().await?
    };

    let wallets = wallet_repository.get_wallets().await;

    for wallet in wallets {
        // Recover from incomplete operations (required after wallet creation)
        let recovery = wallet.recover_incomplete_sagas().await?;
        println!(
            "Recovered {} operations, {} compensated, {} skipped, {} failed",
            recovery.recovered, recovery.compensated, recovery.skipped, recovery.failed
        );
    }

    match &args.command {
        Commands::DecodeToken(sub_command_args) => {
            sub_commands::decode_token::decode_token(sub_command_args)
        }
        Commands::Balance => sub_commands::balance::balance(&wallet_repository).await,
        Commands::Melt(sub_command_args) => {
            sub_commands::melt::pay(&wallet_repository, sub_command_args, &currency_unit).await
        }
        Commands::Receive(sub_command_args) => {
            sub_commands::receive::receive(
                &wallet_repository,
                sub_command_args,
                &work_dir,
                &currency_unit,
            )
            .await
        }
        Commands::Send(sub_command_args) => {
            sub_commands::send::send(&wallet_repository, sub_command_args, &currency_unit).await
        }
        Commands::Transfer(sub_command_args) => {
            sub_commands::transfer::transfer(&wallet_repository, sub_command_args, &currency_unit)
                .await
        }
        Commands::CheckPending => {
            sub_commands::check_pending::check_pending(&wallet_repository).await
        }
        Commands::MintInfo(sub_command_args) => {
            sub_commands::mint_info::mint_info(args.proxy, sub_command_args).await
        }
        Commands::Mint(sub_command_args) => {
            sub_commands::mint::mint(&wallet_repository, sub_command_args, &currency_unit).await
        }
        Commands::MintPending => {
            sub_commands::pending_mints::mint_pending(&wallet_repository).await
        }
        Commands::Burn(sub_command_args) => {
            sub_commands::burn::burn(&wallet_repository, sub_command_args).await
        }
        Commands::Restore(sub_command_args) => {
            sub_commands::restore::restore(&wallet_repository, sub_command_args, &currency_unit)
                .await
        }
        Commands::UpdateMintUrl(sub_command_args) => {
            sub_commands::update_mint_url::update_mint_url(
                &wallet_repository,
                sub_command_args,
                &currency_unit,
            )
            .await
        }
        Commands::ListMintProofs => {
            sub_commands::list_mint_proofs::proofs(&wallet_repository).await
        }
        Commands::DecodeRequest(sub_command_args) => {
            sub_commands::decode_request::decode_payment_request(sub_command_args)
        }
        Commands::PayRequest(sub_command_args) => {
            sub_commands::pay_request::pay_request(&wallet_repository, sub_command_args).await
        }
        Commands::CreateRequest(sub_command_args) => {
            sub_commands::create_request::create_request(
                &wallet_repository,
                sub_command_args,
                &currency_unit,
            )
            .await
        }
        Commands::MintBlindAuth(sub_command_args) => {
            sub_commands::mint_blind_auth::mint_blind_auth(
                &wallet_repository,
                sub_command_args,
                &work_dir,
                &currency_unit,
            )
            .await
        }
        Commands::CatLogin(sub_command_args) => {
            sub_commands::cat_login::cat_login(&wallet_repository, sub_command_args, &work_dir)
                .await
        }
        Commands::CatDeviceLogin(sub_command_args) => {
            sub_commands::cat_device_login::cat_device_login(
                &wallet_repository,
                sub_command_args,
                &work_dir,
            )
            .await
        }
        #[cfg(feature = "npubcash")]
        Commands::NpubCash { mint_url, command } => {
            sub_commands::npubcash::npubcash(
                &wallet_repository,
                mint_url,
                command,
                Some(args.npubcash_url.clone()),
            )
            .await
        }
    }
}
