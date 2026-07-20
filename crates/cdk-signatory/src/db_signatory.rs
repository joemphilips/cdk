//! Main Signatory implementation
//!
//! It is named db_signatory because it uses a database to maintain state.
use std::collections::HashMap;
#[cfg(all(test, feature = "conditional-tokens"))]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::{self, Secp256k1};
use cdk_common::dhke::{sign_message, verify_message};
use cdk_common::mint::MintKeySetInfo;
use cdk_common::nuts::{BlindSignature, BlindedMessage, CurrencyUnit, Id, MintKeySet, Proof};
use cdk_common::{database, Error, PublicKey};
use tokio::sync::RwLock;
use tracing::instrument;

use crate::common::{
    check_unit_string_collision_for_units, create_new_keyset, derivation_path_from_unit,
    init_keysets,
};
#[cfg(feature = "conditional-tokens")]
use crate::signatory::PreparedConditionalKeySet;
use crate::signatory::{
    validate_keyset_info_binding, RotateKeyArguments, Signatory, SignatoryKeySet, SignatoryKeysets,
};

#[cfg(all(test, feature = "conditional-tokens"))]
struct ReloadPause {
    reached: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
}

#[cfg(all(test, feature = "conditional-tokens"))]
#[derive(Default)]
struct DbSignatoryTestHooks {
    reload_pause: tokio::sync::Mutex<Option<ReloadPause>>,
    pause_first_rotation_after_commit: AtomicBool,
    rotation_commit_count: AtomicUsize,
    rotation_commit_notify: tokio::sync::Notify,
    rotation_release: tokio::sync::Notify,
}

/// In-memory Signatory
///
/// This is the default signatory implementation for the mint.
///
/// The private keys and the all key-related data is stored in memory, in the same process, but it
/// is not accessible from the outside.
#[allow(missing_debug_implementations)]
pub struct DbSignatory {
    keysets: RwLock<HashMap<Id, (MintKeySetInfo, MintKeySet)>>,
    active_keysets: RwLock<HashMap<CurrencyUnit, Id>>,
    localstore: Arc<dyn database::MintKeysDatabase<Err = database::Error> + Send + Sync>,
    secp_ctx: Secp256k1<secp256k1::All>,
    custom_paths: HashMap<CurrencyUnit, DerivationPath>,
    xpriv: Xpriv,
    xpub: PublicKey,
    keyset_mutation_lock: tokio::sync::Mutex<()>,
    #[cfg(all(test, feature = "conditional-tokens"))]
    conditional_derivation_count: Arc<AtomicUsize>,
    #[cfg(all(test, feature = "conditional-tokens"))]
    test_hooks: DbSignatoryTestHooks,
}

impl DbSignatory {
    /// Creates a new MemorySignatory instance
    ///
    /// # Panics
    ///
    /// Panics if the seed produces an invalid master key (should never happen with valid entropy).
    pub async fn new(
        localstore: Arc<dyn database::MintKeysDatabase<Err = database::Error> + Send + Sync>,
        seed: &[u8],
        mut supported_units: HashMap<CurrencyUnit, (u64, Vec<u64>)>,
        custom_paths: HashMap<CurrencyUnit, DerivationPath>,
    ) -> Result<Self, Error> {
        let secp_ctx = Secp256k1::new();
        let xpriv = Xpriv::new_master(bitcoin::Network::Bitcoin, seed).expect("RNG busted");
        init_keysets(xpriv, &secp_ctx, &localstore, &supported_units).await?;

        supported_units
            .entry(CurrencyUnit::Auth)
            .or_insert((0, vec![1]));

        let keys = Self {
            keysets: Default::default(),
            active_keysets: Default::default(),
            localstore,
            custom_paths,
            xpub: xpriv.to_keypair(&secp_ctx).public_key().into(),
            secp_ctx,
            xpriv,
            keyset_mutation_lock: tokio::sync::Mutex::new(()),
            #[cfg(all(test, feature = "conditional-tokens"))]
            conditional_derivation_count: Arc::new(AtomicUsize::new(0)),
            #[cfg(all(test, feature = "conditional-tokens"))]
            test_hooks: DbSignatoryTestHooks::default(),
        };
        keys.reload_keys_from_db().await?;

        Ok(keys)
    }

    /// Load all the keysets from the database, even if they are not active.
    ///
    /// Since the database is owned by this process, we can load all the keysets in memory, and use
    /// it as the primary source, and the database as the persistence layer.
    ///
    /// Any operation performed with keysets, are done through this trait and never to the database
    /// directly.
    ///
    /// The load path is split in two:
    /// - Regular keysets come from the `keyset` table. Active status is derived from
    ///   `get_active_keysets()` which returns one keyset per unit (the primary).
    /// - Conditional keysets (NUT-CTF) live in the separate `conditional_keyset` table.
    ///   Each row's `active` flag is honoured verbatim (the unique partial index enforces
    ///   "at most one active per outcome_collection_id"), so conditional keysets do NOT
    ///   collapse the per-unit primary keyset.
    async fn reload_keys_from_db(&self) -> Result<(), Error> {
        let _mutation_guard = self.keyset_mutation_lock.lock().await;
        let db_active_keysets = self.localstore.get_active_keysets().await?;
        let regular_infos = self.localstore.get_keyset_infos().await?;

        #[cfg(feature = "conditional-tokens")]
        let conditional_infos = self
            .localstore
            .get_all_conditional_mint_keyset_infos()
            .await?;

        #[cfg(all(test, feature = "conditional-tokens"))]
        self.pause_reload_after_database_read().await;

        let secp_ctx = self.secp_ctx.clone();
        let xpriv = self.xpriv;
        let (replacement_keysets, replacement_active_keysets) =
            tokio::task::spawn_blocking(move || {
                let mut keysets = HashMap::new();
                let mut active_keysets = HashMap::new();
                for mut info in regular_infos {
                    let id = info.id;
                    info.active = db_active_keysets.get(&info.unit) == Some(&id);
                    let keyset = MintKeySet::generate_from_xpriv(
                        &secp_ctx,
                        xpriv,
                        &info.amounts,
                        info.unit.clone(),
                        info.derivation_path.clone(),
                        info.input_fee_ppk,
                        info.final_expiry,
                        info.id.get_version(),
                    );
                    let public = (&info, &keyset).into();
                    validate_keyset_info_binding(&info, &public)?;
                    if info.active {
                        active_keysets.insert(info.unit.clone(), id);
                    }
                    keysets.insert(id, (info, keyset));
                }

                #[cfg(feature = "conditional-tokens")]
                for info in conditional_infos {
                    let keyset = MintKeySet::generate_from_xpriv(
                        &secp_ctx,
                        xpriv,
                        &info.amounts,
                        info.unit.clone(),
                        info.derivation_path.clone(),
                        info.input_fee_ppk,
                        info.final_expiry,
                        info.id.get_version(),
                    );
                    let public = (&info, &keyset).into();
                    validate_keyset_info_binding(&info, &public)?;
                    // Conditional keysets are NOT registered in active_keysets — that map
                    // still has "one primary per unit" semantics so that wallets binding
                    // via /v1/keys find the real collateral keyset, not a CTF keyset.
                    let id = info.id;
                    keysets.insert(id, (info, keyset));
                }

                Ok::<_, Error>((keysets, active_keysets))
            })
            .await
            .map_err(|error| Error::Custom(format!("keyset reload task failed: {error}")))??;

        // Keep signing reads on the old complete maps throughout database I/O
        // and key derivation. Both replacements are published under short
        // write locks, so readers never observe a cleared or partial map.
        let mut keysets = self.keysets.write().await;
        let mut active_keysets = self.active_keysets.write().await;
        *keysets = replacement_keysets;
        *active_keysets = replacement_active_keysets;

        Ok(())
    }

    #[cfg(all(test, feature = "conditional-tokens"))]
    async fn pause_next_reload(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        *self.test_hooks.reload_pause.lock().await = Some(ReloadPause {
            reached: reached_tx,
            release: release_rx,
        });
        (reached_rx, release_tx)
    }

    #[cfg(all(test, feature = "conditional-tokens"))]
    async fn pause_reload_after_database_read(&self) {
        if let Some(pause) = self.test_hooks.reload_pause.lock().await.take() {
            let _ = pause.reached.send(());
            let _ = pause.release.await;
        }
    }

    #[cfg(all(test, feature = "conditional-tokens"))]
    fn pause_first_rotation_after_commit(&self) {
        self.test_hooks
            .pause_first_rotation_after_commit
            .store(true, Ordering::SeqCst);
    }

    #[cfg(all(test, feature = "conditional-tokens"))]
    async fn after_rotation_commit(&self) {
        let commit_number = self
            .test_hooks
            .rotation_commit_count
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        self.test_hooks.rotation_commit_notify.notify_waiters();
        if commit_number == 1
            && self
                .test_hooks
                .pause_first_rotation_after_commit
                .load(Ordering::SeqCst)
        {
            self.test_hooks.rotation_release.notified().await;
        }
    }

    #[cfg(all(test, feature = "conditional-tokens"))]
    async fn wait_for_rotation_commits(&self, expected: usize) {
        loop {
            let notified = self.test_hooks.rotation_commit_notify.notified();
            if self.test_hooks.rotation_commit_count.load(Ordering::SeqCst) >= expected {
                return;
            }
            notified.await;
        }
    }
}

#[async_trait::async_trait]
impl Signatory for DbSignatory {
    fn name(&self) -> String {
        format!("Signatory {}", env!("CARGO_PKG_VERSION"))
    }

    #[instrument(skip_all)]
    async fn blind_sign(
        &self,
        blinded_messages: Vec<BlindedMessage>,
    ) -> Result<Vec<BlindSignature>, Error> {
        let keysets = self.keysets.read().await;

        blinded_messages
            .into_iter()
            .map(|blinded_message| {
                let BlindedMessage {
                    amount,
                    blinded_secret,
                    keyset_id,
                    ..
                } = blinded_message;

                let (info, key) = keysets.get(&keyset_id).ok_or(Error::UnknownKeySet)?;
                if !info.active {
                    return Err(Error::InactiveKeyset);
                }

                let key_pair = key.keys.get(&amount).ok_or(Error::UnknownKeySet)?;
                let c = sign_message(&key_pair.secret_key, &blinded_secret)?;

                let blinded_signature = BlindSignature::new(
                    amount,
                    c,
                    keyset_id,
                    &blinded_message.blinded_secret,
                    key_pair.secret_key.clone(),
                )?;

                Ok(blinded_signature)
            })
            .collect::<Result<Vec<_>, _>>()
    }

    #[tracing::instrument(skip_all)]
    async fn verify_proofs(&self, proofs: Vec<Proof>) -> Result<(), Error> {
        let keysets = self.keysets.read().await;

        proofs.into_iter().try_for_each(|proof| {
            let (_, key) = keysets.get(&proof.keyset_id).ok_or(Error::UnknownKeySet)?;
            let key_pair = key.keys.get(&proof.amount).ok_or(Error::UnknownKeySet)?;
            verify_message(&key_pair.secret_key, proof.c, proof.secret.as_bytes())?;
            Ok(())
        })
    }

    #[tracing::instrument(skip_all)]
    async fn keysets(&self) -> Result<SignatoryKeysets, Error> {
        Ok(SignatoryKeysets {
            pubkey: self.xpub,
            keysets: self
                .keysets
                .read()
                .await
                .values()
                .map(|k| k.into())
                .collect::<Vec<_>>(),
        })
    }

    /// Add current keyset to inactive keysets
    /// Generate new keyset
    #[tracing::instrument(skip(self))]
    async fn rotate_keyset(&self, args: RotateKeyArguments) -> Result<SignatoryKeySet, Error> {
        let _mutation_guard = self.keyset_mutation_lock.lock().await;
        let current_keyset_id = self.localstore.get_active_keyset_id(&args.unit).await?;
        let (path_index, amounts) = if let Some(current_keyset_id) = current_keyset_id {
            let keyset_info = self
                .localstore
                .get_keyset_info(&current_keyset_id)
                .await?
                .ok_or(Error::UnknownKeySet)?;

            (
                keyset_info.derivation_path_index.unwrap_or(1) + 1,
                keyset_info.amounts,
            )
        } else {
            (1, vec![])
        };

        let derivation_path = match self.custom_paths.get(&args.unit) {
            Some(path) => path.clone(),
            None => derivation_path_from_unit(args.unit.clone(), path_index)
                .ok_or(Error::UnsupportedUnit)?,
        };

        let amounts = if args.amounts.is_empty() {
            if amounts.is_empty() {
                return Err(Error::Custom("Amounts cannot be empty".to_string()));
            }
            amounts
        } else {
            args.amounts
        };

        let (keyset, info) = create_new_keyset(
            &self.secp_ctx,
            self.xpriv,
            derivation_path,
            Some(path_index),
            args.unit.clone(),
            &amounts,
            args.input_fee_ppk,
            args.final_expiry,
            args.keyset_id_type,
        );

        {
            let keysets = self.keysets.read().await;
            check_unit_string_collision_for_units(
                keysets.values().map(|(info, _)| info.unit.clone()),
                &info,
            )?;
        }

        let id = info.id;
        let unit = args.unit;
        let mut tx = self.localstore.begin_transaction().await?;
        tx.add_keyset_info(info.clone()).await?;
        tx.set_active_keyset(unit.clone(), id).await?;
        tx.commit().await?;

        #[cfg(all(test, feature = "conditional-tokens"))]
        self.after_rotation_commit().await;

        // Publish only the changed regular keysets. Conditional keysets can
        // number in the thousands and are unrelated to this unit rotation.
        let public = (&(info.clone(), keyset.clone())).into();
        let mut keysets = self.keysets.write().await;
        if let Some(previous_id) = current_keyset_id {
            if previous_id != id {
                if let Some((previous_info, _)) = keysets.get_mut(&previous_id) {
                    previous_info.active = false;
                }
            }
        }
        keysets.insert(id, (info, keyset));
        self.active_keysets.write().await.insert(unit, id);

        Ok(public)
    }

    #[cfg(feature = "conditional-tokens")]
    #[tracing::instrument(skip(self))]
    async fn prepare_conditional_keyset(
        &self,
        unit: CurrencyUnit,
        condition_id: &str,
        outcome_collection: &str,
        outcome_collection_id: &str,
        amounts: Vec<u64>,
        input_fee_ppk: u64,
        final_expiry: Option<u64>,
    ) -> Result<PreparedConditionalKeySet, Error> {
        let (keyset, mut info) = crate::common::create_conditional_keyset(
            &self.secp_ctx,
            self.xpriv,
            unit,
            condition_id,
            outcome_collection_id,
            &amounts,
            input_fee_ppk,
            final_expiry,
        )
        .ok_or(Error::UnsupportedUnit)?;

        info.outcome_collection = Some(outcome_collection.to_string());
        info.active = true;

        let public = (&(info.clone(), keyset)).into();

        Ok(PreparedConditionalKeySet {
            keyset: public,
            info,
        })
    }

    #[cfg(feature = "conditional-tokens")]
    #[tracing::instrument(skip_all, fields(keyset_count = keysets.len()))]
    async fn install_conditional_keysets(
        &self,
        keysets: Vec<MintKeySetInfo>,
    ) -> Result<Vec<SignatoryKeySet>, Error> {
        let _mutation_guard = self.keyset_mutation_lock.lock().await;
        let mut missing_by_id = HashMap::<Id, MintKeySetInfo>::new();
        {
            let in_memory = self.keysets.read().await;
            for info in &keysets {
                match in_memory.get(&info.id) {
                    Some((existing, _)) if existing != info => {
                        return Err(Error::Custom(format!(
                            "Conflicting conditional keyset metadata for id {}",
                            info.id
                        )));
                    }
                    Some(_) => {}
                    None => match missing_by_id.get(&info.id) {
                        Some(existing) if existing != info => {
                            return Err(Error::Custom(format!(
                                "Conflicting conditional keyset metadata for id {}",
                                info.id
                            )));
                        }
                        Some(_) => {}
                        None => {
                            missing_by_id.insert(info.id, info.clone());
                        }
                    },
                }
            }
        }

        let missing = missing_by_id.into_values().collect::<Vec<_>>();
        let secp_ctx = self.secp_ctx.clone();
        let xpriv = self.xpriv;
        #[cfg(test)]
        self.conditional_derivation_count
            .fetch_add(missing.len(), Ordering::SeqCst);
        let prepared = if missing.is_empty() {
            Vec::new()
        } else {
            tokio::task::spawn_blocking(move || {
                missing
                    .into_iter()
                    .map(|info| {
                        let private = MintKeySet::generate_from_xpriv(
                            &secp_ctx,
                            xpriv,
                            &info.amounts,
                            info.unit.clone(),
                            info.derivation_path.clone(),
                            info.input_fee_ppk,
                            info.final_expiry,
                            info.id.get_version(),
                        );
                        let public = (&info, &private).into();
                        validate_keyset_info_binding(&info, &public)?;
                        Ok((info.id, info, private))
                    })
                    .collect::<Result<Vec<(Id, MintKeySetInfo, MintKeySet)>, Error>>()
            })
            .await
            .map_err(|error| {
                Error::Custom(format!("conditional key derivation task failed: {error}"))
            })??
        };

        {
            let mut in_memory = self.keysets.write().await;
            for (id, info, _) in &prepared {
                if in_memory
                    .get(id)
                    .is_some_and(|(existing, _)| existing != info)
                {
                    return Err(Error::Custom(format!(
                        "Conflicting conditional keyset metadata for id {id}"
                    )));
                }
            }
            for (id, info, private) in prepared {
                in_memory.entry(id).or_insert((info, private));
            }
        }

        let in_memory = self.keysets.read().await;
        keysets
            .into_iter()
            .map(|requested| {
                let (installed, private) = in_memory.get(&requested.id).ok_or_else(|| {
                    Error::Custom(format!(
                        "Conditional keyset {} was not installed",
                        requested.id
                    ))
                })?;
                if installed != &requested {
                    return Err(Error::Custom(format!(
                        "Conflicting conditional keyset metadata for id {}",
                        requested.id
                    )));
                }
                Ok((installed, private).into())
            })
            .collect()
    }

    #[cfg(feature = "conditional-tokens")]
    async fn reload_keysets_from_storage(&self) -> Result<(), Error> {
        self.reload_keys_from_db().await
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::collections::HashSet;
    #[cfg(feature = "conditional-tokens")]
    use std::sync::Arc;

    use bitcoin::key::Secp256k1;
    use bitcoin::Network;
    #[cfg(feature = "conditional-tokens")]
    use cdk_common::database::mint::{ConditionsDatabase, KeysDatabase};
    use cdk_common::util::hex;
    use cdk_common::{Amount, MintKeySet, PublicKey};

    use super::*;

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn incremental_install_handles_representative_two_thousand_keyset_batch() {
        const KEYSET_COUNT: usize = 2_000;

        let database = Arc::new(
            cdk_sqlite::mint::memory::empty()
                .await
                .expect("mint database should open"),
        );
        let mut supported_units = HashMap::new();
        supported_units.insert(CurrencyUnit::Sat, (0, vec![1]));
        let signatory = Arc::new(
            DbSignatory::new(database, &[0x42; 64], supported_units, HashMap::new())
                .await
                .expect("signatory should initialize"),
        );

        let mut infos = Vec::with_capacity(KEYSET_COUNT);
        for index in 0..KEYSET_COUNT {
            let prepared = signatory
                .prepare_conditional_keyset(
                    CurrencyUnit::Sat,
                    &"11".repeat(32),
                    &format!("OUTCOME-{index}"),
                    &format!("{index:064x}"),
                    vec![1],
                    0,
                    None,
                )
                .await
                .expect("conditional keyset should prepare");
            infos.push(prepared.info);
        }
        let existing_count = signatory
            .keysets()
            .await
            .expect("existing keysets should read")
            .keysets
            .len();

        let started = std::time::Instant::now();
        let installing = {
            let signatory = signatory.clone();
            tokio::spawn(async move { signatory.install_conditional_keysets(infos).await })
        };
        let observed = tokio::time::timeout(std::time::Duration::from_secs(1), signatory.keysets())
            .await
            .expect("public keyset reads should not wait on batch derivation")
            .expect("public keysets should remain readable");
        let installed = installing
            .await
            .expect("install task should join")
            .expect("prepared keysets should install");
        let elapsed = started.elapsed();

        eprintln!(
            "incrementally installed {KEYSET_COUNT} conditional keysets in {} ms",
            elapsed.as_millis()
        );
        assert_eq!(installed.len(), KEYSET_COUNT);
        assert!(observed.keysets.len() >= existing_count);
        assert_eq!(
            signatory
                .keysets()
                .await
                .expect("installed keysets should read")
                .keysets
                .len(),
            KEYSET_COUNT + existing_count,
            "existing and newly installed conditional keysets should remain available"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "representative incremental install exceeded its local test budget: {elapsed:?}"
        );

        let before_rotation = signatory
            .keysets()
            .await
            .expect("keysets before rotation should read");
        let rotation_started = std::time::Instant::now();
        signatory
            .rotate_keyset(RotateKeyArguments {
                unit: CurrencyUnit::Sat,
                amounts: vec![1],
                input_fee_ppk: 0,
                keyset_id_type: cdk_common::nut02::KeySetVersion::Version01,
                final_expiry: None,
            })
            .await
            .expect("regular keyset should rotate incrementally");
        let after_rotation = signatory
            .keysets()
            .await
            .expect("keysets after rotation should read");
        assert_eq!(
            after_rotation.keysets.len(),
            before_rotation.keysets.len() + 1
        );
        assert_eq!(
            after_rotation
                .keysets
                .iter()
                .filter(|keyset| keyset.condition_id.is_some())
                .count(),
            KEYSET_COUNT,
            "regular rotation must preserve every installed conditional keyset"
        );
        assert!(
            rotation_started.elapsed() < std::time::Duration::from_secs(1),
            "regular rotation should not rederive the representative conditional catalogue"
        );
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_reload_keeps_existing_keysets_available_until_atomic_replacement() {
        let database = Arc::new(
            cdk_sqlite::mint::memory::empty()
                .await
                .expect("mint database should open"),
        );
        let mut supported_units = HashMap::new();
        supported_units.insert(CurrencyUnit::Sat, (0, vec![1]));
        let signatory = Arc::new(
            DbSignatory::new(
                database.clone(),
                &[0x44; 64],
                supported_units,
                HashMap::new(),
            )
            .await
            .expect("signatory should initialize"),
        );
        let old_id = signatory
            .rotate_keyset(RotateKeyArguments {
                unit: CurrencyUnit::Sat,
                amounts: vec![1],
                input_fee_ppk: 0,
                keyset_id_type: cdk_common::nut02::KeySetVersion::Version01,
                final_expiry: None,
            })
            .await
            .expect("initial SAT keyset should rotate")
            .id;
        let derivation_path = derivation_path_from_unit(CurrencyUnit::Sat, 2)
            .expect("second SAT derivation path should exist");
        let (_, replacement_info) = create_new_keyset(
            &signatory.secp_ctx,
            signatory.xpriv,
            derivation_path,
            Some(2),
            CurrencyUnit::Sat,
            &[1],
            0,
            None,
            cdk_common::nut02::KeySetVersion::Version01,
        );
        let replacement_id = replacement_info.id;
        let mut tx = database
            .begin_transaction()
            .await
            .expect("keyset transaction should start");
        tx.add_keyset_info(replacement_info)
            .await
            .expect("replacement keyset should persist");
        tx.set_active_keyset(CurrencyUnit::Sat, replacement_id)
            .await
            .expect("replacement keyset should become authoritative");
        tx.commit().await.expect("replacement keyset should commit");

        let (reload_reached, reload_release) = signatory.pause_next_reload().await;
        let reloading = {
            let signatory = signatory.clone();
            tokio::spawn(async move { signatory.reload_keysets_from_storage().await })
        };
        reload_reached
            .await
            .expect("reload should pause after its database read");

        let blinded_secret = PublicKey::from_hex(
            "024aebe0f8be04b1ba1d7d6b7fe454c9ae43e0fa22b2fdc88b172f3c5a0d19aaa4",
        )
        .expect("public key should parse");
        let signing = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            signatory.blind_sign(vec![BlindedMessage::new(
                Amount::from(1_u64),
                old_id,
                blinded_secret,
            )]),
        )
        .await;
        reload_release
            .send(())
            .expect("blocked reload should still be waiting");
        reloading
            .await
            .expect("reload task should join")
            .expect("reload should complete");
        assert_eq!(
            signing
                .expect("blind signing must not wait for database fetch or key derivation")
                .expect("the previously active keyset must remain signable")
                .len(),
            1
        );

        let active_keysets = signatory.active_keysets.read().await;
        let keysets = signatory.keysets.read().await;
        assert_eq!(
            active_keysets.get(&CurrencyUnit::Sat),
            Some(&replacement_id)
        );
        assert!(keysets
            .get(&replacement_id)
            .is_some_and(|(info, _)| info.active));
        assert!(keysets.get(&old_id).is_some_and(|(info, _)| !info.active));
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_regular_rotations_publish_latest_authoritative_commit() {
        let database = Arc::new(
            cdk_sqlite::mint::memory::empty()
                .await
                .expect("mint database should open"),
        );
        let mut supported_units = HashMap::new();
        supported_units.insert(CurrencyUnit::Sat, (0, vec![1]));
        let signatory = Arc::new(
            DbSignatory::new(
                database.clone(),
                &[0x45; 64],
                supported_units,
                HashMap::new(),
            )
            .await
            .expect("signatory should initialize"),
        );
        signatory.pause_first_rotation_after_commit();
        let first = {
            let signatory = signatory.clone();
            tokio::spawn(async move {
                signatory
                    .rotate_keyset(RotateKeyArguments {
                        unit: CurrencyUnit::Sat,
                        amounts: vec![1],
                        input_fee_ppk: 1,
                        keyset_id_type: cdk_common::nut02::KeySetVersion::Version01,
                        final_expiry: None,
                    })
                    .await
            })
        };
        signatory.wait_for_rotation_commits(1).await;
        let second = {
            let signatory = signatory.clone();
            tokio::spawn(async move {
                signatory
                    .rotate_keyset(RotateKeyArguments {
                        unit: CurrencyUnit::Sat,
                        amounts: vec![1],
                        input_fee_ppk: 2,
                        keyset_id_type: cdk_common::nut02::KeySetVersion::Version01,
                        final_expiry: None,
                    })
                    .await
            })
        };

        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            signatory.wait_for_rotation_commits(2),
        )
        .await;
        signatory.test_hooks.rotation_release.notify_waiters();
        let first = first
            .await
            .expect("first rotation task should join")
            .expect("first rotation should succeed");
        let second = second
            .await
            .expect("second rotation task should join")
            .expect("second rotation should succeed");
        assert_ne!(first.id, second.id);

        assert_eq!(
            database
                .get_active_keyset_id(&CurrencyUnit::Sat)
                .await
                .expect("database active keyset should load"),
            Some(second.id),
            "database authority must retain the latest committed rotation"
        );
        assert_eq!(
            signatory
                .active_keysets
                .read()
                .await
                .get(&CurrencyUnit::Sat),
            Some(&second.id),
            "in-memory active map must match the latest commit"
        );
        let keysets = signatory.keysets.read().await;
        assert!(keysets.get(&second.id).is_some_and(|(info, _)| info.active));
        assert!(keysets.get(&first.id).is_some_and(|(info, _)| !info.active));
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn reload_rejects_conditional_id_derived_by_a_different_seed_without_map_mutation() {
        let database = Arc::new(
            cdk_sqlite::mint::memory::empty()
                .await
                .expect("mint database should open"),
        );
        let mut supported_units = HashMap::new();
        supported_units.insert(CurrencyUnit::Sat, (0, vec![1]));
        let signatory = DbSignatory::new(
            database.clone(),
            &[0x46; 64],
            supported_units.clone(),
            HashMap::new(),
        )
        .await
        .expect("signatory should initialize");
        signatory
            .rotate_keyset(RotateKeyArguments {
                unit: CurrencyUnit::Sat,
                amounts: vec![1],
                input_fee_ppk: 0,
                keyset_id_type: cdk_common::nut02::KeySetVersion::Version01,
                final_expiry: None,
            })
            .await
            .expect("regular keyset should initialize the live map");
        let before_keysets = signatory.keysets.read().await.clone();
        let before_active = signatory.active_keysets.read().await.clone();

        let foreign_database = Arc::new(
            cdk_sqlite::mint::memory::empty()
                .await
                .expect("foreign database should open"),
        );
        let foreign = DbSignatory::new(
            foreign_database,
            &[0x47; 64],
            supported_units,
            HashMap::new(),
        )
        .await
        .expect("foreign signatory should initialize");
        let condition_id = "46".repeat(32);
        let foreign_info = foreign
            .prepare_conditional_keyset(
                CurrencyUnit::Sat,
                &condition_id,
                "YES",
                &"47".repeat(32),
                vec![1],
                0,
                None,
            )
            .await
            .expect("foreign conditional keyset should prepare")
            .info;
        database
            .add_condition(cdk_common::mint::StoredCondition {
                condition_id,
                threshold: 1,
                tags_json: "[]".to_string(),
                announcements_json: "[]".to_string(),
                collateral: Some(CurrencyUnit::Sat),
                attestation_status: "pending".to_string(),
                winning_outcome: None,
                attested_at: None,
                created_at: 1_000,
                condition_type: "enum".to_string(),
                lo_bound: None,
                hi_bound: None,
                precision: None,
            })
            .await
            .expect("condition should persist for corruption test");
        database
            .add_conditional_keyset(foreign_info, 1_000)
            .await
            .expect("foreign metadata should persist for corruption test");

        signatory
            .reload_keysets_from_storage()
            .await
            .expect_err("reload must reject keys that do not derive to the persisted ID");
        assert_eq!(*signatory.keysets.read().await, before_keysets);
        assert_eq!(*signatory.active_keysets.read().await, before_active);
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn install_rejects_corrupt_conditional_binding_without_map_mutation() {
        let database = Arc::new(
            cdk_sqlite::mint::memory::empty()
                .await
                .expect("mint database should open"),
        );
        let mut supported_units = HashMap::new();
        supported_units.insert(CurrencyUnit::Sat, (0, vec![1]));
        let signatory = DbSignatory::new(database, &[0x48; 64], supported_units, HashMap::new())
            .await
            .expect("signatory should initialize");
        let mut corrupt = signatory
            .prepare_conditional_keyset(
                CurrencyUnit::Sat,
                &"48".repeat(32),
                "YES",
                &"49".repeat(32),
                vec![1],
                0,
                None,
            )
            .await
            .expect("conditional keyset should prepare")
            .info;
        corrupt.outcome_collection_id = Some("50".repeat(32));
        let before_keysets = signatory.keysets.read().await.clone();
        let before_active = signatory.active_keysets.read().await.clone();

        signatory
            .install_conditional_keysets(vec![corrupt])
            .await
            .expect_err("install must reject corrupt conditional metadata binding");
        assert_eq!(*signatory.keysets.read().await, before_keysets);
        assert_eq!(*signatory.active_keysets.read().await, before_active);
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn repeated_and_concurrent_install_derives_each_missing_keyset_once() {
        const CONCURRENT_RETRIES: usize = 8;

        let database = Arc::new(
            cdk_sqlite::mint::memory::empty()
                .await
                .expect("mint database should open"),
        );
        let mut supported_units = HashMap::new();
        supported_units.insert(CurrencyUnit::Sat, (0, vec![1]));
        let signatory = Arc::new(
            DbSignatory::new(database, &[0x43; 64], supported_units, HashMap::new())
                .await
                .expect("signatory should initialize"),
        );
        let info = signatory
            .prepare_conditional_keyset(
                CurrencyUnit::Sat,
                &"12".repeat(32),
                "YES",
                &"13".repeat(32),
                vec![1],
                0,
                None,
            )
            .await
            .expect("conditional keyset should prepare")
            .info;
        let barrier = Arc::new(tokio::sync::Barrier::new(CONCURRENT_RETRIES + 1));
        let mut retries = Vec::new();
        for _ in 0..CONCURRENT_RETRIES {
            let signatory = signatory.clone();
            let info = info.clone();
            let barrier = barrier.clone();
            retries.push(tokio::spawn(async move {
                barrier.wait().await;
                signatory.install_conditional_keysets(vec![info]).await
            }));
        }
        barrier.wait().await;

        for retry in retries {
            let installed = retry
                .await
                .expect("concurrent retry should join")
                .expect("concurrent retry should reconcile");
            assert_eq!(installed.len(), 1);
            assert_eq!(installed[0].id, info.id);
        }
        assert_eq!(
            signatory
                .conditional_derivation_count
                .load(Ordering::SeqCst),
            1,
            "concurrent retries must coalesce the one necessary derivation"
        );

        let replayed = signatory
            .install_conditional_keysets(vec![info.clone()])
            .await
            .expect("healthy replay should return the existing public keyset");
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].id, info.id);
        assert_eq!(
            signatory
                .conditional_derivation_count
                .load(Ordering::SeqCst),
            1,
            "healthy replay must not schedule free key derivation work"
        );

        let mut conflicting = info;
        conflicting.input_fee_ppk = 1;
        let error = signatory
            .install_conditional_keysets(vec![conflicting])
            .await
            .expect_err("immutable metadata conflict must fail before derivation");
        assert!(error.to_string().contains("Conflicting conditional keyset"));
        assert_eq!(
            signatory
                .conditional_derivation_count
                .load(Ordering::SeqCst),
            1,
            "metadata conflicts must not schedule derivation work"
        );
    }

    #[test]
    fn mint_mod_generate_keyset_from_seed() {
        let seed = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
        let keyset = MintKeySet::generate_from_seed(
            &Secp256k1::new(),
            &seed,
            &[1, 2],
            CurrencyUnit::Sat,
            derivation_path_from_unit(CurrencyUnit::Sat, 0).unwrap(),
            0,
            None,
            cdk_common::nut02::KeySetVersion::Version01,
        );

        assert_eq!(keyset.unit, CurrencyUnit::Sat);
        assert_eq!(keyset.keys.len(), 2);

        let expected_amounts_and_pubkeys: HashSet<(Amount, PublicKey)> = vec![
            (
                Amount::from(1),
                PublicKey::from_hex(
                    "0380a4bb98d9bc5d5b11c7cf2b705dbc894b62ac99cf67e0ef1a3d47ea6dc54706",
                )
                .unwrap(),
            ),
            (
                Amount::from(2),
                PublicKey::from_hex(
                    "022fe5e50a15d721014b538ca6a3ff20ee049b195ba0b1705f64829da8779b6940",
                )
                .unwrap(),
            ),
        ]
        .into_iter()
        .collect();

        let amounts_and_pubkeys: HashSet<(Amount, PublicKey)> = keyset
            .keys
            .iter()
            .map(|(amount, pair)| (*amount, pair.public_key))
            .collect();

        assert_eq!(amounts_and_pubkeys, expected_amounts_and_pubkeys);
    }

    #[test]
    fn mint_mod_generate_keyset_from_xpriv() {
        let seed = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
        let network = Network::Bitcoin;
        let xpriv = Xpriv::new_master(network, &seed).expect("Failed to create xpriv");
        let keyset = MintKeySet::generate_from_xpriv(
            &Secp256k1::new(),
            xpriv,
            &[1, 2],
            CurrencyUnit::Sat,
            derivation_path_from_unit(CurrencyUnit::Sat, 0).unwrap(),
            0,
            None,
            cdk_common::nut02::KeySetVersion::Version00,
        );

        assert_eq!(keyset.unit, CurrencyUnit::Sat);
        assert_eq!(keyset.keys.len(), 2);

        let expected_amounts_and_pubkeys: HashSet<(Amount, PublicKey)> = vec![
            (
                Amount::from(1),
                PublicKey::from_hex(
                    "0380a4bb98d9bc5d5b11c7cf2b705dbc894b62ac99cf67e0ef1a3d47ea6dc54706",
                )
                .unwrap(),
            ),
            (
                Amount::from(2),
                PublicKey::from_hex(
                    "022fe5e50a15d721014b538ca6a3ff20ee049b195ba0b1705f64829da8779b6940",
                )
                .unwrap(),
            ),
        ]
        .into_iter()
        .collect();

        let amounts_and_pubkeys: HashSet<(Amount, PublicKey)> = keyset
            .keys
            .iter()
            .map(|(amount, pair)| (*amount, pair.public_key))
            .collect();

        assert_eq!(amounts_and_pubkeys, expected_amounts_and_pubkeys);
    }

    #[test]
    fn mint_make_btc_remote_signer_keyset() {
        let seed = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
        let network = Network::Bitcoin;
        let xpriv = Xpriv::new_master(network, &seed).expect("Failed to create xpriv");
        let keyset = MintKeySet::generate_from_xpriv(
            &Secp256k1::new(),
            xpriv,
            &[
                1,
                2,
                4,
                8,
                16,
                32,
                64,
                128,
                256,
                512,
                1024,
                2048,
                4096,
                8192,
                16384,
                32768,
                65536,
                131072,
                262144,
                524288,
                1_048_576,
                2_097_152,
                4_194_304,
                8_388_608,
                16_777_216,
                33_554_432,
                67_108_864,
                134_217_728,
                268_435_456,
                536_870_912,
                1_073_741_824,
                2_147_483_648,
                4_294_967_296,
                8_589_934_592,
                17_179_869_184,
                34_359_738_368,
                68_719_476_736,
                137_438_953_472,
                274_877_906_944,
                549_755_813_888,
                1_099_511_627_776,
                2_199_023_255_552,
                4_398_046_511_104,
                8_796_093_022_208,
                17_592_186_044_416,
                35_184_372_088_832,
                70_368_744_177_664,
                140_737_488_355_328,
                281_474_976_710_656,
                562_949_953_421_312,
                1_125_899_906_842_624,
                2_251_799_813_685_248,
                4_503_599_627_370_496,
                9_007_199_254_740_992,
                18_014_398_509_481_984,
                36_028_797_018_963_968,
                72_057_594_037_927_936,
                144_115_188_075_855_872,
                288_230_376_151_711_744,
                576_460_752_303_423_488,
                1_152_921_504_606_846_976,
                2_305_843_009_213_693_952,
                4_611_686_018_427_387_904,
                9_223_372_036_854_775_808,
            ],
            CurrencyUnit::Sat,
            derivation_path_from_unit(CurrencyUnit::Sat, 1).unwrap(),
            0,
            None,
            cdk_common::nut02::KeySetVersion::Version00,
        );

        assert_eq!(keyset.unit, CurrencyUnit::Sat);
        assert_eq!(keyset.keys.len(), 64);

        let expected_results: HashMap<u64, &str> = [
            (
                1,
                "0233501d047ff4058007722d5d24e10a8ff5c723a677be411fff46a3cee9a92cc0",
            ),
            (
                2,
                "03a09803ce40118b8917fafa08409dbe6e8bb36d76c55f4c58400cd720abaf54cb",
            ),
            (
                4,
                "02dac058df2e8611098286ef87ee9698f555548784ab4b1a860c79338073ad8c49",
            ),
            (
                8,
                "025b66b937d65544981817aa9a053a762a7d72a7543c66a54370ea68aa53170a10",
            ),
            (
                16,
                "027cf2ad5fa02b99ea37b305048562828453d89dfa7defcda1c10f6746f25f7541",
            ),
            (
                32,
                "0336033cbbc044737bced1fd40b7f0cb0ce08a83aedaa882ed1ced875a1f517879",
            ),
            (
                64,
                "035be95ecaadbfe67b14f07205d13bbcab5da58bb595c57dfb9b61c5e3e7e4de0e",
            ),
            (
                128,
                "0232c757957a8f5a14e93a9bbe8852c273b985ad238ce9b4d5a16885d8a761462b",
            ),
            (
                256,
                "02cbd889df7d38e95dca2ee0e09bc22e3ae57e95975043854a5560a464f970ac1f",
            ),
            (
                512,
                "02c99a0b72ba8f01c5da765c534e75ae3e5f51e4931bfced18a91df4b9233b168f",
            ),
            (
                1024,
                "0320527abb6ae3dd6db9da5041ca941be679e953b446614843af7a4393e9ac96bc",
            ),
            (
                2048,
                "033f9276b0c5f73fbeb0130eab5705a8e878f4191fe251a18cbd918cda3c9e2d5e",
            ),
            (
                4096,
                "03cf69ed2939be4ac35308560d4423e1a0d96cacf9fe33267c7e6a047bf438e53e",
            ),
            (
                8192,
                "027c8bfff71352766c3870e9f5f577830bbb44eadfb757fdff9a8cd209c4b22d76",
            ),
            (
                16384,
                "02ea21bd310828b9e46746eba2ae985626b3a2efc2468db66ae480715dc6deec8a",
            ),
            (
                32768,
                "027ae7179192282d5b44ac55bff82c13e1ea916ae1edefa33ea64100be7408e015",
            ),
            (
                65536,
                "028f333c1beada3445cb62108e35d72199925a055c1e7c102c742e1761770f6c62",
            ),
            (
                131072,
                "03de95cae3614499a3df2d412e91aa09ddef8b8d49e8d652e3798419da86958139",
            ),
            (
                262144,
                "03c7817c19b4b107eb2ccf2f32b60f9c22a59a1d4a93e492ad01f1505097a654b7",
            ),
            (
                524288,
                "028aad03886b6ec6b9f628090e9c151a73f025aa949a9686dac1f0b32995a4e8df",
            ),
            (
                1048576,
                "034bf50a5916d9f112b8fbfe82a5ac914b5bec792b107cf25922c9866f002473e8",
            ),
            (
                2097152,
                "03d2894e1b1b7ab7497ff69e16d280b630f60ba34fe00edd7c748ae5ee73bc0d1a",
            ),
            (
                4194304,
                "0285ba0ee2960927de958610b13d63fc29019407eb32c477d9a2d016fda3062a37",
            ),
            (
                8388608,
                "03d7a4b4b1b8d6b9f2b5966e380a62f8efd53f79d1965e076a716d2fb75e9774a1",
            ),
            (
                16777216,
                "037a033e2f1df992523df83bcb9aa02cefdadd59882d7949f4500f5493d89fa2fd",
            ),
            (
                33554432,
                "03014de7af4809599cabc6d6b30e5121b4a88153eb38a7b66dd8e50e3166215ab0",
            ),
            (
                67108864,
                "0240162a1d2eb1841450de53a6244a625922b14006153d5219dad0fcf0c369c497",
            ),
            (
                134217728,
                "03f8c6f7b0ee71f66940a33c746c3bf8b1cba793a498dd2fdeb6857552415a4d5d",
            ),
            (
                268435456,
                "02dc9de15fa1332f5a2c8f85045ea127cbc3407fb8a844b453f38e1c9cdce9ef87",
            ),
            (
                536870912,
                "0291bdcb1719b5bf447b2885efc84061d1de30b9d1f583d25034059457a2fd739e",
            ),
            (
                1073741824,
                "02f8a96485e3fa791f57d7f4ef279dd3617b873efbdf673815c49dbf9ce7422b0d",
            ),
            (
                2147483648,
                "02ff8cf3e3de985bb2f286c98e335a175b2b53a0e0d7fa1f53d642c95a372329a2",
            ),
            (
                4294967296,
                "02d96196cc54e7506bfe9fdb4a0d691eed2948ecb9b8e81d28d27225287ad5debc",
            ),
            (
                8589934592,
                "03e64e5664f7ab843f41aaf4c0534d698b3318d140c23cbd2fcc33eece53400dac",
            ),
            (
                17179869184,
                "034c9a4bf7b4cb8fac6ace994624e5250ddac5ac84541b6c8bd12b71d22719bb2d",
            ),
            (
                34359738368,
                "0313027c2b106c7dcdee0d806c3343026260276c6793d4d1dfdf79aae30875be31",
            ),
            (
                68719476736,
                "03081adca96d42cb2ac4ac94e0ea2aac4d9412265ae55ed377e3c0357aa1157253",
            ),
            (
                137438953472,
                "02fdc4118761739425220ba87dee5ea9fdc1d581abfcb506fb5afabf76e172b798",
            ),
            (
                274877906944,
                "031dd7cd25f761c8f80828b487bab1cef730f68e8d6f2026b443cc7223862f6c73",
            ),
            (
                549755813888,
                "02da505eab15744a6fd3fa6b3257bced520d4d294ea94444528fd30d7f90948629",
            ),
            (
                1099511627776,
                "02bfc54369099958275376ab030f2a085532c8a00ae4d1bbfa5031c64b42d58a47",
            ),
            (
                2199023255552,
                "032241a5d4d1e988b8ae85f68a381df0e40065ae8c81b1c4f7ea31c87eab2c0d81",
            ),
            (
                4398046511104,
                "03a681e41990d350cdedd30840f26ad970b4015dd6e6b5c03f7cc99b384bee8762",
            ),
            (
                8796093022208,
                "033d5293a33cda29d65058d6d3a4b821472574e92414fa052c79f8bdc1cd72faba",
            ),
            (
                17592186044416,
                "033ddfec40622aaf62d672f43fd05ddb396afd7ad9f00daede45102c890d3a012b",
            ),
            (
                35184372088832,
                "02564bbdcbed18a8e2d79b2fdad6e5e8a9fe92e853ab23170934d84015cc4b96b0",
            ),
            (
                70368744177664,
                "02170950642b94d0ed232370d5dd3630b5eb7e73791447fb961b12d8139de975de",
            ),
            (
                140737488355328,
                "02b2add5a6eb5dc06f706e9dba190ba412c2c7ba240284b336b66ef38a39e51f1c",
            ),
            (
                281474976710656,
                "03e3e584a4bc1d0a6399f5b6b9355bd67a10ad9f46c8a4283de96854e47eb4357c",
            ),
            (
                562949953421312,
                "033821262e6a78f29dad81d3133845883a7632a47f51ab1d99a0eae4a5354eef45",
            ),
            (
                1125899906842624,
                "038db672a61c70dc66b504152ea39b607527f2f59e8ebfdf8d955c38e914661534",
            ),
            (
                2251799813685248,
                "03dafb9683eac036a422266ddc85b675bf13aeafe0658cad2ec1555c28f4049b28",
            ),
            (
                4503599627370496,
                "0351733345d4bb491e27bdb221e382d00f2248f2ee7f04dc6f3faab2692fbd296c",
            ),
            (
                9007199254740992,
                "03f930c1e6c154ca169370adbec7691fd9c11245867a37ae086f7547f5c9e8386f",
            ),
            (
                18014398509481984,
                "02d700dc30d3cd6be292bddbd5f74c09df784862c785cd763ad6c829be59c21bed",
            ),
            (
                36028797018963968,
                "03444b9c312900fffbd478e390aa6fdf9d3ffe230239141ecadf0bcee25e379512",
            ),
            (
                72057594037927936,
                "03af7acedfcfcaf83cfdb7d171ef64723286bd6e0ab90f3629e627e77955917776",
            ),
            (
                144115188075855872,
                "02e35aef647a881e8c318879fb81b6261df73e385dfbc5ff3fc0ab40f13f5ed560",
            ),
            (
                288230376151711744,
                "024558ed8e986901e05839c34d17c261c8d93b8cabb5dee83ab805bb5028e5e463",
            ),
            (
                576460752303423488,
                "024f60a89ba055e009d84a90a13a7860a909fb486a8ffb4315c2f59aff6fbfd929",
            ),
            (
                1152921504606846976,
                "0311b2a5b91dfaebab4fb125338fd38dab72ec5671e6db5f468cb1477970ea3876",
            ),
            (
                2305843009213693952,
                "02aeaa116d930767b5143cac922511c0e093beee5a2850f67490f5a5bb44a8af76",
            ),
            (
                4611686018427387904,
                "02bf7003847bc8e7ad35ea5c8975e3fdde8d1c43ef540d250cf2dc75792c733647",
            ),
            (
                9223372036854775808,
                "0376b06a13092fbb679f6e7a90ce877c37d5a20714a65567177a91a0479b3e86a9",
            ),
        ]
        .into_iter()
        .collect();

        assert_eq!(keyset.id.to_string(), "00b5a0580f75cc2f".to_string());

        for key in expected_results {
            let amount = Amount::from(key.0);
            let pubkey = keyset
                .keys
                .get(&amount)
                .unwrap()
                .public_key
                .clone()
                .to_hex();

            assert_eq!(pubkey, key.1.to_string());
        }
    }

    #[test]
    fn mint_make_auth_remote_signer_keyset() {
        let seed = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
        let network = Network::Bitcoin;
        let xpriv = Xpriv::new_master(network, &seed).expect("Failed to create xpriv");
        let keyset = MintKeySet::generate_from_xpriv(
            &Secp256k1::new(),
            xpriv,
            &[1],
            CurrencyUnit::Auth,
            derivation_path_from_unit(CurrencyUnit::Auth, 1).unwrap(),
            0,
            None,
            cdk_common::nut02::KeySetVersion::Version00,
        );

        assert_eq!(keyset.unit, CurrencyUnit::Auth);
        assert_eq!(keyset.keys.len(), 1);

        assert_eq!(keyset.id.to_string(), "00e1cf6079abb988".to_string());

        let amount = Amount::from(1);
        let pubkey = keyset
            .keys
            .get(&amount)
            .unwrap()
            .public_key
            .clone()
            .to_hex();
        assert_eq!(
            pubkey,
            "025b6c1ca8bb741a6f2321c953266df7bf3f3f2c3be8c54c0a6e41bb00976046a4".to_string()
        );
    }
}
