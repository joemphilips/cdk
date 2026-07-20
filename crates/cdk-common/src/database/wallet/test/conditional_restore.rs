//! Generic atomic conditional-restore database tests.

use std::collections::BTreeMap;
use std::sync::Arc;

use cashu::nuts::nut_ctf::{compute_outcome_collection_id, ConditionalKeySetInfo};
use cashu::secret::Secret;
use cashu::{Amount, CurrencyUnit, Id, KeySet, KeySetInfo, Keys, Proof, SecretKey, State};

use super::{test_keyset_id, test_mint_url, test_proof_info, Database};
use crate::database::wallet::{
    ConditionalRestoreAdmission, ConditionalRestoreAdmissionMode, ConditionalRestoreAdmissionResult,
};
use crate::database::Error;
use crate::wallet::ProofInfo;

fn admission(observed_wall_time: u64, final_expiry: u64) -> ConditionalRestoreAdmission {
    admission_for_outcome(observed_wall_time, Some(final_expiry), "YES", 9)
}

/// Build a valid admission for backend-specific contention and corruption tests.
pub fn conditional_restore_test_admission(
    observed_wall_time: u64,
    final_expiry: u64,
) -> ConditionalRestoreAdmission {
    admission(observed_wall_time, final_expiry)
}

fn admission_for_outcome(
    observed_wall_time: u64,
    final_expiry: Option<u64>,
    outcome_collection: &str,
    proof_byte: u8,
) -> ConditionalRestoreAdmission {
    let mut key_map = BTreeMap::new();
    for (amount, byte) in [(1, 1), (2, 2), (4, 4), (8, 8)] {
        let secret = SecretKey::from_slice(&[byte; 32]).expect("test secret key should parse");
        key_map.insert(Amount::from(amount), secret.public_key());
    }
    let keys = Keys::new(key_map);
    let condition_id = "11".repeat(32);
    let condition_id_bytes = <[u8; 32]>::try_from(
        cashu::util::hex::decode(&condition_id).expect("condition id should decode"),
    )
    .expect("condition id should be 32 bytes");
    let outcome_collection_id = cashu::util::hex::encode(
        compute_outcome_collection_id(&[0_u8; 32], &condition_id_bytes, outcome_collection)
            .expect("outcome collection id should derive"),
    );
    let id = Id::v2_from_data_conditional(
        &keys,
        &CurrencyUnit::Sat,
        1,
        final_expiry,
        &condition_id,
        &outcome_collection_id,
    );
    let mint_url = test_mint_url();
    let proof = Proof::new(
        Amount::from(1),
        id,
        Secret::new(format!(
            "conditional restore generic test proof {proof_byte}"
        )),
        SecretKey::from_slice(&[proof_byte; 32])
            .expect("test proof key should parse")
            .public_key(),
    );
    let proof = ProofInfo::new(proof, mint_url.clone(), State::Unspent, CurrencyUnit::Sat)
        .expect("test proof info should derive");

    ConditionalRestoreAdmission {
        mint_url,
        unit: CurrencyUnit::Sat,
        observed_wall_time,
        mode: ConditionalRestoreAdmissionMode::HeldProofs,
        conditional_keyset: ConditionalKeySetInfo {
            id,
            unit: CurrencyUnit::Sat.to_string(),
            active: true,
            input_fee_ppk: Some(1),
            final_expiry,
            condition_id,
            outcome_collection: outcome_collection.to_string(),
            outcome_collection_id,
            registered_at: 10,
        },
        keyset: KeySetInfo {
            id,
            unit: CurrencyUnit::Sat,
            active: false,
            input_fee_ppk: 1,
            final_expiry,
        },
        keys: KeySet {
            id,
            unit: CurrencyUnit::Sat,
            active: Some(true),
            keys,
            input_fee_ppk: 1,
            final_expiry,
        },
        proofs: vec![proof],
        spent_proofs: vec![],
        counter_floor: 7,
    }
}

fn non_expiring_admission(observed_wall_time: u64) -> ConditionalRestoreAdmission {
    let mut admission = admission_for_outcome(observed_wall_time, None, "YES", 9);
    admission.conditional_keyset.input_fee_ppk = None;
    admission.conditional_keyset.final_expiry = None;
    admission.keyset.input_fee_ppk = 0;
    admission.keyset.final_expiry = None;
    admission.keys.input_fee_ppk = 0;
    admission.keys.final_expiry = None;
    let id = Id::v2_from_data_conditional(
        &admission.keys.keys,
        &admission.unit,
        0,
        None,
        &admission.conditional_keyset.condition_id,
        &admission.conditional_keyset.outcome_collection_id,
    );
    admission.conditional_keyset.id = id;
    admission.keyset.id = id;
    admission.keys.id = id;
    admission.proofs[0].proof.keyset_id = id;
    admission
}

fn progress_only(mut admission: ConditionalRestoreAdmission) -> ConditionalRestoreAdmission {
    admission.mode = ConditionalRestoreAdmissionMode::ProgressOnly;
    admission.proofs.clear();
    admission
}

/// Progress-only recovery must validate an existing namespace before advancing progress.
pub async fn conditional_restore_progress_only_rejects_namespace_conflicts<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let admission = admission(100, 300);
    db.add_mint(admission.mint_url.clone(), None).await.unwrap();
    db.advance_conditional_restore_high_water(
        admission.mint_url.clone(),
        admission.unit.clone(),
        10,
    )
    .await
    .unwrap();
    db.add_mint_keysets(admission.mint_url.clone(), vec![admission.keyset.clone()])
        .await
        .unwrap();
    assert!(matches!(
        db.commit_conditional_restore(progress_only(admission.clone()))
            .await,
        Err(Error::ConditionalRestoreMetadataConflict)
    ));
    assert_eq!(
        db.advance_conditional_restore_high_water(
            admission.mint_url.clone(),
            admission.unit.clone(),
            0
        )
        .await
        .unwrap(),
        10
    );
    assert_eq!(
        db.increment_keyset_counter(&admission.keyset.id, 0)
            .await
            .unwrap(),
        0
    );

    let held = admission_for_outcome(100, Some(300), "HELD", 71);
    db.commit_conditional_restore(held.clone()).await.unwrap();
    let mut conflicting = progress_only(held.clone());
    conflicting.observed_wall_time = 150;
    conflicting.counter_floor = 50;
    conflicting.conditional_keyset.registered_at += 1;
    assert!(matches!(
        db.commit_conditional_restore(conflicting).await,
        Err(Error::ConditionalRestoreMetadataConflict)
    ));
    assert_eq!(
        db.increment_keyset_counter(&held.keyset.id, 0)
            .await
            .unwrap(),
        held.counter_floor
    );
}

/// Spent evidence advances only an exact existing proof and never hydrates a fresh row.
pub async fn conditional_restore_spent_evidence_is_exact_and_non_hydrating<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let held = admission_for_outcome(100, Some(400), "SPENT-EXISTING", 72);
    db.add_mint(held.mint_url.clone(), None).await.unwrap();
    db.commit_conditional_restore(held.clone()).await.unwrap();

    let mut spent = progress_only(held.clone());
    spent.observed_wall_time = 110;
    let mut evidence = held.proofs[0].clone();
    evidence.state = State::Spent;
    spent.spent_proofs.push(evidence);
    db.commit_conditional_restore(spent).await.unwrap();
    let stored = db.get_proofs_by_ys(vec![held.proofs[0].y]).await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].state, State::Spent);

    let fresh = admission_for_outcome(120, Some(400), "SPENT-FRESH", 73);
    let mut fresh_progress = progress_only(fresh.clone());
    let mut fresh_evidence = fresh.proofs[0].clone();
    fresh_evidence.state = State::Spent;
    fresh_progress.spent_proofs.push(fresh_evidence);
    db.commit_conditional_restore(fresh_progress).await.unwrap();
    assert!(db
        .get_keyset_by_id(&fresh.keyset.id)
        .await
        .unwrap()
        .is_none());
    assert!(db.get_keys(&fresh.keyset.id).await.unwrap().is_none());
    assert!(db
        .get_proofs_by_ys(vec![fresh.proofs[0].y])
        .await
        .unwrap()
        .is_empty());
}

/// Active and spent views may not claim the same proof identity in one batch.
pub async fn conditional_restore_rejects_duplicate_spent_evidence<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let mut invalid = admission(100, 300);
    db.add_mint(invalid.mint_url.clone(), None).await.unwrap();
    db.advance_conditional_restore_high_water(invalid.mint_url.clone(), invalid.unit.clone(), 10)
        .await
        .unwrap();
    let mut spent = invalid.proofs[0].clone();
    spent.state = State::Spent;
    invalid.spent_proofs.push(spent);
    assert!(matches!(
        db.commit_conditional_restore(invalid.clone()).await,
        Err(Error::InvalidConditionalRestore(_))
    ));
    assert_eq!(
        db.advance_conditional_restore_high_water(invalid.mint_url, invalid.unit, 0)
            .await
            .unwrap(),
        10
    );
}

/// Concurrent advances preserve the maximum full-width unsigned timestamp.
pub async fn conditional_restore_high_water_is_monotonic<DB>(db: DB)
where
    DB: Database<Error> + Send + Sync + 'static,
{
    let db = Arc::new(db);
    let mint_url = test_mint_url();
    let values = [9_u64, 3, u64::MAX - 1, 42, u64::MAX - 2];
    let mut tasks = Vec::new();
    for observed in values {
        let db = Arc::clone(&db);
        let mint_url = mint_url.clone();
        tasks.push(tokio::spawn(async move {
            db.advance_conditional_restore_high_water(mint_url, CurrencyUnit::Sat, observed)
                .await
        }));
    }
    for task in tasks {
        task.await
            .expect("high-water task should join")
            .expect("high-water advance should succeed");
    }
    let effective = db
        .advance_conditional_restore_high_water(mint_url, CurrencyUnit::Sat, 1)
        .await
        .expect("rollback observation should be fenced");
    assert_eq!(effective, u64::MAX - 1);
}

/// A valid admission persists every owned object and the absolute counter floor.
pub async fn conditional_restore_commit_is_atomic<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let admission = admission(100, 200);
    db.add_mint(admission.mint_url.clone(), None)
        .await
        .expect("mint should persist");
    let result = db
        .commit_conditional_restore(admission.clone())
        .await
        .expect("conditional restore should commit");
    assert_eq!(
        result,
        ConditionalRestoreAdmissionResult::HeldProofs {
            effective_time: 100
        }
    );
    assert_eq!(
        db.get_keyset_by_id(&admission.keyset.id)
            .await
            .expect("keyset should load"),
        Some(admission.keyset.clone())
    );
    assert_eq!(
        db.get_keys(&admission.keyset.id)
            .await
            .expect("keys should load"),
        Some(admission.keys.keys.clone())
    );
    assert_eq!(
        db.increment_keyset_counter(&admission.keyset.id, 0)
            .await
            .expect("counter should load"),
        admission.counter_floor
    );
}

/// Missing expiry is non-expiring and a missing fee is canonical zero.
pub async fn conditional_restore_accepts_non_expiring_optional_fee_metadata<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let admission = non_expiring_admission(u64::MAX - 1);
    db.add_mint(admission.mint_url.clone(), None)
        .await
        .expect("mint should persist");
    assert_eq!(
        db.commit_conditional_restore(admission.clone())
            .await
            .expect("non-expiring admission should commit"),
        ConditionalRestoreAdmissionResult::HeldProofs {
            effective_time: u64::MAX - 1
        }
    );
    assert_eq!(
        db.get_keyset_by_id(&admission.keyset.id)
            .await
            .expect("keyset should load"),
        Some(admission.keyset)
    );
}

/// Expiry commits only the monotonic time fence.
pub async fn conditional_restore_expiry_only_advances_high_water<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let admission = admission(200, 200);
    db.add_mint(admission.mint_url.clone(), None)
        .await
        .expect("mint should persist");
    let result = db
        .commit_conditional_restore(admission.clone())
        .await
        .expect("expired admission should return a typed outcome");
    assert_eq!(
        result,
        ConditionalRestoreAdmissionResult::Expired {
            effective_time: 200
        }
    );
    assert!(db
        .get_keyset_by_id(&admission.keyset.id)
        .await
        .expect("keyset lookup should succeed")
        .is_none());
    assert!(db
        .get_keys(&admission.keyset.id)
        .await
        .expect("keys lookup should succeed")
        .is_none());
    assert!(db
        .get_proofs(None, None, None, None)
        .await
        .expect("proof listing should succeed")
        .is_empty());
    assert_eq!(
        db.advance_conditional_restore_high_water(admission.mint_url, CurrencyUnit::Sat, 0,)
            .await
            .expect("high-water should remain persisted"),
        200
    );
}

/// An all-spent scan advances only the counter and time fence without hydrating custody.
pub async fn conditional_restore_progress_only_advances_counter_without_hydration<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let admission = progress_only(admission(100, 300));
    db.add_mint(admission.mint_url.clone(), None)
        .await
        .expect("mint should persist");
    assert_eq!(
        db.commit_conditional_restore(admission.clone())
            .await
            .expect("progress-only admission should commit"),
        ConditionalRestoreAdmissionResult::ProgressOnly {
            effective_time: 100
        }
    );
    assert!(db
        .get_keyset_by_id(&admission.keyset.id)
        .await
        .expect("keyset lookup should succeed")
        .is_none());
    assert!(db
        .get_keys(&admission.keyset.id)
        .await
        .expect("keys lookup should succeed")
        .is_none());
    assert!(db
        .get_proofs(None, None, None, None)
        .await
        .expect("proof listing should succeed")
        .is_empty());
    assert_eq!(
        db.increment_keyset_counter(&admission.keyset.id, 0)
            .await
            .expect("counter floor should load"),
        admission.counter_floor
    );
    db.add_mint_keysets(admission.mint_url, vec![admission.keyset])
        .await
        .expect("progress-only recovery must not claim the conditional namespace");
}

/// Concurrent progress-only retries preserve both monotonic maxima.
pub async fn conditional_restore_progress_only_retries_preserve_maxima<DB>(db: DB)
where
    DB: Database<Error> + Send + Sync + 'static,
{
    let db = Arc::new(db);
    let base = progress_only(admission(100, 400));
    db.add_mint(base.mint_url.clone(), None)
        .await
        .expect("mint should persist");
    let mut tasks = Vec::new();
    for (observed_wall_time, counter_floor) in [
        (102_u64, 12_u32),
        (101, 30),
        (u64::MAX - 1, u32::MAX),
        (99, 20),
    ] {
        let db = Arc::clone(&db);
        let mut admission = base.clone();
        admission.observed_wall_time = observed_wall_time;
        admission.counter_floor = counter_floor;
        admission.conditional_keyset.final_expiry = None;
        admission.keyset.final_expiry = None;
        admission.keys.final_expiry = None;
        let id = Id::v2_from_data_conditional(
            &admission.keys.keys,
            &admission.unit,
            admission.keyset.input_fee_ppk,
            None,
            &admission.conditional_keyset.condition_id,
            &admission.conditional_keyset.outcome_collection_id,
        );
        admission.conditional_keyset.id = id;
        admission.keyset.id = id;
        admission.keys.id = id;
        tasks.push(tokio::spawn(async move {
            db.commit_conditional_restore(admission).await
        }));
    }
    for task in tasks {
        task.await
            .expect("progress-only task should join")
            .expect("progress-only retry should commit");
    }
    let mut final_admission = base;
    final_admission.conditional_keyset.final_expiry = None;
    final_admission.keyset.final_expiry = None;
    final_admission.keys.final_expiry = None;
    let id = Id::v2_from_data_conditional(
        &final_admission.keys.keys,
        &final_admission.unit,
        final_admission.keyset.input_fee_ppk,
        None,
        &final_admission.conditional_keyset.condition_id,
        &final_admission.conditional_keyset.outcome_collection_id,
    );
    assert_eq!(
        db.advance_conditional_restore_high_water(
            final_admission.mint_url,
            final_admission.unit,
            0,
        )
        .await
        .expect("high-water maximum should load"),
        u64::MAX - 1
    );
    assert_eq!(
        db.increment_keyset_counter(&id, 0)
            .await
            .expect("counter maximum should load"),
        u32::MAX
    );
    assert!(db
        .get_keyset_by_id(&id)
        .await
        .expect("keyset lookup should succeed")
        .is_none());
}

/// Expired progress-only recovery commits the fence but not the counter or custody rows.
pub async fn conditional_restore_expired_progress_only_does_not_advance_counter<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let admission = progress_only(admission(300, 300));
    db.add_mint(admission.mint_url.clone(), None)
        .await
        .expect("mint should persist");
    db.increment_keyset_counter(&admission.keyset.id, 3)
        .await
        .expect("counter fixture should persist");
    assert_eq!(
        db.commit_conditional_restore(admission.clone())
            .await
            .expect("expired progress should return a typed outcome"),
        ConditionalRestoreAdmissionResult::Expired {
            effective_time: 300
        }
    );
    assert_eq!(
        db.increment_keyset_counter(&admission.keyset.id, 0)
            .await
            .expect("counter should remain unchanged"),
        3
    );
    assert!(db
        .get_keyset_by_id(&admission.keyset.id)
        .await
        .expect("keyset lookup should succeed")
        .is_none());
}

/// Conflicting immutable catalogue metadata rolls back the full transaction.
pub async fn conditional_restore_rejects_immutable_metadata_conflict<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let admission = admission(100, 200);
    db.add_mint(admission.mint_url.clone(), None)
        .await
        .expect("mint should persist");
    db.commit_conditional_restore(admission.clone())
        .await
        .expect("first admission should commit");
    let mut conflicting = admission.clone();
    conflicting.observed_wall_time = 150;
    conflicting.conditional_keyset.registered_at += 1;
    assert!(matches!(
        db.commit_conditional_restore(conflicting).await,
        Err(Error::ConditionalRestoreMetadataConflict)
    ));
    assert_eq!(
        db.advance_conditional_restore_high_water(admission.mint_url, CurrencyUnit::Sat, 0,)
            .await
            .expect("failed transaction must not advance high-water"),
        100
    );
}

/// A proof-identity collision detected after tentative metadata writes rolls everything back.
pub async fn conditional_restore_late_proof_conflict_rolls_back<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let first = admission_for_outcome(100, Some(300), "FIRST", 21);
    db.add_mint(first.mint_url.clone(), None)
        .await
        .expect("mint should persist");
    db.commit_conditional_restore(first.clone())
        .await
        .expect("first admission should commit");
    let second = admission_for_outcome(150, Some(300), "SECOND", 21);
    assert_eq!(first.proofs[0].y, second.proofs[0].y);
    assert!(matches!(
        db.commit_conditional_restore(second.clone()).await,
        Err(Error::ConditionalRestoreMetadataConflict)
    ));
    assert_eq!(
        db.advance_conditional_restore_high_water(second.mint_url.clone(), second.unit.clone(), 0,)
            .await
            .expect("failed late conflict must not advance high-water"),
        100
    );
    db.add_mint_keysets(second.mint_url, vec![second.keyset.clone()])
        .await
        .expect("rolled-back classification must not claim the keyset id");
    assert_eq!(
        db.increment_keyset_counter(&second.keyset.id, 0)
            .await
            .expect("rolled-back counter should load"),
        0
    );
}

/// Invalid state, identity, or duplicate Y fails before advancing the durable fence.
pub async fn conditional_restore_rejects_invalid_proof_admission<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let base = admission(100, 300);
    db.add_mint(base.mint_url.clone(), None)
        .await
        .expect("mint should persist");
    db.advance_conditional_restore_high_water(base.mint_url.clone(), base.unit.clone(), 10)
        .await
        .expect("initial fence should persist");

    let mut invalid_state = base.clone();
    invalid_state.proofs[0].state = State::Spent;
    assert!(matches!(
        db.commit_conditional_restore(invalid_state).await,
        Err(Error::InvalidConditionalRestore(_))
    ));

    let mut invalid_y = base.clone();
    invalid_y.proofs[0].y = SecretKey::from_slice(&[31; 32])
        .expect("test key should parse")
        .public_key();
    assert!(matches!(
        db.commit_conditional_restore(invalid_y).await,
        Err(Error::InvalidConditionalRestore(_))
    ));

    let mut duplicate_y = base.clone();
    duplicate_y.proofs.push(duplicate_y.proofs[0].clone());
    assert!(matches!(
        db.commit_conditional_restore(duplicate_y).await,
        Err(Error::InvalidConditionalRestore(_))
    ));
    assert_eq!(
        db.advance_conditional_restore_high_water(base.mint_url, base.unit, 0)
            .await
            .expect("invalid admissions must not advance high-water"),
        10
    );
}

/// Conditional metadata must bind the root outcome label and supported keyset version.
pub async fn conditional_restore_rejects_mutated_semantic_binding<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let base = admission(100, 300);
    db.add_mint(base.mint_url.clone(), None)
        .await
        .expect("mint should persist");
    db.advance_conditional_restore_high_water(base.mint_url.clone(), base.unit.clone(), 10)
        .await
        .expect("initial fence should persist");

    let mut mutated_label = base.clone();
    mutated_label.conditional_keyset.outcome_collection = "NO".to_string();
    assert!(matches!(
        db.commit_conditional_restore(mutated_label).await,
        Err(Error::InvalidConditionalRestore(_))
    ));

    let mut mutated_id = base.clone();
    mutated_id.conditional_keyset.outcome_collection_id = "00".repeat(32);
    assert!(matches!(
        db.commit_conditional_restore(mutated_id).await,
        Err(Error::InvalidConditionalRestore(_))
    ));

    let mut unsupported_version = base.clone();
    let v1 = Id::v1_from_keys(&unsupported_version.keys.keys);
    unsupported_version.conditional_keyset.id = v1;
    unsupported_version.keyset.id = v1;
    unsupported_version.keys.id = v1;
    unsupported_version.proofs[0].proof.keyset_id = v1;
    assert!(matches!(
        db.commit_conditional_restore(unsupported_version).await,
        Err(Error::InvalidConditionalRestore(_))
    ));
    assert_eq!(
        db.advance_conditional_restore_high_water(base.mint_url, base.unit, 0)
            .await
            .expect("semantic binding failures must not advance high-water"),
        10
    );
}

/// An ordinary row with the same keyset ID prevents conditional classification.
pub async fn conditional_restore_rejects_ordinary_id_collision<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let admission = admission(150, 300);
    db.add_mint(admission.mint_url.clone(), None)
        .await
        .expect("mint should persist");
    db.advance_conditional_restore_high_water(
        admission.mint_url.clone(),
        admission.unit.clone(),
        100,
    )
    .await
    .expect("initial fence should persist");
    db.add_mint_keysets(admission.mint_url.clone(), vec![admission.keyset.clone()])
        .await
        .expect("ordinary collision fixture should persist");
    assert!(matches!(
        db.commit_conditional_restore(admission.clone()).await,
        Err(Error::ConditionalRestoreMetadataConflict)
    ));
    assert_eq!(
        db.advance_conditional_restore_high_water(
            admission.mint_url.clone(),
            admission.unit.clone(),
            0,
        )
        .await
        .expect("collision must roll back the fence"),
        100
    );
    assert!(db
        .get_proofs(None, None, None, None)
        .await
        .expect("proof listing should succeed")
        .is_empty());
}

/// A normal NUT-02 refresh cannot mutate a classified conditional keyset.
pub async fn ordinary_keyset_refresh_rejects_conditional_id<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let admission = admission(100, 300);
    db.add_mint(admission.mint_url.clone(), None)
        .await
        .expect("mint should persist");
    db.commit_conditional_restore(admission.clone())
        .await
        .expect("conditional admission should commit");
    let mut refreshed = admission.keyset.clone();
    refreshed.active = true;
    assert!(matches!(
        db.add_mint_keysets(admission.mint_url, vec![refreshed])
            .await,
        Err(Error::ConditionalRestoreMetadataConflict)
    ));
    assert_eq!(
        db.get_keyset_by_id(&admission.keyset.id)
            .await
            .expect("keyset should load"),
        Some(admission.keyset)
    );
}

/// Recovery joins mint evidence monotonically and never downgrades local lifecycle state.
pub async fn conditional_restore_retry_joins_proof_lifecycle<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let mint_url = test_mint_url();
    db.add_mint(mint_url, None)
        .await
        .expect("mint should persist");
    for (index, existing, incoming, expected) in [
        (10_u8, State::Unspent, State::Pending, State::Pending),
        (11, State::Pending, State::Unspent, State::Pending),
        (12, State::Reserved, State::Unspent, State::Reserved),
        (13, State::PendingSpent, State::Pending, State::PendingSpent),
        (14, State::Spent, State::Unspent, State::Spent),
    ] {
        let mut admission =
            admission_for_outcome(100, Some(300), &format!("OUTCOME-{index}"), index);
        admission.proofs[0].state = State::Unspent;
        db.commit_conditional_restore(admission.clone())
            .await
            .expect("initial conditional admission should commit");
        db.update_proofs_state(vec![admission.proofs[0].y], existing)
            .await
            .expect("existing proof lifecycle should persist");
        admission.proofs[0].state = incoming;
        db.commit_conditional_restore(admission.clone())
            .await
            .expect("retry should join lifecycle state");
        let proofs = db
            .get_proofs_by_ys(vec![admission.proofs[0].y])
            .await
            .expect("proof should load");
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].state, expected);
    }
}

/// Counter admission uses max(existing, floor), never addition or rollback.
pub async fn conditional_restore_counter_uses_absolute_floor<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let mut admission = admission(100, 300);
    db.add_mint(admission.mint_url.clone(), None)
        .await
        .expect("mint should persist");
    db.increment_keyset_counter(&admission.keyset.id, 10)
        .await
        .expect("counter should seed");
    admission.counter_floor = 7;
    db.commit_conditional_restore(admission.clone())
        .await
        .expect("lower floor should commit without rollback");
    assert_eq!(
        db.increment_keyset_counter(&admission.keyset.id, 0)
            .await
            .expect("counter should load"),
        10
    );
    admission.counter_floor = 15;
    db.commit_conditional_restore(admission.clone())
        .await
        .expect("higher floor should commit");
    assert_eq!(
        db.increment_keyset_counter(&admission.keyset.id, 0)
            .await
            .expect("counter should load"),
        15
    );
    admission.counter_floor = 12;
    db.commit_conditional_restore(admission.clone())
        .await
        .expect("retry with lower floor should commit");
    assert_eq!(
        db.increment_keyset_counter(&admission.keyset.id, 0)
            .await
            .expect("counter should load"),
        15
    );
    admission.counter_floor = u32::MAX;
    db.commit_conditional_restore(admission.clone())
        .await
        .expect("full-width counter floor should commit");
    assert_eq!(
        db.increment_keyset_counter(&admission.keyset.id, 0)
            .await
            .expect("full-width counter should load"),
        u32::MAX
    );
}

/// Counter overflow fails without changing the persisted full-width floor.
pub async fn conditional_restore_counter_overflow_is_non_mutating<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let mut admission = admission(100, 300);
    admission.counter_floor = u32::MAX;
    db.add_mint(admission.mint_url.clone(), None).await.unwrap();
    db.commit_conditional_restore(admission.clone())
        .await
        .unwrap();
    assert!(db
        .increment_keyset_counter(&admission.keyset.id, 1)
        .await
        .is_err());
    assert_eq!(
        db.increment_keyset_counter(&admission.keyset.id, 0)
            .await
            .unwrap(),
        u32::MAX
    );
}

/// Ordinary key APIs cannot overwrite or delete hydrated conditional keys.
pub async fn ordinary_key_operations_cannot_mutate_conditional_keys<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let admission = admission(100, 300);
    db.add_mint(admission.mint_url.clone(), None).await.unwrap();
    db.commit_conditional_restore(admission.clone())
        .await
        .unwrap();
    assert!(matches!(
        db.add_keys(admission.keys.clone()).await,
        Err(Error::ConditionalRestoreMetadataConflict)
    ));
    let remove = db.remove_keys(&admission.keyset.id).await;
    assert!(
        matches!(remove, Err(Error::ConditionalRestoreMetadataConflict)),
        "conditional key deletion returned {remove:?}"
    );
    assert_eq!(
        db.get_keys(&admission.keyset.id).await.unwrap(),
        Some(admission.keys.keys)
    );
}

/// Mint URL migration carries forward the maximum rollback-resistant fence.
pub async fn conditional_restore_update_mint_url_preserves_fence<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let admission = admission(100, 300);
    let new_mint = super::test_mint_url_2();
    db.add_mint(admission.mint_url.clone(), None)
        .await
        .expect("old mint should persist");
    db.add_mint(new_mint.clone(), None)
        .await
        .expect("new mint should persist");
    db.commit_conditional_restore(admission.clone())
        .await
        .expect("conditional admission should commit");
    db.advance_conditional_restore_high_water(new_mint.clone(), admission.unit.clone(), 150)
        .await
        .expect("new URL fence should seed");
    db.update_mint_url(admission.mint_url.clone(), new_mint.clone())
        .await
        .expect("mint URL should migrate atomically");
    assert_eq!(
        db.advance_conditional_restore_high_water(new_mint.clone(), admission.unit.clone(), 0,)
            .await
            .expect("merged high-water should load"),
        150
    );
    assert_eq!(
        db.advance_conditional_restore_high_water(
            admission.mint_url.clone(),
            admission.unit.clone(),
            0,
        )
        .await
        .expect("old URL starts a new independent fence"),
        0
    );
    let moved = db
        .get_proofs_by_ys(vec![admission.proofs[0].y])
        .await
        .expect("moved proof should load");
    assert_eq!(moved[0].mint_url, new_mint);
    let mut moved_admission = admission.clone();
    moved_admission.mint_url = new_mint.clone();
    moved_admission.proofs[0].mint_url = new_mint.clone();
    db.commit_conditional_restore(moved_admission)
        .await
        .expect("moved classification and keyset ownership should remain idempotent");
    let ordinary = db
        .get_ordinary_proofs(
            new_mint.clone(),
            admission.unit.clone(),
            Some(vec![State::Unspent]),
            None,
        )
        .await
        .expect("ordinary proof selection should remain available");
    assert!(ordinary.is_empty());
    assert!(db
        .get_mint_keysets(new_mint)
        .await
        .expect("new mint keysets should load")
        .is_some_and(|keysets| keysets.contains(&admission.keyset)));
}

/// Updating a mint URL to itself preserves the conditional restore namespace unchanged.
pub async fn conditional_restore_update_mint_url_same_url_is_noop<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let admission = admission(100, 300);
    db.add_mint(admission.mint_url.clone(), None)
        .await
        .expect("mint should persist");
    db.commit_conditional_restore(admission.clone())
        .await
        .expect("conditional admission should commit");
    db.advance_conditional_restore_high_water(
        admission.mint_url.clone(),
        admission.unit.clone(),
        250,
    )
    .await
    .expect("high-water should advance");

    db.update_mint_url(admission.mint_url.clone(), admission.mint_url.clone())
        .await
        .expect("same-URL update should be a no-op");

    assert_eq!(
        db.advance_conditional_restore_high_water(
            admission.mint_url.clone(),
            admission.unit.clone(),
            0,
        )
        .await
        .expect("same-URL update should preserve high-water"),
        250
    );
    assert_eq!(
        db.get_keyset_by_id(&admission.keyset.id)
            .await
            .expect("keyset should load"),
        Some(admission.keyset.clone())
    );
    assert_eq!(
        db.get_keys(&admission.keyset.id)
            .await
            .expect("keys should load"),
        Some(admission.keys.keys.clone())
    );
    assert_eq!(
        db.get_proofs_by_ys(vec![admission.proofs[0].y])
            .await
            .expect("proof should load"),
        admission.proofs
    );
    db.commit_conditional_restore(admission.clone())
        .await
        .expect("conditional classification should remain idempotent");
    assert!(db
        .get_ordinary_proofs(
            admission.mint_url,
            admission.unit,
            Some(vec![State::Unspent]),
            None,
        )
        .await
        .expect("ordinary proof selection should remain available")
        .is_empty());
}

/// Automatic selection excludes conditional proofs while ordinary inspection remains inclusive.
pub async fn ordinary_proofs_exclude_conditional_but_listing_and_balance_include_it<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let admission = admission(100, 200);
    db.add_mint(admission.mint_url.clone(), None)
        .await
        .expect("mint should persist");
    let ordinary = test_proof_info(test_keyset_id(), 2, admission.mint_url.clone());
    db.update_proofs(vec![ordinary.clone()], vec![])
        .await
        .expect("ordinary control proof should persist");
    db.commit_conditional_restore(admission.clone())
        .await
        .expect("conditional admission should commit");
    let listed = db
        .get_proofs(
            Some(admission.mint_url.clone()),
            Some(admission.unit.clone()),
            Some(vec![State::Unspent]),
            None,
        )
        .await
        .expect("inclusive proof listing should succeed");
    assert_eq!(listed.len(), 2);
    assert!(listed.contains(&ordinary));
    assert!(listed.contains(&admission.proofs[0]));
    assert_eq!(
        db.get_balance(
            Some(admission.mint_url.clone()),
            Some(admission.unit.clone()),
            Some(vec![State::Unspent]),
        )
        .await
        .expect("inclusive balance should succeed"),
        3
    );
    let ordinary_only = db
        .get_ordinary_proofs(
            admission.mint_url,
            admission.unit,
            Some(vec![State::Unspent]),
            Some(vec![]),
        )
        .await
        .expect("ordinary proof query should succeed");
    assert_eq!(ordinary_only, vec![ordinary]);
}
