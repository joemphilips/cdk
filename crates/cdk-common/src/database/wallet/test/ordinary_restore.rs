//! Generic atomic ordinary-restore database tests.

use cashu::secret::Secret;
use cashu::{Amount, CurrencyUnit, Id, Proof, SecretKey, State};

use super::{test_keyset_id, test_mint_url, Database};
use crate::database::wallet::OrdinaryRestoreAdmission;
use crate::database::Error;
use crate::wallet::ProofInfo;

fn proof(id: Id, label: &str, state: State) -> ProofInfo {
    let proof = Proof::new(
        Amount::ONE,
        id,
        Secret::new(label.to_string()),
        SecretKey::generate().public_key(),
    );
    ProofInfo::new(proof, test_mint_url(), state, CurrencyUnit::Sat)
        .expect("ordinary restore proof")
}

fn admission(
    id: Id,
    proofs: Vec<ProofInfo>,
    spent_proofs: Vec<ProofInfo>,
    counter_floor: u32,
) -> OrdinaryRestoreAdmission {
    OrdinaryRestoreAdmission {
        mint_url: test_mint_url(),
        unit: CurrencyUnit::Sat,
        keyset_id: id,
        proofs,
        spent_proofs,
        counter_floor,
    }
}

/// Restore retries preserve local lifecycle links; spent evidence is exact and non-hydrating.
pub async fn ordinary_restore_preserves_lifecycle_and_spent_evidence<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let id = test_keyset_id();
    let recovered = proof(id, "ordinary restore held proof", State::Unspent);
    db.commit_ordinary_restore(admission(id, vec![recovered.clone()], vec![], 7))
        .await
        .unwrap();

    let operation_id = uuid::Uuid::new_v4();
    db.reserve_proofs(vec![recovered.y], &operation_id)
        .await
        .unwrap();
    let reserved = db
        .get_proofs_by_ys(vec![recovered.y])
        .await
        .unwrap()
        .pop()
        .expect("reserved proof");

    let mut pending_retry = recovered.clone();
    pending_retry.state = State::Pending;
    db.commit_ordinary_restore(admission(id, vec![pending_retry], vec![], 8))
        .await
        .unwrap();
    let after_retry = db
        .get_proofs_by_ys(vec![recovered.y])
        .await
        .unwrap()
        .pop()
        .expect("retried proof");
    assert_eq!(after_retry, reserved);

    let mut spent = recovered.clone();
    spent.state = State::Spent;
    let missing = proof(id, "ordinary restore missing spent proof", State::Spent);
    db.commit_ordinary_restore(admission(id, vec![], vec![spent, missing.clone()], 9))
        .await
        .unwrap();
    let after_spent = db
        .get_proofs_by_ys(vec![recovered.y, missing.y])
        .await
        .unwrap();
    assert_eq!(after_spent.len(), 1);
    assert_eq!(after_spent[0].state, State::Spent);
    assert_eq!(after_spent[0].used_by_operation, Some(operation_id));
    let mut expected = reserved;
    expected.state = State::Spent;
    assert_eq!(after_spent[0], expected);
    assert_eq!(db.increment_keyset_counter(&id, 0).await.unwrap(), 9);
}

/// A late proof conflict rolls back earlier inserts and the absolute counter floor.
pub async fn ordinary_restore_conflict_rolls_back_proofs_and_counter<DB>(db: DB)
where
    DB: Database<Error> + Sync,
{
    let id = test_keyset_id();
    let existing = proof(id, "ordinary restore existing proof", State::Unspent);
    db.update_proofs(vec![existing.clone()], vec![])
        .await
        .unwrap();

    let fresh = proof(id, "ordinary restore fresh proof", State::Unspent);
    let mut conflicting = existing.clone();
    conflicting.proof.c = SecretKey::generate().public_key();
    assert!(matches!(
        db.commit_ordinary_restore(admission(id, vec![fresh.clone(), conflicting], vec![], 11))
            .await,
        Err(Error::OrdinaryRestoreMetadataConflict)
    ));
    assert!(db.get_proofs_by_ys(vec![fresh.y]).await.unwrap().is_empty());
    assert_eq!(db.increment_keyset_counter(&id, 0).await.unwrap(), 0);
    assert_eq!(
        db.get_proofs_by_ys(vec![existing.y]).await.unwrap(),
        vec![existing]
    );
}
