//! Records of settlement requests that the mint refused after their cutoff.
//!
//! A record makes the refusal definitive while a copy of the request that
//! passed the expiry check before the cutoff can still reach its commit. After
//! the retention time no copy can commit, so maintenance deletes the record
//! and the mint writes no new one. A committed request keeps its record.

use super::*;
use crate::mint::state_limits::{
    StateLimits, MAX_CUTOFF_REJECTION_RECORDS, SETTLEMENT_RECORD_RETENTION_SECS,
};

/// The lifetime of the authorizations of a `standard_settlement_fixture`.
const FIXTURE_LIFETIME_SECS: u64 = 60;

async fn recorded_outcome(
    mint: &Mint,
    fixture: &StandardSettlementFixture,
) -> Option<CtfSettlementReplay> {
    mint.localstore()
        .get_ctf_settlement_replay(fixture.request.request_digest().unwrap())
        .await
        .unwrap()
}

/// The mint gives the definitive expiry refusal and moves no token.
async fn refuse_after_cutoff(mint: &Mint, fixture: &StandardSettlementFixture, at: u64) {
    let completed_before = completed_swap_count(mint).await;
    let result = mint
        .process_ctf_settlement(&fixture.request, settlement_settings(), at)
        .await;
    assert!(
        matches!(result, Err(CtfSettlementError::AuthorizationExpired)),
        "at {at}: {result:?}"
    );
    assert_ctf_settlement_has_no_persistent_mutations(mint, fixture, completed_before).await;
}

/// The mint refuses the request, but writes no record and gives no definitive refusal.
async fn refuse_without_record(mint: &Mint, fixture: &StandardSettlementFixture, at: u64) {
    let completed_before = completed_swap_count(mint).await;
    let result = mint
        .process_ctf_settlement(&fixture.request, settlement_settings(), at)
        .await;
    assert!(
        matches!(
            result,
            Err(CtfSettlementError::AuthorizationExpiredUnrecorded)
        ),
        "at {at}: {result:?}"
    );
    assert_eq!(recorded_outcome(mint, fixture).await, None);
    assert_ctf_settlement_has_no_persistent_mutations(mint, fixture, completed_before).await;
}

/// Store the rejection of another request.
async fn store_foreign_rejection(mint: &Mint, digest: u8, cutoff: u64) {
    let mut tx = mint.localstore().begin_transaction().await.unwrap();
    tx.add_ctf_settlement_rejection(CanonicalHash::from_bytes([digest; 32]), cutoff)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// Maintenance deletes a rejection after its retention, and never a commit.
async fn assert_rejection_retention(mint: &Mint) {
    let now = unix_time();
    let cutoff = now + FIXTURE_LIFETIME_SECS;
    let committed = standard_settlement_fixture_for_event(mint, now, None, "committed").await;
    let response = mint
        .process_ctf_settlement(&committed.request, settlement_settings(), now)
        .await
        .expect("pre-cutoff settlement should commit");
    let rejected = standard_settlement_fixture_for_event(mint, now, None, "rejected").await;
    refuse_after_cutoff(mint, &rejected, cutoff).await;

    let deleted_at = cutoff + SETTLEMENT_RECORD_RETENTION_SECS;
    mint.run_maintenance(deleted_at - 1).await;
    assert_eq!(
        recorded_outcome(mint, &rejected).await,
        Some(CtfSettlementReplay::RejectedAfterCutoff { cutoff })
    );
    refuse_after_cutoff(mint, &rejected, deleted_at - 1).await;

    mint.run_maintenance(deleted_at).await;
    assert_eq!(recorded_outcome(mint, &rejected).await, None);
    // A later copy gets the same refusal, and does not add the record again.
    for at in [deleted_at, deleted_at + 1, 2 * deleted_at] {
        refuse_after_cutoff(mint, &rejected, at).await;
        assert_eq!(recorded_outcome(mint, &rejected).await, None, "at {at}");
    }

    let much_later = 2 * deleted_at;
    mint.run_maintenance(much_later).await;
    for at in [cutoff, deleted_at, much_later] {
        assert_eq!(
            mint.process_ctf_settlement(&committed.request, settlement_settings(), at)
                .await
                .expect("a committed request replays"),
            response,
            "at {at}"
        );
    }
}

#[tokio::test]
async fn test_ctf_settlement_rejection_record_is_deleted_after_its_retention() {
    assert_rejection_retention(
        &create_test_mint_with_unit(CurrencyUnit::Sat, 1)
            .await
            .unwrap(),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires an isolated PostgreSQL database in PG_DB_URL"]
async fn test_postgres_ctf_settlement_rejection_record_is_deleted_after_its_retention() {
    let mint = postgres_test_mint("ctf_rejection_retention", 41, &[(CurrencyUnit::Sat, 1)]).await;
    assert_rejection_retention(&mint).await;
    mint.stop().await.unwrap();
}

/// A copy can pass the expiry check before the cutoff and reach its commit
/// transaction after the record is deleted. The commit refuses it there.
async fn assert_delayed_commit(mint: &Mint) {
    // The copy read its clock here. The margin keeps each case clear of the
    // time that the test itself takes.
    let margin = 600;
    let end_of_retention = unix_time();
    let read_at = |cutoff: u64| cutoff - FIXTURE_LIFETIME_SECS;

    let late_cutoff = end_of_retention - SETTLEMENT_RECORD_RETENTION_SECS;
    let late =
        standard_settlement_fixture_for_event(mint, read_at(late_cutoff), None, "late").await;
    let completed_before = completed_swap_count(mint).await;
    let result = mint
        .process_ctf_settlement(&late.request, settlement_settings(), read_at(late_cutoff))
        .await;
    assert!(
        matches!(
            result,
            Err(CtfSettlementError::Mint(Error::SettlementAfterExpiry))
        ),
        "{result:?}"
    );
    assert_eq!(recorded_outcome(mint, &late).await, None);
    assert_ctf_settlement_has_no_persistent_mutations(mint, &late, completed_before).await;

    // Inside the retention a record would still refuse it, so it can commit.
    let cutoff = late_cutoff + margin;
    let delayed =
        standard_settlement_fixture_for_event(mint, read_at(cutoff), None, "delayed").await;
    mint.process_ctf_settlement(&delayed.request, settlement_settings(), read_at(cutoff))
        .await
        .expect("a copy inside the retention commits");
}

#[tokio::test]
async fn test_ctf_settlement_copy_delayed_past_the_retention_cannot_commit() {
    assert_delayed_commit(
        &create_test_mint_with_unit(CurrencyUnit::Sat, 1)
            .await
            .unwrap(),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires an isolated PostgreSQL database in PG_DB_URL"]
async fn test_postgres_ctf_settlement_copy_delayed_past_the_retention_cannot_commit() {
    let mint = postgres_test_mint("ctf_rejection_delayed", 42, &[(CurrencyUnit::Sat, 1)]).await;
    assert_delayed_commit(&mint).await;
    mint.stop().await.unwrap();
}

/// The mint keeps at most its cap of live rejection records.
async fn assert_rejection_cap(mint: Mint) {
    let now = unix_time();
    let cutoff = now + FIXTURE_LIFETIME_SECS;
    let capped = |max_cutoff_rejection_records| {
        mint.clone().with_state_limits(StateLimits {
            max_cutoff_rejection_records,
            ..StateLimits::default()
        })
    };
    // Maintenance can delete the first record, so it does not count. The
    // second one counts until the end of its retention.
    let oldest_live = cutoff - SETTLEMENT_RECORD_RETENTION_SECS + 1;
    store_foreign_rejection(&mint, 0x01, oldest_live - 1).await;
    store_foreign_rejection(&mint, 0x02, oldest_live).await;

    let committed = standard_settlement_fixture_for_event(&mint, now, None, "committed").await;
    let response = mint
        .process_ctf_settlement(&committed.request, settlement_settings(), now)
        .await
        .expect("pre-cutoff settlement should commit");
    let recorded = standard_settlement_fixture_for_event(&mint, now, None, "recorded").await;
    refuse_after_cutoff(&capped(2), &recorded, cutoff).await;
    assert_eq!(
        recorded_outcome(&mint, &recorded).await,
        Some(CtfSettlementReplay::RejectedAfterCutoff { cutoff })
    );

    // At the cap, only the requests that have a record get their outcome.
    let refused = standard_settlement_fixture_for_event(&mint, now, None, "refused").await;
    for at in [cutoff, cutoff + 1] {
        refuse_without_record(&capped(1), &refused, at).await;
    }
    refuse_after_cutoff(&capped(0), &recorded, cutoff).await;
    assert_eq!(
        capped(0)
            .process_ctf_settlement(&committed.request, settlement_settings(), cutoff)
            .await
            .expect("a committed request replays at the cap"),
        response
    );

    // The cap ends with the retention: the refusal then needs no record.
    let end = cutoff + SETTLEMENT_RECORD_RETENTION_SECS;
    refuse_without_record(&capped(0), &refused, end - 1).await;
    refuse_after_cutoff(&capped(0), &refused, end).await;
    assert_eq!(recorded_outcome(&mint, &refused).await, None);

    // Below the cap, the identical request gets its record.
    refuse_after_cutoff(&capped(3), &refused, cutoff).await;
    assert_eq!(
        recorded_outcome(&mint, &refused).await,
        Some(CtfSettlementReplay::RejectedAfterCutoff { cutoff })
    );
}

#[tokio::test]
async fn test_ctf_settlement_rejection_records_have_a_cap() {
    assert_eq!(
        StateLimits::default().max_cutoff_rejection_records,
        MAX_CUTOFF_REJECTION_RECORDS
    );
    assert_rejection_cap(
        create_test_mint_with_unit(CurrencyUnit::Sat, 1)
            .await
            .unwrap(),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires an isolated PostgreSQL database in PG_DB_URL"]
async fn test_postgres_ctf_settlement_rejection_records_have_a_cap() {
    let mint = postgres_test_mint("ctf_rejection_cap", 43, &[(CurrencyUnit::Sat, 1)]).await;
    assert_rejection_cap(mint.clone()).await;
    mint.stop().await.unwrap();
}

/// The refusal at the cap is not definitive: a copy that passed the expiry
/// check before the cutoff can commit after it.
#[tokio::test]
async fn test_ctf_settlement_refused_at_the_rejection_cap_can_still_commit() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap()
        .with_state_limits(StateLimits {
            max_cutoff_rejection_records: 0,
            ..StateLimits::default()
        });
    let now = unix_time();
    let cutoff = now + FIXTURE_LIFETIME_SECS;
    let fixture = standard_settlement_fixture(&mint, now).await;
    refuse_without_record(&mint, &fixture, cutoff).await;
    let response = mint
        .process_ctf_settlement(&fixture.request, settlement_settings(), now)
        .await
        .expect("the copy that was in flight commits");
    assert_eq!(
        mint.process_ctf_settlement(&fixture.request, settlement_settings(), cutoff)
            .await
            .expect("the committed request replays"),
        response
    );
}
