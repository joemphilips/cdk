//! Payments

use std::cmp::Reverse;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use cashu::nut00::KnownMethod;
use cashu::quote_id::QuoteId;
use cashu::{Amount, BlindSignature, CurrencyUnit, Id, SecretKey};

use crate::database::mint::{Database, DynMintDatabase, Error, KeysDatabase};
use crate::database::MintSignaturesDatabase;
use crate::mint::{MeltPaymentRequest, MeltQuote, MintQuote, Operation};
use crate::payment::PaymentIdentifier;

fn unique_string() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Add a mint quote
pub async fn add_mint_quote<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(0, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt12),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    assert!(tx.add_mint_quote(mint_quote.clone()).await.is_ok());
    tx.commit().await.unwrap();
}

/// Dup mint quotes fails
pub async fn add_mint_quote_only_once<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(0, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt12),
        0,
        0,
        vec![],
        vec![],
        None,
    );
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    assert!(tx.add_mint_quote(mint_quote.clone()).await.is_ok());
    tx.commit().await.unwrap();

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    assert!(tx.add_mint_quote(mint_quote).await.is_err());
    tx.commit().await.unwrap();
}

/// Register payments
pub async fn register_payments<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(0, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt12),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx.add_mint_quote(mint_quote).await.unwrap();

    let p1 = unique_string();
    let p2 = unique_string();

    mint_quote
        .add_payment(
            Amount::from(100).with_unit(CurrencyUnit::Sat),
            p1.clone(),
            None,
        )
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();

    assert_eq!(mint_quote.amount_paid().value(), 100);

    mint_quote
        .add_payment(
            Amount::from(250).with_unit(CurrencyUnit::Sat),
            p2.clone(),
            None,
        )
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();

    assert_eq!(mint_quote.amount_paid().value(), 350);

    tx.commit().await.unwrap();

    let mint_quote_from_db = db
        .get_mint_quote(&mint_quote.id)
        .await
        .unwrap()
        .expect("mint_quote_from_db");
    assert_eq!(mint_quote_from_db.amount_paid().value(), 350);
    assert_eq!(
        mint_quote_from_db
            .payments
            .iter()
            .map(|x| (x.payment_id.clone(), x.amount.clone()))
            .collect::<Vec<_>>(),
        vec![
            (p1, Amount::from(100).with_unit(CurrencyUnit::Sat)),
            (p2, Amount::from(250).with_unit(CurrencyUnit::Sat))
        ]
    );
}

/// Read mint and payments from db and tx objects
pub async fn read_mint_from_db_and_tx<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(0, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt12),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    let p1 = unique_string();
    let p2 = unique_string();

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx.add_mint_quote(mint_quote.clone()).await.unwrap();
    mint_quote
        .add_payment(
            Amount::from(100).with_unit(CurrencyUnit::Sat),
            p1.clone(),
            None,
        )
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();

    assert_eq!(mint_quote.amount_paid().value(), 100);

    mint_quote
        .add_payment(
            Amount::from(250).with_unit(CurrencyUnit::Sat),
            p2.clone(),
            None,
        )
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();
    assert_eq!(mint_quote.amount_paid().value(), 350);
    tx.commit().await.unwrap();

    let mint_quote_from_db = db
        .get_mint_quote(&mint_quote.id)
        .await
        .unwrap()
        .expect("mint_quote_from_db");
    assert_eq!(mint_quote_from_db.amount_paid().value(), 350);
    assert_eq!(
        mint_quote_from_db
            .payments
            .iter()
            .map(|x| (x.payment_id.clone(), x.amount.clone()))
            .collect::<Vec<_>>(),
        vec![
            (p1, Amount::from(100).with_unit(CurrencyUnit::Sat)),
            (p2, Amount::from(250).with_unit(CurrencyUnit::Sat))
        ]
    );

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mint_quote_from_tx = tx
        .get_mint_quote(&mint_quote.id)
        .await
        .unwrap()
        .expect("mint_quote_from_tx");
    assert_eq!(mint_quote_from_db, mint_quote_from_tx.deref().to_owned());
}

/// Reject duplicate payments in the same txs
pub async fn reject_duplicate_payments_same_tx<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(0, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt12),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    let p1 = unique_string();

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx.add_mint_quote(mint_quote.clone()).await.unwrap();
    mint_quote
        .add_payment(
            Amount::from(100).with_unit(CurrencyUnit::Sat),
            p1.clone(),
            None,
        )
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();

    // Duplicate payment should fail
    assert!(mint_quote
        .add_payment(Amount::from(100).with_unit(CurrencyUnit::Sat), p1, None)
        .is_err());
    tx.commit().await.unwrap();

    let mint_quote_from_db = db
        .get_mint_quote(&mint_quote.id)
        .await
        .unwrap()
        .expect("mint_from_db");
    assert_eq!(mint_quote_from_db.amount_paid(), mint_quote.amount_paid());
    assert_eq!(mint_quote_from_db.payments.len(), 1);
}

/// Reject duplicate payments in different txs
pub async fn reject_duplicate_payments_diff_tx<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let p1 = unique_string();

    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(0, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt12),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx.add_mint_quote(mint_quote.clone()).await.unwrap();
    mint_quote
        .add_payment(
            Amount::from(100).with_unit(CurrencyUnit::Sat),
            p1.clone(),
            None,
        )
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx
        .get_mint_quote(&mint_quote.id)
        .await
        .expect("no error")
        .expect("quote");
    // Duplicate payment should fail
    assert!(mint_quote
        .add_payment(Amount::from(100).with_unit(CurrencyUnit::Sat), p1, None)
        .is_err());
    tx.commit().await.unwrap(); // although in theory nothing has changed, let's try it out

    let mint_quote_from_db = db
        .get_mint_quote(&mint_quote.id)
        .await
        .unwrap()
        .expect("mint_from_db");
    assert_eq!(mint_quote_from_db.amount_paid(), mint_quote.amount_paid());
    assert_eq!(mint_quote_from_db.payments.len(), 1);
}

/// Reject over issue in same tx
pub async fn reject_over_issue_same_tx<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(0, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt12),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx.add_mint_quote(mint_quote.clone()).await.unwrap();
    // Trying to issue without any payment should fail (over-issue)
    assert!(mint_quote
        .add_issuance(Amount::from(100).with_unit(CurrencyUnit::Sat))
        .is_err());
}

/// Reject over issue
pub async fn reject_over_issue_different_tx<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(0, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt12),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_mint_quote(mint_quote.clone()).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx
        .get_mint_quote(&mint_quote.id)
        .await
        .expect("no error")
        .expect("quote");
    // Trying to issue without any payment should fail (over-issue)
    assert!(mint_quote
        .add_issuance(Amount::from(100).with_unit(CurrencyUnit::Sat))
        .is_err());
}

/// Reject over issue with payment
pub async fn reject_over_issue_with_payment<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(0, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt12),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    let p1 = unique_string();
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx.add_mint_quote(mint_quote.clone()).await.unwrap();
    mint_quote
        .add_payment(
            Amount::from(100).with_unit(CurrencyUnit::Sat),
            p1.clone(),
            None,
        )
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();
    // Trying to issue more than paid should fail (over-issue)
    assert!(mint_quote
        .add_issuance(Amount::from(101).with_unit(CurrencyUnit::Sat))
        .is_err());
}

/// Reject over issue with payment
pub async fn reject_over_issue_with_payment_different_tx<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(0, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt12),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    let p1 = unique_string();
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx.add_mint_quote(mint_quote).await.unwrap();
    let quote_id = mint_quote.id.clone();
    mint_quote
        .add_payment(
            Amount::from(100).with_unit(CurrencyUnit::Sat),
            p1.clone(),
            None,
        )
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx
        .get_mint_quote(&quote_id)
        .await
        .expect("no error")
        .expect("quote");
    // Trying to issue more than paid should fail (over-issue)
    assert!(mint_quote
        .add_issuance(Amount::from(101).with_unit(CurrencyUnit::Sat))
        .is_err());
}
/// Successful melt with unique blinded messages
pub async fn add_melt_request_unique_blinded_messages<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error> + MintSignaturesDatabase<Err = Error>,
{
    let inputs_amount = Amount::new(100, CurrencyUnit::Sat);
    let inputs_fee = Amount::new(1, CurrencyUnit::Sat);
    let keyset_id = Id::from_str("001711afb1de20cb").unwrap();

    // Use reverse key order to verify physical lock ordering does not change
    // the logical order returned to the client.
    let mut blinded_messages = vec![
        cashu::BlindedMessage {
            blinded_secret: SecretKey::generate().public_key(),
            keyset_id,
            amount: Amount::from(100u64),
            witness: None,
        },
        cashu::BlindedMessage {
            blinded_secret: SecretKey::generate().public_key(),
            keyset_id,
            amount: Amount::from(200u64),
            witness: None,
        },
    ];
    blinded_messages.sort_unstable_by_key(|message| Reverse(message.blinded_secret.to_bytes()));

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let quote = MeltQuote::new(None,MeltPaymentRequest::Bolt11 { bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap() }, cashu::CurrencyUnit::Sat, Amount::new(33, cashu::CurrencyUnit::Sat), Amount::new(0, cashu::CurrencyUnit::Sat), 0, None, None, cashu::PaymentMethod::Known(KnownMethod::Bolt11), None, None);
    tx.add_melt_quote(quote.clone()).await.unwrap();
    tx.add_melt_request(&quote.id, inputs_amount.clone(), inputs_fee.clone())
        .await
        .unwrap();
    tx.add_blinded_messages(
        Some(&quote.id),
        &blinded_messages,
        &Operation::new_melt(
            Amount::ZERO,
            Amount::ZERO,
            cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        ),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Verify retrieval
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let retrieved = tx
        .get_melt_request_and_blinded_messages(&quote.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved.inputs_amount, inputs_amount);
    assert_eq!(retrieved.inputs_fee, inputs_fee);
    assert_eq!(retrieved.change_outputs.len(), 2);
    assert_eq!(retrieved.change_outputs, blinded_messages);
    tx.commit().await.unwrap();
}

/// Reject melt with duplicate blinded message (already signed)
pub async fn reject_melt_duplicate_blinded_signature<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error> + MintSignaturesDatabase<Err = Error>,
{
    let quote_id1 = QuoteId::new();
    let inputs_amount = Amount::new(100, CurrencyUnit::Sat);
    let inputs_fee = Amount::new(1, CurrencyUnit::Sat);
    let keyset_id = Id::from_str("001711afb1de20cb").unwrap();

    // Create a dummy blinded message
    let blinded_secret = SecretKey::generate().public_key();
    let blinded_message = cashu::BlindedMessage {
        blinded_secret,
        keyset_id,
        amount: Amount::from(100u64),
        witness: None,
    };
    let blinded_messages = vec![blinded_message.clone()];

    // First, "sign" it by adding to blind_signature (simulate successful mint)
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let c = SecretKey::generate().public_key();
    let blind_sig = cashu::BlindSignature {
        amount: Amount::from(100u64),
        keyset_id,
        c,
        dleq: None,
    };
    let blinded_secrets = vec![blinded_message.blinded_secret];
    tx.add_blind_signatures(&blinded_secrets, &[blind_sig], Some(quote_id1))
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Now try to add melt request with the same blinded message - should fail due to constraint
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let quote2 = MeltQuote::new(None,MeltPaymentRequest::Bolt11 { bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap() }, cashu::CurrencyUnit::Sat, Amount::new(33, cashu::CurrencyUnit::Sat),Amount::new(0, cashu::CurrencyUnit::Sat), 0, None, None, cashu::PaymentMethod::Known(KnownMethod::Bolt11), None, None);
    tx.add_melt_quote(quote2.clone()).await.unwrap();
    tx.add_melt_request(&quote2.id, inputs_amount, inputs_fee)
        .await
        .unwrap();
    let result = tx
        .add_blinded_messages(
            Some(&quote2.id),
            &blinded_messages,
            &Operation::new_melt(
                Amount::ZERO,
                Amount::ZERO,
                cashu::PaymentMethod::Known(KnownMethod::Bolt11),
            ),
        )
        .await;
    assert!(result.is_err() && matches!(result.unwrap_err(), Error::Duplicate));
    tx.rollback().await.unwrap(); // Rollback to avoid partial state
}

/// Reject duplicate blinded message insert via DB constraint (different quotes)
pub async fn reject_duplicate_blinded_message_db_constraint<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let inputs_amount = Amount::new(100, CurrencyUnit::Sat);
    let inputs_fee = Amount::new(1, CurrencyUnit::Sat);
    let keyset_id = Id::from_str("001711afb1de20cb").unwrap();

    // Create a dummy blinded message
    let blinded_secret = SecretKey::generate().public_key();
    let blinded_message = cashu::BlindedMessage {
        blinded_secret,
        keyset_id,
        amount: Amount::from(100u64),
        witness: None,
    };
    let blinded_messages = vec![blinded_message];

    // First insert succeeds
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let quote = MeltQuote::new(None,MeltPaymentRequest::Bolt11 { bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap() }, cashu::CurrencyUnit::Sat, Amount::new(33, cashu::CurrencyUnit::Sat), Amount::new(0, cashu::CurrencyUnit::Sat), 0, None, None, cashu::PaymentMethod::Known(KnownMethod::Bolt11), None, None);
    tx.add_melt_quote(quote.clone()).await.unwrap();
    tx.add_melt_request(&quote.id, inputs_amount.clone(), inputs_fee.clone())
        .await
        .unwrap();
    assert!(tx
        .add_blinded_messages(
            Some(&quote.id),
            &blinded_messages,
            &Operation::new_melt(
                Amount::ZERO,
                Amount::ZERO,
                cashu::PaymentMethod::Known(KnownMethod::Bolt11)
            )
        )
        .await
        .is_ok());
    tx.commit().await.unwrap();

    // Second insert with same blinded_message but different quote_id should fail due to unique constraint on blinded_message
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let quote = MeltQuote::new(None,MeltPaymentRequest::Bolt11 { bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap() }, cashu::CurrencyUnit::Sat, Amount::new(33, cashu::CurrencyUnit::Sat), Amount::new(0, cashu::CurrencyUnit::Sat), 0, None, None, cashu::PaymentMethod::Known(KnownMethod::Bolt11), None, None);
    tx.add_melt_quote(quote.clone()).await.unwrap();
    tx.add_melt_request(&quote.id, inputs_amount, inputs_fee)
        .await
        .unwrap();
    let result = tx
        .add_blinded_messages(
            Some(&quote.id),
            &blinded_messages,
            &Operation::new_melt(
                Amount::ZERO,
                Amount::ZERO,
                cashu::PaymentMethod::Known(KnownMethod::Bolt11),
            ),
        )
        .await;
    // Expect a database error due to unique violation
    assert!(result.is_err()); // Specific error might be DB-specific, e.g., SqliteError or PostgresError
    tx.rollback().await.unwrap();
}

/// Cleanup of melt request after processing
pub async fn cleanup_melt_request_after_processing<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let inputs_amount = Amount::new(100, CurrencyUnit::Sat);
    let inputs_fee = Amount::new(1, CurrencyUnit::Sat);
    let keyset_id = Id::from_str("001711afb1de20cb").unwrap();

    // Create dummy blinded message
    let blinded_secret = SecretKey::generate().public_key();
    let blinded_message = cashu::BlindedMessage {
        blinded_secret,
        keyset_id,
        amount: Amount::from(100u64),
        witness: None,
    };
    let blinded_messages = vec![blinded_message];

    // Insert melt request
    let mut tx1 = Database::begin_transaction(&db).await.unwrap();
    let quote = MeltQuote::new(None,MeltPaymentRequest::Bolt11 { bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap() }, cashu::CurrencyUnit::Sat, Amount::new(33, cashu::CurrencyUnit::Sat), Amount::new(0, cashu::CurrencyUnit::Sat), 0, None, None, cashu::PaymentMethod::Known(KnownMethod::Bolt11), None, None);
    tx1.add_melt_quote(quote.clone()).await.unwrap();
    tx1.add_melt_request(&quote.id, inputs_amount, inputs_fee)
        .await
        .unwrap();
    tx1.add_blinded_messages(
        Some(&quote.id),
        &blinded_messages,
        &Operation::new_melt(
            Amount::ZERO,
            Amount::ZERO,
            cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        ),
    )
    .await
    .unwrap();
    tx1.commit().await.unwrap();

    // Simulate processing: get and delete
    let mut tx2 = Database::begin_transaction(&db).await.unwrap();
    let _retrieved = tx2
        .get_melt_request_and_blinded_messages(&quote.id)
        .await
        .unwrap()
        .unwrap();
    tx2.delete_melt_request(&quote.id).await.unwrap();
    tx2.commit().await.unwrap();

    // Verify melt_request is deleted
    let mut tx3 = Database::begin_transaction(&db).await.unwrap();
    let retrieved = tx3
        .get_melt_request_and_blinded_messages(&quote.id)
        .await
        .unwrap();
    assert!(retrieved.is_none());
    tx3.commit().await.unwrap();
}

/// Test adding and retrieving melt quotes
pub async fn add_and_get_melt_quote<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let melt_quote = MeltQuote::new(
        None,
        MeltPaymentRequest::Bolt11 {
            bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap()
        },
        cashu::CurrencyUnit::Sat,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(10, cashu::CurrencyUnit::Sat),
        0,
        None,
        None,
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        Some(serde_json::json!({"processor": "metadata"})),
        None    );

    // Add melt quote
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    assert!(tx.add_melt_quote(melt_quote.clone()).await.is_ok());
    tx.commit().await.unwrap();

    // Retrieve melt quote
    let retrieved = db.get_melt_quote(&melt_quote.id).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, melt_quote.id);
    assert_eq!(retrieved.amount(), melt_quote.amount());
    assert_eq!(retrieved.fee_reserve(), melt_quote.fee_reserve());
    assert_eq!(retrieved.extra_json, melt_quote.extra_json);
}

/// Test adding duplicate melt quotes fails
pub async fn add_melt_quote_only_once<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let melt_quote = MeltQuote::new(
        None,
        MeltPaymentRequest::Bolt11 {
            bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap()
        },
        cashu::CurrencyUnit::Sat,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(10, cashu::CurrencyUnit::Sat),
        0,
        None,
        None,
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        None,
        None    );

    // Add first melt quote
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    assert!(tx.add_melt_quote(melt_quote.clone()).await.is_ok());
    tx.commit().await.unwrap();

    // Try to add duplicate - should fail
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    assert!(tx.add_melt_quote(melt_quote).await.is_err());
    tx.rollback().await.unwrap();
}

/// Test updating melt quote state
pub async fn update_melt_quote_state_transition<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    use cashu::MeltQuoteState;

    let melt_quote = MeltQuote::new(
        None,
        MeltPaymentRequest::Bolt11 {
            bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap()
        },
        cashu::CurrencyUnit::Sat,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(10, cashu::CurrencyUnit::Sat),
        0,
        None,
        None,
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        Some(serde_json::json!({"state": "init"})),
        None,
    );

    // Add melt quote
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_melt_quote(melt_quote.clone()).await.unwrap();
    tx.commit().await.unwrap();

    // Update to Pending state
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut quote = tx.get_melt_quote(&melt_quote.id).await.unwrap().unwrap();
    let old_state = tx
        .update_melt_quote_state(&mut quote, MeltQuoteState::Pending, None)
        .await
        .unwrap();
    assert_eq!(old_state, MeltQuoteState::Unpaid);
    assert_eq!(quote.state, MeltQuoteState::Pending);
    assert_eq!(quote.extra_json, Some(serde_json::json!({"state": "init"})));
    tx.commit().await.unwrap();

    // Update to Paid state with payment proof
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut quote = tx.get_melt_quote(&melt_quote.id).await.unwrap().unwrap();
    let payment_proof = "payment_proof_123".to_string();
    let old_state = tx
        .update_melt_quote_state(
            &mut quote,
            MeltQuoteState::Paid,
            Some(payment_proof.clone()),
        )
        .await
        .unwrap();
    assert_eq!(old_state, MeltQuoteState::Pending);
    assert_eq!(quote.state, MeltQuoteState::Paid);
    // The payment proof is stored in the melt quote (verification depends on implementation)
    tx.commit().await.unwrap();
}

/// Test updating melt quote request lookup id
pub async fn update_melt_quote_request_lookup_id<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let melt_quote = MeltQuote::new(
        None,
        MeltPaymentRequest::Bolt11 {
            bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap()
        },
        cashu::CurrencyUnit::Sat,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(10, cashu::CurrencyUnit::Sat),
        0,
        Some(PaymentIdentifier::CustomId("old_lookup_id".to_string())),
        None,
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        Some(serde_json::json!({"lookup": "test"})),
        None,
    );

    // Add melt quote
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_melt_quote(melt_quote.clone()).await.unwrap();
    tx.commit().await.unwrap();

    // Update request lookup id
    let new_lookup_id = PaymentIdentifier::CustomId("new_lookup_id".to_string());
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut quote = tx.get_melt_quote(&melt_quote.id).await.unwrap().unwrap();
    tx.update_melt_quote_request_lookup_id(&mut quote, &new_lookup_id)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Verify the update
    let retrieved = db.get_melt_quote(&melt_quote.id).await.unwrap().unwrap();
    assert_eq!(retrieved.request_lookup_id, Some(new_lookup_id));
    assert_eq!(
        retrieved.extra_json,
        Some(serde_json::json!({"lookup": "test"}))
    );
}

/// Test getting all mint quotes
pub async fn get_all_mint_quotes<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let quote1 = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    let quote2 = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(200, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    // Add quotes
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_mint_quote(quote1.clone()).await.unwrap();
    tx.add_mint_quote(quote2.clone()).await.unwrap();
    tx.commit().await.unwrap();

    // Get all quotes
    let all_quotes = db.get_mint_quotes().await.unwrap();
    assert!(all_quotes.len() >= 2);
    assert!(all_quotes.iter().any(|q| q.id == quote1.id));
    assert!(all_quotes.iter().any(|q| q.id == quote2.id));
}

/// Test getting all melt quotes
pub async fn get_all_melt_quotes<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let quote1 = MeltQuote::new(
        None,
        MeltPaymentRequest::Bolt11 {
            bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap()
        },
        cashu::CurrencyUnit::Sat,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(10, cashu::CurrencyUnit::Sat),
        0,
        None,
        None,
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        Some(serde_json::json!({"processor": "metadata-1"})),
        None    );

    let quote2 = MeltQuote::new(
        None,
        MeltPaymentRequest::Bolt11 {
            bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap()
        },
        cashu::CurrencyUnit::Sat,
        Amount::new(200, cashu::CurrencyUnit::Sat),
        Amount::new(20, cashu::CurrencyUnit::Sat),
        0,
        None,
        None,
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        Some(serde_json::json!({"processor": "metadata-2"})),
        None    );

    // Add quotes
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_melt_quote(quote1.clone()).await.unwrap();
    tx.add_melt_quote(quote2.clone()).await.unwrap();
    tx.commit().await.unwrap();

    // Get all quotes
    let all_quotes = db.get_melt_quotes().await.unwrap();
    assert!(all_quotes.len() >= 2);

    let retrieved_quote1 = all_quotes.iter().find(|q| q.id == quote1.id).unwrap();
    let retrieved_quote2 = all_quotes.iter().find(|q| q.id == quote2.id).unwrap();

    assert_eq!(retrieved_quote1.extra_json, quote1.extra_json);
    assert_eq!(retrieved_quote1.payment_method, quote1.payment_method);
    assert_eq!(retrieved_quote2.extra_json, quote2.extra_json);
    assert_eq!(retrieved_quote2.payment_method, quote2.payment_method);
}

/// Test getting mint quote by request
pub async fn get_mint_quote_by_request<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let request = unique_string();
    let mint_quote = MintQuote::new(
        None,
        request.clone(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    // Add quote
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_mint_quote(mint_quote.clone()).await.unwrap();
    tx.commit().await.unwrap();

    // Get by request
    let retrieved = db.get_mint_quote_by_request(&request).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, mint_quote.id);
    assert_eq!(retrieved.request, request);
}

/// Test getting mint quote by request lookup id
pub async fn get_mint_quote_by_request_lookup_id<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let lookup_id = PaymentIdentifier::CustomId(unique_string());
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        lookup_id.clone(),
        None,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    // Add quote
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_mint_quote(mint_quote.clone()).await.unwrap();
    tx.commit().await.unwrap();

    // Get by request lookup id
    let retrieved = db
        .get_mint_quote_by_request_lookup_id(&lookup_id)
        .await
        .unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, mint_quote.id);
    assert_eq!(retrieved.request_lookup_id, lookup_id);
}

/// Test deleting blinded messages
pub async fn delete_blinded_messages<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let keyset_id = Id::from_str("001711afb1de20cb").unwrap();

    // Create blinded messages
    let blinded_secret1 = SecretKey::generate().public_key();
    let blinded_secret2 = SecretKey::generate().public_key();

    let blinded_message1 = cashu::BlindedMessage {
        blinded_secret: blinded_secret1,
        keyset_id,
        amount: Amount::from(100u64),
        witness: None,
    };

    let blinded_message2 = cashu::BlindedMessage {
        blinded_secret: blinded_secret2,
        keyset_id,
        amount: Amount::from(200u64),
        witness: None,
    };

    let blinded_messages = vec![blinded_message1.clone(), blinded_message2.clone()];

    // Add blinded messages
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_blinded_messages(
        None,
        &blinded_messages,
        &Operation::new_mint(
            Amount::ZERO,
            cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        ),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Delete one blinded message
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.delete_blinded_messages(&[blinded_secret1])
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Try to add same blinded messages again - first should succeed, second should fail
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    assert!(tx
        .add_blinded_messages(
            None,
            &[blinded_message1],
            &Operation::new_mint(
                Amount::ZERO,
                cashu::PaymentMethod::Known(KnownMethod::Bolt11)
            )
        )
        .await
        .is_ok());
    assert!(tx
        .add_blinded_messages(
            None,
            &[blinded_message2],
            &Operation::new_mint(
                Amount::ZERO,
                cashu::PaymentMethod::Known(KnownMethod::Bolt11)
            )
        )
        .await
        .is_err());
    tx.rollback().await.unwrap();
}

/// Compensation deletes only pending outputs. A stored signature is permanent.
pub async fn delete_blinded_messages_keeps_signed_rows<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error> + MintSignaturesDatabase<Err = Error>,
{
    let keyset_id = Id::from_str("001711afb1de20cb").unwrap();
    let message = |amount: u64| cashu::BlindedMessage {
        blinded_secret: SecretKey::generate().public_key(),
        keyset_id,
        amount: Amount::from(amount),
        witness: None,
    };
    let signature = |amount: u64| BlindSignature {
        amount: Amount::from(amount),
        keyset_id,
        c: SecretKey::generate().public_key(),
        dleq: None,
    };
    let operation = Operation::new_swap(Amount::ZERO, Amount::ZERO, Amount::ZERO);
    let signed = message(8);
    let pending = message(4);
    let stored = signature(8);

    // One operation stores both outputs as pending and then signs one of them.
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_blinded_messages(None, &[signed.clone(), pending.clone()], &operation)
        .await
        .unwrap();
    tx.add_blind_signatures(
        &[signed.blinded_secret],
        std::slice::from_ref(&stored),
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Compensation names both outputs.
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.delete_blinded_messages(&[signed.blinded_secret, pending.blinded_secret])
        .await
        .unwrap();
    tx.commit().await.unwrap();

    assert_eq!(
        db.get_blind_signatures(&[signed.blinded_secret, pending.blinded_secret])
            .await
            .unwrap(),
        vec![Some(stored.clone()), None]
    );
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    assert!(
        tx.add_blinded_messages(None, std::slice::from_ref(&pending), &operation)
            .await
            .is_ok(),
        "the pending row must be gone"
    );
    assert!(matches!(
        tx.add_blinded_messages(None, std::slice::from_ref(&signed), &operation)
            .await,
        Err(Error::Duplicate)
    ));
    tx.rollback().await.unwrap();

    // A later operation cannot replace the stored signature.
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    assert!(matches!(
        tx.add_blind_signatures(&[signed.blinded_secret], &[signature(8)], None)
            .await,
        Err(Error::Duplicate)
    ));
    tx.rollback().await.unwrap();
    assert_eq!(
        db.get_blind_signatures(&[signed.blinded_secret])
            .await
            .unwrap(),
        vec![Some(stored)]
    );
}

/// Deleting a melt request deletes only its pending change outputs.
pub async fn delete_melt_request_keeps_signed_change<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error> + MintSignaturesDatabase<Err = Error>,
{
    let keyset_id = Id::from_str("001711afb1de20cb").unwrap();
    let message = |amount: u64| cashu::BlindedMessage {
        blinded_secret: SecretKey::generate().public_key(),
        keyset_id,
        amount: Amount::from(amount),
        witness: None,
    };
    let operation = Operation::new_melt(
        Amount::ZERO,
        Amount::ZERO,
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
    );
    let signed = message(8);
    let pending = message(4);
    let stored = BlindSignature {
        amount: Amount::from(8u64),
        keyset_id,
        c: SecretKey::generate().public_key(),
        dleq: None,
    };
    let quote = MeltQuote::new(
        None,
        MeltPaymentRequest::Bolt11 {
            bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap(),
        },
        CurrencyUnit::Sat,
        Amount::new(33, CurrencyUnit::Sat),
        Amount::new(0, CurrencyUnit::Sat),
        0,
        None,
        None,
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        None,
        None,
    );

    // The melt request stores two change outputs, and one of them is signed.
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_melt_quote(quote.clone()).await.unwrap();
    tx.add_melt_request(
        &quote.id,
        Amount::new(100, CurrencyUnit::Sat),
        Amount::new(1, CurrencyUnit::Sat),
    )
    .await
    .unwrap();
    tx.add_blinded_messages(
        Some(&quote.id),
        &[signed.clone(), pending.clone()],
        &operation,
    )
    .await
    .unwrap();
    tx.add_blind_signatures(
        &[signed.blinded_secret],
        std::slice::from_ref(&stored),
        Some(quote.id.clone()),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // The signed row keeps the quote id, so only `c IS NULL` protects it here.
    assert_eq!(
        db.get_blind_signatures_for_quote(&quote.id).await.unwrap(),
        vec![stored.clone()]
    );
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.delete_melt_request(&quote.id).await.unwrap();
    tx.commit().await.unwrap();

    assert_eq!(
        db.get_blind_signatures(&[signed.blinded_secret, pending.blinded_secret])
            .await
            .unwrap(),
        vec![Some(stored), None]
    );
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    assert!(
        tx.add_blinded_messages(None, std::slice::from_ref(&pending), &operation)
            .await
            .is_ok(),
        "the pending change row must be gone"
    );
    assert!(matches!(
        tx.add_blinded_messages(None, std::slice::from_ref(&signed), &operation)
            .await,
        Err(Error::Duplicate)
    ));
    tx.rollback().await.unwrap();
}

/// Test incrementing mint quote amount paid
pub async fn increment_mint_quote_amount_paid<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(1000, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    // Add quote
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mint_quote = tx.add_mint_quote(mint_quote).await.unwrap();
    tx.commit().await.unwrap();

    // Add payment first time
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx
        .get_mint_quote(&mint_quote.id)
        .await
        .expect("valid quote")
        .expect("valid result");
    mint_quote
        .add_payment(
            Amount::from(300).with_unit(CurrencyUnit::Sat),
            "payment_1".to_string(),
            Some(100),
        )
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();
    assert_eq!(mint_quote.amount_paid().value(), 300);
    let first_updated_at = mint_quote.updated_at();
    assert!(first_updated_at > 0);
    tx.commit().await.unwrap();

    // Add payment second time
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx
        .get_mint_quote(&mint_quote.id)
        .await
        .expect("valid quote")
        .expect("valid result");
    mint_quote
        .add_payment(
            Amount::from(200).with_unit(CurrencyUnit::Sat),
            "payment_2".to_string(),
            Some(100),
        )
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();
    assert_eq!(mint_quote.amount_paid().value(), 500);
    let second_updated_at = mint_quote.updated_at();
    assert!(second_updated_at > first_updated_at);
    tx.commit().await.unwrap();

    // Verify final state
    let retrieved = db.get_mint_quote(&mint_quote.id).await.unwrap().unwrap();
    assert_eq!(retrieved.amount_paid().value(), 500);
    assert_eq!(retrieved.updated_at(), second_updated_at);

    // Even if the in-memory quote carries a stale timestamp, persistence must
    // bump from the database value instead of regressing.
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx
        .get_mint_quote(&mint_quote.id)
        .await
        .expect("valid quote")
        .expect("valid result");
    mint_quote.set_updated_at(0);
    mint_quote
        .add_payment(
            Amount::from(100).with_unit(CurrencyUnit::Sat),
            "payment_3".to_string(),
            Some(100),
        )
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();
    assert_eq!(mint_quote.amount_paid().value(), 600);
    let stale_update_updated_at = mint_quote.updated_at();
    assert!(stale_update_updated_at > second_updated_at);
    tx.commit().await.unwrap();

    let retrieved = db.get_mint_quote(&mint_quote.id).await.unwrap().unwrap();
    assert_eq!(retrieved.amount_paid().value(), 600);
    assert_eq!(retrieved.updated_at(), stale_update_updated_at);
}

/// Test incrementing mint quote amount issued
pub async fn increment_mint_quote_amount_issued<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(1000, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    // Add quote
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_mint_quote(mint_quote.clone()).await.unwrap();
    tx.commit().await.unwrap();

    // First add payment to allow issuing
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx
        .get_mint_quote(&mint_quote.id)
        .await
        .expect("valid quote")
        .expect("valid result");
    mint_quote
        .add_payment(
            Amount::from(1000).with_unit(CurrencyUnit::Sat),
            "payment_1".to_string(),
            None,
        )
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();
    let paid_updated_at = mint_quote.updated_at();
    tx.commit().await.unwrap();

    // Add issuance first time
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx
        .get_mint_quote(&mint_quote.id)
        .await
        .expect("valid quote")
        .expect("valid result");
    mint_quote
        .add_issuance(Amount::from(400).with_unit(CurrencyUnit::Sat))
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();
    assert_eq!(mint_quote.amount_issued().value(), 400);
    let first_issuance_updated_at = mint_quote.updated_at();
    assert!(first_issuance_updated_at > paid_updated_at);
    tx.commit().await.unwrap();

    // Add issuance second time
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx
        .get_mint_quote(&mint_quote.id)
        .await
        .expect("valid quote")
        .expect("valid result");
    mint_quote
        .add_issuance(Amount::from(300).with_unit(CurrencyUnit::Sat))
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();
    assert_eq!(mint_quote.amount_issued().value(), 700);
    let second_issuance_updated_at = mint_quote.updated_at();
    assert!(second_issuance_updated_at > first_issuance_updated_at);
    tx.commit().await.unwrap();

    // Verify final state
    let retrieved = db.get_mint_quote(&mint_quote.id).await.unwrap().unwrap();
    assert_eq!(retrieved.amount_issued().value(), 700);
    assert_eq!(retrieved.updated_at(), second_issuance_updated_at);
}

/// Test getting mint quote within transaction (with lock)
pub async fn get_mint_quote_in_transaction<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    // Add quote
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_mint_quote(mint_quote.clone()).await.unwrap();
    tx.commit().await.unwrap();

    // Get quote within transaction
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let retrieved = tx.get_mint_quote(&mint_quote.id).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, mint_quote.id);
    assert_eq!(retrieved.request, mint_quote.request);
    tx.commit().await.unwrap();
}

/// Test getting melt quote within transaction (with lock)
pub async fn get_melt_quote_in_transaction<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let melt_quote = MeltQuote::new(
        None,
        MeltPaymentRequest::Bolt11 {
            bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap()
        },
        cashu::CurrencyUnit::Sat,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(10, cashu::CurrencyUnit::Sat),
        0,
        None,
        None,
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        Some(serde_json::json!({"tx": true})),
        None,
    );

    // Add quote
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_melt_quote(melt_quote.clone()).await.unwrap();
    tx.commit().await.unwrap();

    // Get quote within transaction
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let retrieved = tx.get_melt_quote(&melt_quote.id).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, melt_quote.id);
    assert_eq!(retrieved.amount(), melt_quote.amount());
    assert_eq!(retrieved.extra_json, Some(serde_json::json!({"tx": true})));
    tx.commit().await.unwrap();
}

/// Test get mint quote by request within transaction
pub async fn get_mint_quote_by_request_in_transaction<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let request = unique_string();
    let mint_quote = MintQuote::new(
        None,
        request.clone(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    // Add quote
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_mint_quote(mint_quote.clone()).await.unwrap();
    tx.commit().await.unwrap();

    // Get by request within transaction
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let retrieved = tx.get_mint_quote_by_request(&request).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, mint_quote.id);
    assert_eq!(retrieved.request, request);
    tx.commit().await.unwrap();
}

/// Test get mint quote by request lookup id within transaction
pub async fn get_mint_quote_by_request_lookup_id_in_transaction<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let lookup_id = PaymentIdentifier::CustomId(unique_string());
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        lookup_id.clone(),
        None,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    // Add quote
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_mint_quote(mint_quote.clone()).await.unwrap();
    tx.commit().await.unwrap();

    // Get by request lookup id within transaction
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let retrieved = tx
        .get_mint_quote_by_request_lookup_id(&lookup_id)
        .await
        .unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, mint_quote.id);
    assert_eq!(retrieved.request_lookup_id, lookup_id);
    tx.commit().await.unwrap();
}

/// Test getting blind signatures within transaction
pub async fn get_blind_signatures_in_transaction<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    use std::str::FromStr;

    let keyset_id = Id::from_str("001711afb1de20cb").unwrap();
    let blinded_message = SecretKey::generate().public_key();

    let sig = BlindSignature {
        amount: Amount::from(100u64),
        keyset_id,
        c: SecretKey::generate().public_key(),
        dleq: None,
    };

    // Add blind signature
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_blind_signatures(&[blinded_message], std::slice::from_ref(&sig), None)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Get blind signature within transaction
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let retrieved = tx.get_blind_signatures(&[blinded_message]).await.unwrap();
    assert_eq!(retrieved.len(), 1);
    assert!(retrieved[0].is_some());
    let retrieved_sig = retrieved[0].as_ref().unwrap();
    assert_eq!(retrieved_sig.amount, sig.amount);
    tx.commit().await.unwrap();
}

/// Test getting melt quotes by request lookup id
pub async fn get_melt_quotes_by_request_lookup_id<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let lookup_id = PaymentIdentifier::CustomId(unique_string());

    let quote1 = MeltQuote::new(
        None,
        MeltPaymentRequest::Bolt11 {
            bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap()
        },
        cashu::CurrencyUnit::Sat,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(10, cashu::CurrencyUnit::Sat),
        0,
        Some(lookup_id.clone()),
        None,
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        Some(serde_json::json!({"item": 1})),
        None,
    );

    let quote2 = MeltQuote::new(
        None,
        MeltPaymentRequest::Bolt11 {
            bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap()
        },
        cashu::CurrencyUnit::Sat,
        Amount::new(200, cashu::CurrencyUnit::Sat),
        Amount::new(20, cashu::CurrencyUnit::Sat),
        0,
        Some(lookup_id.clone()),
        None,
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        Some(serde_json::json!({"item": 2})),
        None,
    );

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_melt_quote(quote1.clone()).await.unwrap();
    tx.add_melt_quote(quote2.clone()).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let retrieved = tx
        .get_melt_quotes_by_request_lookup_id(&lookup_id)
        .await
        .unwrap();

    assert_eq!(retrieved.len(), 2);

    let retrieved_quote1 = retrieved.iter().find(|q| q.id == quote1.id).unwrap();
    let retrieved_quote2 = retrieved.iter().find(|q| q.id == quote2.id).unwrap();

    assert_eq!(
        retrieved_quote1.extra_json,
        Some(serde_json::json!({"item": 1}))
    );
    assert_eq!(
        retrieved_quote2.extra_json,
        Some(serde_json::json!({"item": 2}))
    );

    tx.commit().await.unwrap();
}

/// Test lock melt quote and related
pub async fn lock_melt_quote_and_related<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let lookup_id = PaymentIdentifier::CustomId(unique_string());

    let quote1 = MeltQuote::new(
        None,
        MeltPaymentRequest::Bolt11 {
            bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap()
        },
        cashu::CurrencyUnit::Sat,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(10, cashu::CurrencyUnit::Sat),
        0,
        Some(lookup_id.clone()),
        None,
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        Some(serde_json::json!({"target": true})),
        None,
    );

    let quote2 = MeltQuote::new(
        None,
        MeltPaymentRequest::Bolt11 {
            bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap()
        },
        cashu::CurrencyUnit::Sat,
        Amount::new(200, cashu::CurrencyUnit::Sat),
        Amount::new(20, cashu::CurrencyUnit::Sat),
        0,
        Some(lookup_id.clone()),
        None,
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        Some(serde_json::json!({"target": false})),
        None,
    );

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_melt_quote(quote1.clone()).await.unwrap();
    tx.add_melt_quote(quote2.clone()).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let locked = tx.lock_melt_quote_and_related(&quote1.id).await.unwrap();

    assert!(locked.target.is_some());
    let target = locked.target.unwrap();
    assert_eq!(target.id, quote1.id);
    assert_eq!(target.extra_json, Some(serde_json::json!({"target": true})));

    assert_eq!(locked.all_related.len(), 2);

    let retrieved_quote1 = locked
        .all_related
        .iter()
        .find(|q| q.id == quote1.id)
        .unwrap();
    let retrieved_quote2 = locked
        .all_related
        .iter()
        .find(|q| q.id == quote2.id)
        .unwrap();

    assert_eq!(
        retrieved_quote1.extra_json,
        Some(serde_json::json!({"target": true}))
    );
    assert_eq!(
        retrieved_quote2.extra_json,
        Some(serde_json::json!({"target": false}))
    );

    tx.commit().await.unwrap();
}

/// Test that duplicate payment IDs are rejected
pub async fn reject_duplicate_payment_ids<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(1000, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    // Add quote
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_mint_quote(mint_quote.clone()).await.unwrap();
    tx.commit().await.unwrap();

    // First payment with payment_id "payment_1"
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx
        .get_mint_quote(&mint_quote.id)
        .await
        .expect("valid quote")
        .expect("valid result");
    mint_quote
        .add_payment(
            Amount::from(300).with_unit(CurrencyUnit::Sat),
            "payment_1".to_string(),
            None,
        )
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();
    assert_eq!(mint_quote.amount_paid().value(), 300);
    tx.commit().await.unwrap();

    // Try to add the same payment_id again - should fail with DuplicatePaymentId error
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx
        .get_mint_quote(&mint_quote.id)
        .await
        .expect("valid quote")
        .expect("valid result");

    let result = mint_quote.add_payment(
        Amount::from(300).with_unit(CurrencyUnit::Sat),
        "payment_1".to_string(),
        None,
    );

    assert!(
        matches!(result.unwrap_err(), crate::Error::DuplicatePaymentId),
        "Duplicate payment_id should be rejected"
    );
    tx.rollback().await.unwrap();

    // Verify that the amount_paid is still 300 (not 600)
    let retrieved = db.get_mint_quote(&mint_quote.id).await.unwrap().unwrap();
    assert_eq!(retrieved.amount_paid().value(), 300);

    // A different payment_id should succeed
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let mut mint_quote = tx
        .get_mint_quote(&mint_quote.id)
        .await
        .expect("valid quote")
        .expect("valid result");

    mint_quote
        .add_payment(
            Amount::from(200).with_unit(CurrencyUnit::Sat),
            "payment_2".to_string(),
            None,
        )
        .unwrap();
    tx.update_mint_quote(&mut mint_quote).await.unwrap();

    assert_eq!(mint_quote.amount_paid().value(), 500);
    tx.commit().await.unwrap();

    // Verify final state
    let retrieved = db.get_mint_quote(&mint_quote.id).await.unwrap().unwrap();
    assert_eq!(retrieved.amount_paid().value(), 500);
}

/// Test that loading the quote first allows modifications
pub async fn modify_mint_quote_after_loading_succeeds<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let mint_quote = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(1000, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_mint_quote(mint_quote.clone()).await.unwrap();
    tx.commit().await.unwrap();

    // Now load the quote first, then modify it
    let mut tx = Database::begin_transaction(&db).await.unwrap();

    // First load the quote (this should lock it)
    let mut loaded_quote = tx
        .get_mint_quote(&mint_quote.id)
        .await
        .unwrap()
        .expect("quote should exist");

    // Now modification should succeed
    loaded_quote
        .add_payment(
            Amount::from(100).with_unit(CurrencyUnit::Sat),
            unique_string(),
            None,
        )
        .unwrap();
    let result = tx.update_mint_quote(&mut loaded_quote).await;

    assert!(
        result.is_ok(),
        "Modifying after loading should succeed, got: {:?}",
        result.err()
    );

    tx.commit().await.unwrap();

    // Verify the modification was persisted
    let retrieved = db.get_mint_quote(&mint_quote.id).await.unwrap().unwrap();
    assert_eq!(retrieved.amount_paid().value(), 100);
}

/// Test getting multiple mint quotes by IDs
pub async fn get_mint_quotes_by_ids<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let quote1 = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    let quote2 = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(200, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    // Add quotes
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    tx.add_mint_quote(quote1.clone()).await.unwrap();
    tx.add_mint_quote(quote2.clone()).await.unwrap();
    tx.commit().await.unwrap();

    // 1. Test getting both quotes
    let ids = vec![quote1.id.clone(), quote2.id.clone()];
    let quotes = db.get_mint_quotes_by_ids(&ids).await.unwrap();
    assert_eq!(quotes.len(), 2);
    assert!(quotes[0].is_some());
    assert!(quotes[1].is_some());
    assert_eq!(quotes[0].as_ref().unwrap().id, quote1.id);
    assert_eq!(quotes[1].as_ref().unwrap().id, quote2.id);

    // 2. Test getting with missing ID
    let missing_id = QuoteId::new();
    let ids = vec![quote1.id.clone(), missing_id, quote2.id.clone()];
    let quotes = db.get_mint_quotes_by_ids(&ids).await.unwrap();
    assert_eq!(quotes.len(), 3);
    assert!(quotes[0].is_some());
    assert!(quotes[1].is_none());
    assert!(quotes[2].is_some());
    assert_eq!(quotes[0].as_ref().unwrap().id, quote1.id);
    assert_eq!(quotes[2].as_ref().unwrap().id, quote2.id);

    // 3. Test empty list
    let quotes = db.get_mint_quotes_by_ids(&[]).await;
    assert!(quotes.is_err());

    // 4. Test within transaction (with locking)
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    let ids = vec![quote2.id.clone(), quote1.id.clone()]; // Reverse order
    let quotes = tx.get_mint_quotes_by_ids(&ids).await.unwrap();
    assert_eq!(quotes.len(), 2);
    assert_eq!(quotes[0].as_ref().unwrap().id, quote2.id);
    assert_eq!(quotes[1].as_ref().unwrap().id, quote1.id);
    tx.commit().await.unwrap();
}

/// Test concurrent quote batches acquire row locks in a consistent order.
///
/// This test is invoked explicitly by the PostgreSQL suite because SQLite does
/// not provide row-level `FOR UPDATE` locking.
pub async fn concurrent_mint_quote_batches_use_consistent_lock_order(db: DynMintDatabase) {
    let quote1 = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(100, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    );
    let quote2 = MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        None,
        0,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(200, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    );

    let mut tx = db.begin_transaction().await.unwrap();
    tx.add_mint_quote(quote1.clone()).await.unwrap();
    tx.add_mint_quote(quote2.clone()).await.unwrap();
    tx.commit().await.unwrap();

    let forward = vec![quote1.id.clone(), quote2.id.clone()];
    let reverse = vec![quote2.id.clone(), quote1.id.clone()];
    let barrier = Arc::new(tokio::sync::Barrier::new(2));

    let first_db = db.clone();
    let first_barrier = Arc::clone(&barrier);
    let first = tokio::spawn(async move {
        let mut tx = first_db.begin_transaction().await?;
        first_barrier.wait().await;
        let quotes = tx.get_mint_quotes_by_ids(&forward).await?;
        tokio::time::sleep(Duration::from_millis(25)).await;
        tx.commit().await?;
        Ok::<_, Error>(quotes)
    });

    let second = tokio::spawn(async move {
        let mut tx = db.begin_transaction().await?;
        barrier.wait().await;
        let quotes = tx.get_mint_quotes_by_ids(&reverse).await?;
        tx.commit().await?;
        Ok::<_, Error>(quotes)
    });

    let (first_result, second_result) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(first, second)
    })
    .await
    .expect("reversed quote batches should not deadlock");

    let first_quotes = first_result.unwrap().unwrap();
    let second_quotes = second_result.unwrap().unwrap();
    assert_eq!(first_quotes[0].as_ref().unwrap().id, quote1.id);
    assert_eq!(first_quotes[1].as_ref().unwrap().id, quote2.id);
    assert_eq!(second_quotes[0].as_ref().unwrap().id, quote2.id);
    assert_eq!(second_quotes[1].as_ref().unwrap().id, quote1.id);
}

fn bolt11_mint_quote(expiry: u64) -> MintQuote {
    MintQuote::new(
        None,
        unique_string(),
        cashu::CurrencyUnit::Sat,
        Some(Amount::new(1000, cashu::CurrencyUnit::Sat)),
        expiry,
        PaymentIdentifier::CustomId(unique_string()),
        None,
        Amount::new(0, cashu::CurrencyUnit::Sat),
        Amount::new(0, cashu::CurrencyUnit::Sat),
        cashu::PaymentMethod::Known(KnownMethod::Bolt11),
        0,
        0,
        vec![],
        vec![],
        None,
    )
}

/// The expired unpaid quotes are read in expiry order, page by page, and stay in the database
pub async fn get_unpaid_mint_quotes_expired_before<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    let expired = [
        bolt11_mint_quote(100),
        bolt11_mint_quote(200),
        bolt11_mint_quote(200),
    ];
    let expired_paid = bolt11_mint_quote(100);
    let live = bolt11_mint_quote(10_000);
    // A quote without an expiry (a BOLT12 offer) is stored with expiry 0.
    let without_expiry = bolt11_mint_quote(0);

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    for quote in expired.iter().chain([&live, &without_expiry]) {
        tx.add_mint_quote(quote.clone()).await.unwrap();
    }
    let mut paid = tx.add_mint_quote(expired_paid.clone()).await.unwrap();
    paid.add_payment(Amount::new(1000, CurrencyUnit::Sat), unique_string(), None)
        .unwrap();
    tx.update_mint_quote(&mut paid).await.unwrap();
    tx.commit().await.unwrap();

    assert_eq!(
        db.count_unexpired_unpaid_mint_quotes(1000).await.unwrap(),
        1
    );
    assert_eq!(
        db.count_unexpired_unpaid_mint_quotes(10_000).await.unwrap(),
        0
    );

    // Expiry first, then id. Two quotes share the expiry 200.
    let mut order: Vec<(u64, String)> = expired
        .iter()
        .map(|quote| (quote.expiry, quote.id.to_string()))
        .collect();
    order.sort();

    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page = db
            .get_unpaid_mint_quotes_expired_before(1000, after.clone(), 2)
            .await
            .unwrap();
        for quote in &page {
            assert_eq!(quote.amount_paid().value(), 0);
            seen.push((quote.expiry, quote.id.to_string()));
            after = Some((quote.expiry, quote.id.clone()));
        }
        if page.len() < 2 {
            break;
        }
    }
    assert_eq!(seen, order);
    // The read deletes nothing.
    for quote in expired
        .iter()
        .chain([&expired_paid, &live, &without_expiry])
    {
        assert!(db.get_mint_quote(&quote.id).await.unwrap().is_some());
    }
    assert!(db
        .get_unpaid_mint_quotes_expired_before(100, None, 10)
        .await
        .unwrap()
        .is_empty());
}

/// The melt outflow counts pending quotes and quotes paid in the window, with their fee reserve
pub async fn melt_outflow_since<DB>(db: DB)
where
    DB: Database<Error> + KeysDatabase<Err = Error>,
{
    use cashu::MeltQuoteState;

    let melt_quote = |amount: u64| {
        MeltQuote::new(
            None,
            MeltPaymentRequest::Bolt11 {
                bolt11: "lnbc330n1p5d85skpp5344v3ktclujsjl3h09wgsfm7zytumr7h7zhrl857f5w8nv0a52zqdqqcqzzsxqyz5vqrzjqvueefmrckfdwyyu39m0lf24sqzcr9vcrmxrvgfn6empxz7phrjxvrttncqq0lcqqyqqqqlgqqqqqqgq2qsp5j3rrg8kvpemqxtf86j8tjm90wq77c7ende4e5qmrerq4xsg02vhq9qxpqysgqjltywgyk6uc5qcgwh8xnzmawl2tjlhz8d28tgp3yx8xwtz76x0jqkfh6mmq70hervjxs0keun7ur0spldgll29l0dnz3md50d65sfqqqwrwpsu".parse().unwrap()
            },
            cashu::CurrencyUnit::Sat,
            Amount::new(amount, cashu::CurrencyUnit::Sat),
            Amount::new(2, cashu::CurrencyUnit::Sat),
            0,
            None,
            None,
            cashu::PaymentMethod::Known(KnownMethod::Bolt11),
            None,
            None,
        )
    };
    let unpaid = melt_quote(1000);
    let pending = melt_quote(100);
    let paid = melt_quote(30);

    let mut tx = Database::begin_transaction(&db).await.unwrap();
    for quote in [&unpaid, &pending, &paid] {
        tx.add_melt_quote(quote.clone()).await.unwrap();
    }
    tx.commit().await.unwrap();

    let before = crate::util::unix_time();
    let mut tx = Database::begin_transaction(&db).await.unwrap();
    for (quote, states) in [
        (&pending, &[MeltQuoteState::Pending][..]),
        (&paid, &[MeltQuoteState::Pending, MeltQuoteState::Paid][..]),
    ] {
        let mut acquired = tx.get_melt_quote(&quote.id).await.unwrap().unwrap();
        for state in states {
            tx.update_melt_quote_state(&mut acquired, *state, None)
                .await
                .unwrap();
        }
    }
    tx.commit().await.unwrap();

    assert_eq!(
        db.melt_outflow_since(&CurrencyUnit::Sat, before)
            .await
            .unwrap(),
        102 + 32
    );
    // A payment before the window is not counted. A pending melt always is.
    assert_eq!(
        db.melt_outflow_since(&CurrencyUnit::Sat, before + 3600)
            .await
            .unwrap(),
        102
    );
    assert_eq!(
        db.melt_outflow_since(&CurrencyUnit::Msat, 0).await.unwrap(),
        0
    );
}
