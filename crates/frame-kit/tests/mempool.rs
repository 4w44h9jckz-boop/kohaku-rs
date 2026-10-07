//! What `exp-frames` experiment 19 found about replacing a pending transaction and about when a
//! receipt can be trusted, checked against a mocked node.

use std::time::Duration;

use alloy::{
    primitives::{Address, B256, U64, U256, b256},
    providers::ProviderBuilder,
    transports::mock::Asserter,
};
use kohaku_frame_kit::{
    Fees,
    json::FrameTxReceiptJson,
    rpc::{RpcError, wait_for_confirmed_receipt},
};
use serde_json::json;

const GWEI: u128 = 1_000_000_000;

#[test]
fn a_bump_raises_both_fees_by_ten_percent() {
    // Experiment 19's accepted replacement: 2 gwei and 1 gwei became 2.2 and 1.1.
    let fees = Fees {
        max_priority_fee_per_gas: GWEI,
        max_fee_per_gas: 2 * GWEI,
        max_fee_per_blob_gas: 7,
    };
    let bumped = fees.bumped();
    assert_eq!(bumped.max_priority_fee_per_gas, 1_100_000_000);
    assert_eq!(bumped.max_fee_per_gas, 2_200_000_000);
    assert_eq!(bumped.max_fee_per_blob_gas, 7);
}

#[test]
fn a_bump_rounds_up_so_it_is_never_under_ten_percent() {
    for fee in [1u128, 9, 11, 1_999, 1_000_000_007] {
        let up = Fees {
            max_priority_fee_per_gas: fee,
            max_fee_per_gas: fee,
            max_fee_per_blob_gas: 0,
        }
        .bumped();
        assert!(up.max_fee_per_gas * 10 >= fee * 11, "{fee}");
        assert!(
            up.max_fee_per_gas * 10 < fee * 11 + 10,
            "{fee}: more than a rounding over"
        );
    }
}

const TX: B256 = b256!("0x7ad80e97b77c814cf95b4acf08ad94107e73e94cd136c35f5e7b44cf16c74c4e");
/// Stand-ins for round 24's two blocks at height 306292, `0xe444fffe…`, which the first receipt
/// named, and `0x72d06b41…`, which the chain kept.
const MISSED: B256 = B256::repeat_byte(0xe4);
const KEPT: B256 = B256::repeat_byte(0x72);
const HEIGHT: u64 = 306_292;

fn receipt_in(block_hash: B256) -> FrameTxReceiptJson {
    FrameTxReceiptJson {
        transaction_hash: TX,
        block_hash,
        block_number: U256::from(HEIGHT),
        transaction_index: U256::ZERO,
        status: U256::from(1),
        from: Address::ZERO,
        payer: Address::ZERO,
        gas_used: U256::from(47_927),
        cumulative_gas_used: U256::from(47_927),
        effective_gas_price: U256::from(1_000_000_007),
        frame_receipts: Vec::new(),
        logs: Vec::new(),
    }
}

fn head(asserter: &Asserter, number: u64) {
    asserter.push_success(&U64::from(number));
}

fn block(asserter: &Asserter, hash: B256) {
    asserter.push_success(&json!({ "hash": hash, "number": U64::from(HEIGHT) }));
}

async fn confirm(asserter: Asserter) -> Result<FrameTxReceiptJson, RpcError> {
    let provider = ProviderBuilder::new().connect_mocked_client(asserter);
    wait_for_confirmed_receipt(
        &provider,
        TX,
        Duration::from_secs(5),
        Duration::from_millis(1),
    )
    .await
}

#[tokio::test]
async fn waits_for_a_child_block() {
    let asserter = Asserter::new();
    asserter.push_success(&None::<FrameTxReceiptJson>); // still pending
    asserter.push_success(&receipt_in(KEPT));
    head(&asserter, HEIGHT); // nothing built on it yet
    asserter.push_success(&receipt_in(KEPT));
    head(&asserter, HEIGHT + 1);
    block(&asserter, KEPT);
    assert_eq!(confirm(asserter.clone()).await.unwrap().block_hash, KEPT);
    assert!(
        asserter.read_q().is_empty(),
        "every mocked response consumed"
    );
}

#[tokio::test]
async fn does_not_trust_a_receipt_from_a_block_that_was_replaced() {
    // Experiment 19, round 24: the receipt named one block at 306292, the chain kept another,
    // and a later receipt named the kept one.
    let asserter = Asserter::new();
    asserter.push_success(&receipt_in(MISSED));
    head(&asserter, HEIGHT + 1);
    block(&asserter, KEPT);
    asserter.push_success(&receipt_in(KEPT));
    head(&asserter, HEIGHT + 1);
    block(&asserter, KEPT);
    assert_eq!(confirm(asserter.clone()).await.unwrap().block_hash, KEPT);
    assert!(
        asserter.read_q().is_empty(),
        "every mocked response consumed"
    );
}

#[tokio::test]
async fn gives_up_at_the_timeout() {
    let asserter = Asserter::new();
    let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
    for _ in 0..1_000 {
        asserter.push_success(&None::<FrameTxReceiptJson>);
    }
    let err = wait_for_confirmed_receipt(
        &provider,
        TX,
        Duration::from_millis(20),
        Duration::from_millis(1),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, RpcError::Timeout(h, _) if h == TX));
}
