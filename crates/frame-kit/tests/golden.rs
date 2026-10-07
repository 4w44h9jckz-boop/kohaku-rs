//! The golden vector in ethrex's `scripts/hegota-testnet/frametx.py`.

use alloy::primitives::{B256, Bytes, U256, address, b256, bytes};
use kohaku_frame_kit::{
    Fees, Frame, FrameSignature, FrameTx,
    constants::{approve, scheme},
    tx::DecodeError,
};

fn golden() -> FrameTx {
    let sender = address!("0x000000000000000000000000000000000000abcd");
    FrameTx {
        chain_id: 1,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: 7,
        sender,
        frames: vec![
            Frame::verify(approve::EXECUTION_AND_PAYMENT, None)
                .with_execution(0x5208)
                .with_data(bytes!("1122")),
            Frame::sender(Some(address!("0x0000000000000000000000000000000000001234")))
                .with_execution(0x9c40),
        ],
        signatures: vec![FrameSignature {
            scheme: scheme::SECP256K1,
            signer: Some(sender),
            msg: Bytes::new(),
            signature: vec![1u8; 65].into(),
        }],
        fees: Fees {
            max_priority_fee_per_gas: 0x3b9a_ca00,
            max_fee_per_gas: 0x6_fc23_ac00,
            max_fee_per_blob_gas: 0,
        },
        blob_versioned_hashes: vec![],
    }
}

#[test]
fn encodes_to_the_golden_rlp() {
    let expected = bytes!(
        "f8b201c1800794000000000000000000000000000000000000abcdeccc010380c48252088080821122de0280940000000000000000000000000000000000001234c4829c40808080f85cf85a0194000000000000000000000000000000000000abcd80b8410101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101cc843b9aca008506fc23ac0080c0"
    );
    assert_eq!(Bytes::from(golden().encode_payload()), expected);
}

#[test]
fn computes_the_golden_sig_hash() {
    let expected: B256 =
        b256!("0x73827d510b0029220c237a46b27f6b6b8e7a3fd3b52c42a55c6c6e343fc45951");
    assert_eq!(golden().sig_hash(), expected);
}

#[test]
fn round_trips() {
    let tx = golden();
    assert_eq!(FrameTx::decode(&tx.encode()).unwrap(), tx);
}

#[test]
fn the_sig_hash_ignores_sig_hash_signatures_only() {
    let tx = golden();
    let mut other = tx.clone();
    other.signatures[0].signature = vec![2u8; 65].into();
    assert_eq!(tx.sig_hash(), other.sig_hash());
    assert_ne!(tx.hash(), other.hash());

    // An explicit-digest signature is committed to.
    let mut explicit = tx.clone();
    explicit.signatures[0].msg = B256::repeat_byte(9).into();
    let mut explicit_other = explicit.clone();
    explicit_other.signatures[0].signature = vec![2u8; 65].into();
    assert_ne!(explicit.sig_hash(), explicit_other.sig_hash());
}

#[test]
fn rejects_non_canonical_input() {
    let raw = golden().encode();
    assert!(FrameTx::decode(&raw[1..]).is_err(), "missing type byte");
    let mut trailing = raw.to_vec();
    trailing.push(0);
    assert!(FrameTx::decode(&trailing).is_err(), "trailing byte");
    // chain_id 1 written as 0x8101 (a one-byte string for a value below 0x80).
    let mut long_form = vec![0x06];
    let payload = &raw[3..]; // after 0x06, f8 b2
    let mut body = vec![0x81, 0x01];
    body.extend_from_slice(&payload[1..]);
    long_form.push(0xf8);
    long_form.push(u8::try_from(body.len()).unwrap());
    long_form.extend(body);
    assert!(matches!(
        FrameTx::decode(&long_form),
        Err(DecodeError::Rlp(alloy::rlp::Error::NonCanonicalSingleByte))
    ));
}
