use alloy::{
    primitives::{Address, B256, U256, address},
    signers::local::PrivateKeySigner,
};
use kohaku_frame_kit::{
    Fees, Frame, FrameSigner, FrameTx, constants::approve, sign::SignError, sign_all, signer_of,
};

fn secp(n: u8) -> FrameSigner {
    FrameSigner::Secp256k1(PrivateKeySigner::from_bytes(&B256::repeat_byte(n)).unwrap())
}

fn p256(n: u8) -> FrameSigner {
    FrameSigner::P256(p256::ecdsa::SigningKey::from_slice(&[n; 32]).unwrap())
}

fn tx(sender: Address) -> FrameTx {
    FrameTx {
        chain_id: 8141,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: 3,
        sender,
        frames: vec![
            Frame::verify(approve::EXECUTION_AND_PAYMENT, None).with_execution(50_000),
            Frame::sender(Some(address!("0x0000000000000000000000000000000000001234")))
                .with_execution(21_000),
        ],
        signatures: vec![],
        fees: Fees {
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 100,
            max_fee_per_blob_gas: 0,
        },
        blob_versioned_hashes: vec![],
    }
}

#[test]
fn secp256k1_signs_the_sig_hash_with_a_bare_recovery_id() {
    let key = secp(7);
    let mut tx = tx(key.address());
    tx.signatures.push(key.placeholder(None));
    sign_all(&mut tx, std::slice::from_ref(&key)).unwrap();
    let sig = &tx.signatures[0].signature;
    assert_eq!(sig.len(), 65);
    assert!(sig[0] <= 1);
    assert_eq!(
        signer_of(&tx.signatures[0], tx.sig_hash()).unwrap(),
        key.address()
    );
}

#[test]
fn p256_signs_with_low_s_and_carries_its_key() {
    // n / 2 for secp256r1.
    let half_n = U256::from_be_slice(
        &alloy::hex::decode("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")
            .unwrap(),
    );
    for n in 1..=16 {
        let key = p256(n);
        let mut tx = tx(Address::repeat_byte(0x55));
        tx.signatures.push(key.placeholder(Some(key.address())));
        sign_all(&mut tx, std::slice::from_ref(&key)).unwrap();
        let sig = &tx.signatures[0].signature;
        assert_eq!(sig.len(), 128);
        assert!(U256::from_be_slice(&sig[32..64]) <= half_n);
        assert_eq!(
            signer_of(&tx.signatures[0], tx.sig_hash()).unwrap(),
            key.address()
        );
    }
}

#[test]
fn explicit_digests_are_signed_before_the_sig_hash() {
    // A co-signer signs a digest of its own; the sender signs the sig hash, which commits to
    // the co-signer's signature. Whatever order the keys are given in, the sender's signature
    // must be over the final envelope.
    let sender = secp(1);
    let cosigner = p256(2);
    for keys in [
        [sender.clone(), cosigner.clone()],
        [cosigner.clone(), sender.clone()],
    ] {
        let mut tx = tx(sender.address());
        let mut explicit = cosigner.placeholder(Some(cosigner.address()));
        explicit.msg = B256::repeat_byte(0xab).into();
        tx.signatures.push(sender.placeholder(None));
        tx.signatures.push(explicit);
        sign_all(&mut tx, &keys).unwrap();
        let sig_hash = tx.sig_hash();
        assert_eq!(
            signer_of(&tx.signatures[0], sig_hash).unwrap(),
            sender.address()
        );
        assert_eq!(
            signer_of(&tx.signatures[1], sig_hash).unwrap(),
            cosigner.address()
        );
    }
}

#[test]
fn a_key_with_no_entry_is_an_error() {
    let key = secp(1);
    let mut tx = tx(key.address());
    tx.signatures.push(key.placeholder(None));
    let stranger = secp(2);
    let err = sign_all(&mut tx, &[key, stranger]).unwrap_err();
    assert!(matches!(err, SignError::NoEntry { .. }));
}

#[test]
fn a_tampered_envelope_recovers_someone_else() {
    let key = secp(9);
    let mut tx = tx(key.address());
    tx.signatures.push(key.placeholder(None));
    sign_all(&mut tx, std::slice::from_ref(&key)).unwrap();
    tx.frames[1].limits.execution += 1;
    assert_ne!(
        signer_of(&tx.signatures[0], tx.sig_hash()).unwrap(),
        key.address()
    );
}
