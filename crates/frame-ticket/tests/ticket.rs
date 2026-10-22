//! A ticket end to end, offline: the DKG, a blind issuance, the unblinded signature, and the
//! steps the paymaster takes to hash the message, against Commonware's hash.

use alloy::primitives::{Address, B256, U256};
use kohaku_frame_ticket::{
    Claim, Committee, Slot, Ticket, blind,
    issuers::{Count, Ledger, request_id},
    ticket::{NAMESPACE, g1_eip2537},
};
use rand::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};

fn claim() -> Claim {
    Claim {
        slot: Slot {
            chain_id: 8141,
            sender: Address::repeat_byte(0x11),
            nonce_keys: vec![U256::ZERO],
            nonce_seq: 0,
        },
        epoch: 4_667_918,
        salt: B256::repeat_byte(0x22),
    }
}

#[test]
fn a_quorum_of_blind_answers_unblinds_to_the_committees_signature() {
    let mut rng = StdRng::seed_from_u64(7);
    let mut committee = Committee::dkg(&mut rng, 4).unwrap();
    assert_eq!(committee.quorum(), 3);
    let claim = claim();
    let (b, r) = blind::blind(&mut rng, NAMESPACE, &claim.message());
    let answers: Vec<_> = committee.issuers[1..]
        .iter_mut()
        .map(|i| i.answer(&b))
        .collect();
    for a in &answers {
        blind::check_answer(&committee.sharing, &b, a).unwrap();
    }
    let ticket = Ticket {
        signature: blind::unblind(&committee.sharing, &answers, &r).unwrap(),
        claim: claim.clone(),
    };
    ticket.verify(&committee.sharing).unwrap();
    // What the issuers saw is not the point the signature is on.
    assert_ne!(b, claim.point());
    for i in &committee.issuers[1..] {
        assert_eq!(i.transcript, vec![b]);
    }
    // Two answers are not enough.
    assert!(blind::unblind(&committee.sharing, &answers[..2], &r).is_err());
    // The pay data reads back.
    let back = Ticket::from_pay_data(claim.slot.clone(), &ticket.pay_data()).unwrap();
    assert_eq!(back, ticket);
}

/// RFC 9380's `expand_message_xmd` with SHA-256, as `TicketPaymaster.yul` computes it.
fn expand(msg: &[u8], dst: &[u8], len: usize) -> Vec<u8> {
    let dst_prime = [dst, &[dst.len() as u8]].concat();
    let b0 = Sha256::new()
        .chain_update([0u8; 64])
        .chain_update(msg)
        .chain_update((len as u16).to_be_bytes())
        .chain_update([0u8])
        .chain_update(&dst_prime)
        .finalize();
    let mut out = vec![];
    let mut prev = [0u8; 32];
    for i in 1..=len.div_ceil(32) {
        let x: Vec<u8> = b0.iter().zip(prev).map(|(a, b)| a ^ b).collect();
        let bi = Sha256::new()
            .chain_update(&x)
            .chain_update([i as u8])
            .chain_update(&dst_prime)
            .finalize();
        prev.copy_from_slice(&bi);
        out.extend_from_slice(&bi);
    }
    out.truncate(len);
    out
}

#[test]
fn the_paymasters_hash_steps_give_commonwares_point() {
    let claim = claim();
    let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
    // union_unique: the namespace's length as a varint, the namespace, the message.
    let msg = [&[NAMESPACE.len() as u8], NAMESPACE, &claim.message()[..]].concat();
    let uniform = expand(&msg, dst, 128);
    let p = num_bigint::BigUint::parse_bytes(
        b"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
        16,
    )
    .unwrap();
    let mut points = vec![];
    for chunk in uniform.chunks(64) {
        let u = num_bigint::BigUint::from_bytes_be(chunk) % &p;
        let mut be = [0u8; 48];
        let bytes = u.to_bytes_be();
        be[48 - bytes.len()..].copy_from_slice(&bytes);
        let mut fp = blst::blst_fp::default();
        let mut q = blst::blst_p1::default();
        // SAFETY: valid pointers to initialized values; blst_map_to_g1 is RFC 9380's
        // map_to_curve followed by clear_cofactor, what EIP-2537's MAP_FP_TO_G1 computes.
        unsafe {
            blst::blst_fp_from_bendian(&raw mut fp, be.as_ptr());
            blst::blst_map_to_g1(&raw mut q, &raw const fp, std::ptr::null());
        }
        points.push(q);
    }
    let mut sum = blst::blst_p1::default();
    let mut affine = blst::blst_p1_affine::default();
    let mut ser = [0u8; 96];
    // SAFETY: valid pointers to initialized values.
    unsafe {
        blst::blst_p1_add_or_double(&raw mut sum, &raw const points[0], &raw const points[1]);
        blst::blst_p1_to_affine(&raw mut affine, &raw const sum);
        blst::blst_p1_affine_serialize(ser.as_mut_ptr(), &raw const affine);
    }
    let want = g1_eip2537(&claim.point());
    assert_eq!(&want[16..64], &ser[..48]);
    assert_eq!(&want[80..], &ser[48..]);
}

/// Issue one ticket per quorum in `quorums` to a buyer who bought `bought`, counting as `count`:
/// how many valid tickets the buyer ends with.
fn collect(count: Count, bought: u64, quorums: &[[usize; 3]]) -> usize {
    let mut rng = StdRng::seed_from_u64(11);
    let mut committee = Committee::dkg(&mut rng, 4).unwrap();
    let buyer = Address::repeat_byte(0xbb);
    let mut ledger = Ledger::new([(buyer, bought)].into());
    let mut valid = 0;
    for (t, quorum) in quorums.iter().enumerate() {
        let mut claim = claim();
        claim.salt = B256::with_last_byte(t as u8);
        let (b, r) = blind::blind(&mut rng, NAMESPACE, &claim.message());
        let mut answers = vec![];
        for &i in quorum {
            if ledger.admit(count, i, buyer, request_id(&b)).is_ok() {
                answers.push(committee.issuers[i].answer(&b));
            }
        }
        if let Ok(signature) = blind::unblind(&committee.sharing, &answers, &r)
            && (Ticket { claim, signature })
                .verify(&committee.sharing)
                .is_ok()
        {
            valid += 1;
        }
    }
    valid
}

#[test]
fn issuers_who_count_alone_issue_more_tickets_than_were_bought() {
    // Every issuer answers the buyer three times, once per quorum it is in.
    let quorums = [[0, 1, 2], [0, 1, 3], [0, 2, 3], [1, 2, 3]];
    assert_eq!(collect(Count::PerIssuer, 3, &quorums), 4);
    assert_eq!(collect(Count::Shared, 3, &quorums), 3);
}
