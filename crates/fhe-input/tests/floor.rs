//! The floor at tfhe-rs's parameters, as `exp-frames` experiment 41 records it, and a proof on
//! BLS12-381 made and verified.

use kohaku_fhe_input::{KECCAK_F_FLOOR_GAS, PkeParams, eip2537, floor, run};
use tfhe_zk_pok::{curve_api::Bls12_381, proofs::ComputeLoad};

#[test]
fn the_floor_at_one_block_is_above_both_budgets() {
    let f = floor(&PkeParams::tfhe_zkv2(1));
    assert_eq!(eip2537::g2_msm(128), 1_509_120);
    assert_eq!(eip2537::pairing(8), 298_500);
    assert_eq!(KECCAK_F_FLOOR_GAS, 504);
    assert_eq!(f.squeezed_bytes, 525_056);
    assert_eq!(f.absorbed_bytes, 49_160);
    assert_eq!(f.permutations, 4_223);
    assert_eq!(f.total_gas, 3_936_012);
    assert!(f.g2_msm_gas + f.pairing_gas > 500_000);
}

// Ignored in debug builds: a CRS at dimension 2048 and a proof take minutes unoptimised.
#[test]
#[ignore = "release mode: cargo test --release -p kohaku-fhe-input -- --ignored"]
fn a_proof_on_bls12_381_verifies_and_a_changed_ciphertext_does_not() {
    let r = run::<Bls12_381>("BLS12-381", &PkeParams::tfhe_zkv2(1), ComputeLoad::Proof, 7);
    assert!(r.verified);
    assert!(r.tampered_refused);
    assert_eq!((r.d, r.k, r.n), (2048, 1, 5892));
}
