//! The chain's end of `exp-frames` experiment 51: an output of a remote enclave, SIMULATED,
//! accepted in a `VERIFY` frame on its attestation or on its zero-knowledge proof.
//!
//! The enclave compares two 64-bit bids encrypted to its Baby Jubjub key and returns one bit.
//! The outcome contract is its own sender and payer and records the output after checking:
//!
//! - route 1, **attestation**: a P-256 signature by the attestation key fixed in its code over
//!   `keccak256("exp-frames/51/attest" || measurement || pk.x || pk.y || inputs || out)`,
//!   checked with `P256VERIFY`. It binds whatever the key signs, and only that;
//! - route 2, **proof**: a Groth16 proof that `out` is the comparison of what the two
//!   ciphertexts decrypt to under the secret key of `pk`. It names no code and no machine.
//!
//! Neither shows that nobody read the bids: the proof needs the decryption key to be made.
//!
//! The Yul source in `contracts/` is experiment 51's, the `.hex` its creation code from
//! `exp-frames`' `compileYul` (solc 0.8.37, EVM version osaka, optimizer on, 200 runs), and
//! `enclave.vkey.json` the comparison circuit's key.

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    sol_types::SolCall,
};
use kohaku_frame_accounts::contracts::{create2_address, deploy_frame};
use kohaku_frame_kit::{
    Fees, Frame, FrameTx,
    constants::{STORAGE_SET_STATE_GAS, approve},
};
use kohaku_frame_registry::groth16::VerifyingKey;
use p256::{
    EncodedPoint,
    ecdsa::{Signature, VerifyingKey as P256Key, signature::hazmat::PrehashVerifier},
};

/// The outcome contract's interface.
pub mod abi {
    alloy::sol! {
        function record(uint256 route, bytes32 measurement, uint256[9] statement, uint256[8] evidence);
        event Outcome(uint256 indexed route, uint256 out, bytes32 inputs, uint256 pkx, uint256 pky);
    }
}

pub const ATTESTED: u8 = 1;
pub const PROVED: u8 = 2;

/// `VERIFY`'s budget: the proof's Groth16 check with nine inputs (245,699 on the testnet).
pub const VERIFY_EXECUTION: u64 = 300_000;
pub const RECORD_EXECUTION: u64 = 30_000;

/// `EnclaveOutcome.yul`. Initcode: code `||` verifier `||` attestation qx `||` qy.
///
/// # Panics
///
/// Never: the code is embedded, and a test deploys it at the testnet's address.
#[must_use]
pub fn outcome_code() -> Vec<u8> {
    hex::decode(include_str!("../contracts/EnclaveOutcome.hex").trim())
        .expect("embedded creation code is hex")
}

/// The comparison circuit's key: nine public inputs.
///
/// # Panics
///
/// Never: the key is embedded, and a test parses it.
#[must_use]
pub fn enclave_key() -> VerifyingKey {
    kohaku_frame_device_key::snarkjs_key(include_str!("../contracts/enclave.vkey.json"))
        .expect("embedded verifying key")
}

/// The outcome contract: its verifier, and the attestation key it trusts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub verifier: Address,
    pub attestation_qx: B256,
    pub attestation_qy: B256,
    pub salt: B256,
}

impl Outcome {
    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut code = outcome_code();
        code.extend_from_slice(&kohaku_frame_accounts::contracts::word(self.verifier));
        code.extend_from_slice(self.attestation_qx.as_slice());
        code.extend_from_slice(self.attestation_qy.as_slice());
        code
    }

    #[must_use]
    pub fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    #[must_use]
    pub fn deploy_frame(&self) -> Frame {
        deploy_frame(&self.initcode(), self.salt, 0)
    }
}

/// `pk.x pk.y Ea.x Ea.y ca Eb.x Eb.y cb out`.
pub type Statement = [U256; 9];

/// `keccak256(Ea.x || Ea.y || ca || Eb.x || Eb.y || cb)`.
#[must_use]
pub fn inputs_of(s: &Statement) -> B256 {
    keccak256(words(&s[2..8]))
}

fn words(ws: &[U256]) -> Vec<u8> {
    ws.iter().flat_map(U256::to_be_bytes::<32>).collect()
}

/// What the attestation key signs.
#[must_use]
pub fn attestation_digest(measurement: B256, s: &Statement) -> B256 {
    let mut m = b"exp-frames/51/attest".to_vec();
    m.extend_from_slice(measurement.as_slice());
    m.extend_from_slice(&words(&s[..2]));
    m.extend_from_slice(inputs_of(s).as_slice());
    m.extend_from_slice(&s[8].to_be_bytes::<32>());
    keccak256(m)
}

/// The transaction's only nonce key: one output per route, enclave key and ciphertexts.
#[must_use]
pub fn nonce_key(route: u8, s: &Statement) -> U256 {
    let mut m = words(&[U256::from(route), s[0], s[1]]);
    m.extend_from_slice(inputs_of(s).as_slice());
    U256::from_be_bytes(keccak256(m).0)
}

/// One output, as the outcome contract's `VERIFY` requires it.
#[must_use]
pub fn outcome_tx(
    contract: &Outcome,
    chain_id: u64,
    route: u8,
    measurement: B256,
    statement: Statement,
    evidence: [U256; 8],
    fees: Fees,
) -> FrameTx {
    let data = abi::recordCall {
        route: U256::from(route),
        measurement,
        statement,
        evidence,
    }
    .abi_encode();
    FrameTx {
        chain_id,
        nonce_keys: vec![nonce_key(route, &statement)],
        nonce_seq: 0,
        sender: contract.address(),
        frames: vec![
            Frame::verify(approve::EXECUTION_AND_PAYMENT, None)
                .with_execution(VERIFY_EXECUTION)
                .with_state(STORAGE_SET_STATE_GAS),
            Frame::sender(Some(contract.address()))
                .with_data(Bytes::from(data))
                .with_execution(RECORD_EXECUTION),
        ],
        signatures: vec![],
        fees,
        blob_versioned_hashes: vec![],
    }
}

/// What route 1 checks: low `s`, and `P256VERIFY` of `(digest, r, s)` under the contract's key.
/// It says that the key signed; it cannot say what ran.
#[must_use]
pub fn attestation_holds(
    contract: &Outcome,
    measurement: B256,
    s: &Statement,
    r: U256,
    sig_s: U256,
) -> bool {
    let point = EncodedPoint::from_affine_coordinates(
        &contract.attestation_qx.0.into(),
        &contract.attestation_qy.0.into(),
        false,
    );
    let Ok(key) = P256Key::from_encoded_point(&point) else {
        return false;
    };
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(&r.to_be_bytes::<32>());
    rs[32..].copy_from_slice(&sig_s.to_be_bytes::<32>());
    let Ok(sig) = Signature::from_slice(&rs) else {
        return false;
    };
    sig.normalize_s().is_none()
        && key
            .verify_prehash(attestation_digest(measurement, s).as_slice(), &sig)
            .is_ok()
}

/// What route 2 checks: the Groth16 proof for the statement.
#[must_use]
pub fn proof_holds(s: &Statement, proof: &[U256; 8]) -> bool {
    enclave_key().verify(proof, s)
}
