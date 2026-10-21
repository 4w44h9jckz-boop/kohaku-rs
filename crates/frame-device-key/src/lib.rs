//! Notes of private owned state whose owner is a P-256 key, as `exp-frames` experiment 50
//! deployed them on the ethrex Hegota testnet.
//!
//! Experiment 32's registry lets whoever holds a note's secrets spend it. Here the note also
//! names an owner key, the kind a device's secure element holds, and the registry's `VERIFY`
//! checks that key's signature over the transaction:
//!
//! ```text
//! inner = H(nullifierSecret, secret, owner)      owner = keccak256(qx || qy)[12:]
//! leaf  = H(tag, inner, state)                   (experiment 32's)
//! ```
//!
//! The kernel proof makes `owner` its seventh public input, and the update carries it in word 6,
//! where experiment 32's pair carried its link. Signature entry 0 is either
//!
//! - `ARBITRARY`, 128 bytes `r || s || qx || qy`: the registry checks the key's address, low `s`,
//!   and calls EIP-7951's `P256VERIFY` at `0x100` over the signature hash; or
//! - `P256`, with `signer` = the owner: the protocol checks it, the registry its signer.
//!
//! The owner key in experiment 50 is a software key. This crate signs with a software key too:
//! what a real enclave would be asked for is exactly [`sign_update`]'s one call, a P-256
//! signature over a 32-byte digest it is handed.
//!
//! The Yul source in `contracts/` is copied from experiment 50, and the `.hex` beside it is its
//! creation code as solc 0.8.37 compiles it (EVM version osaka, optimizer on, 200 runs), from
//! `exp-frames`' `compileYul`. `kernel.vkey.json` is the experiment's kernel key.

use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use kohaku_frame_accounts::contracts::{create2_address, deploy_frame, word};
use kohaku_frame_kit::{
    Fees, Frame, FrameSignature, FrameTx,
    constants::{NEW_ACCOUNT_STATE_GAS, STORAGE_SET_STATE_GAS, approve, scheme},
};
use kohaku_frame_pool::withdrawal::recent_root_frame;
use kohaku_frame_registry::{
    Secrets, Update,
    groth16::VerifyingKey,
    note::field,
    update::{INSERT_EXECUTION, INSERT_STATE, UPDATE_EXECUTION, binding, update_calldata},
};
use kohaku_tornadocash::{Field, mimc_sponge};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey as P256Key, signature::hazmat::PrehashVerifier,
};
use serde::Deserialize;

/// The registry's `VERIFY` budget: experiment 32's 260,000 and room for the owner check (the
/// testnet measured 243,379 at most).
pub const VERIFY_EXECUTION: u64 = 280_000;

/// `OwnedStateRegistryV3.yul`. Initcode: code `||` hasher `||` verifier `||` root salt `||`
/// keyed.
///
/// # Panics
///
/// Never: the code is embedded, and a test deploys it at the testnet's address.
#[must_use]
pub fn registry_v3_code() -> Vec<u8> {
    hex::decode(include_str!("../contracts/OwnedStateRegistryV3.hex").trim())
        .expect("embedded creation code is hex")
}

/// Experiment 50's kernel key, as snarkjs exported it: seven public inputs.
///
/// # Panics
///
/// Never: the key is embedded, and a test parses it.
#[must_use]
pub fn kernel_key() -> VerifyingKey {
    #[derive(Deserialize)]
    struct Json {
        #[serde(rename = "nPublic")]
        n_public: usize,
        vk_alpha_1: Vec<String>,
        vk_beta_2: Vec<Vec<String>>,
        vk_gamma_2: Vec<Vec<String>>,
        vk_delta_2: Vec<Vec<String>>,
        #[serde(rename = "IC")]
        ic: Vec<Vec<String>>,
    }
    let j: Json = serde_json::from_str(include_str!("../contracts/kernel.vkey.json"))
        .expect("embedded verifying key is JSON");
    let n = |s: &String| U256::from_str_radix(s, 10).expect("a decimal field element");
    let g1 = |p: &[String]| [n(&p[0]), n(&p[1])];
    // EIP-197's order: x1, x0, y1, y0.
    let g2 = |p: &[Vec<String>]| [n(&p[0][1]), n(&p[0][0]), n(&p[1][1]), n(&p[1][0])];
    assert_eq!(j.ic.len(), j.n_public + 1);
    VerifyingKey {
        alpha: g1(&j.vk_alpha_1),
        beta: g2(&j.vk_beta_2),
        gamma: g2(&j.vk_gamma_2),
        delta: g2(&j.vk_delta_2),
        ic: j.ic.iter().map(|p| g1(p)).collect(),
    }
}

/// A version 3 registry. `keyed = false` is the control, which skips the owner check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryV3 {
    pub hasher: Address,
    pub verifier: Address,
    pub root_salt: B256,
    pub salt: B256,
    pub keyed: bool,
}

impl RegistryV3 {
    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut code = registry_v3_code();
        code.extend_from_slice(&word(self.hasher));
        code.extend_from_slice(&word(self.verifier));
        code.extend_from_slice(self.root_salt.as_slice());
        code.extend_from_slice(&U256::from(u8::from(self.keyed)).to_be_bytes::<32>());
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

    /// `keccak256(registry || root_salt)`.
    #[must_use]
    pub fn source_id(&self) -> B256 {
        let mut buf = [0u8; 52];
        buf[..20].copy_from_slice(self.address().as_slice());
        buf[20..].copy_from_slice(self.root_salt.as_slice());
        keccak256(buf)
    }
}

/// A P-256 key's address, `keccak256(qx || qy)[12:]`, as the number the note commits to.
#[must_use]
pub fn owner_of(key: &P256Key) -> U256 {
    U256::from_be_slice(kohaku_frame_kit::sign::p256_address(key).as_slice())
}

/// `H(nullifierSecret, secret, owner)`.
#[must_use]
pub fn inner(secrets: &Secrets, owner: U256) -> Field {
    mimc_sponge(&[secrets.nullifier_secret, secrets.secret, field(owner)])
}

/// An update's owner: word 6, where experiment 32's [`Update`] keeps its `link`.
#[must_use]
pub fn owner(update: &Update) -> U256 {
    update.link
}

/// The kernel's seven public inputs for `update` against `root`:
/// root, nullifier, newCommitment, tag, withdrawn, binding, owner, with
/// binding = `keccak256(recipient || fee || owner) >> 8`.
#[must_use]
pub fn public_inputs(update: &Update, root: U256) -> [U256; 7] {
    [
        root,
        update.nullifier,
        update.new_commitment,
        update.tag,
        update.withdrawn,
        binding(update.recipient, update.fee, update.link, None),
        update.link,
    ]
}

/// How the owner's signature travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// An `ARBITRARY` entry, checked by the registry with `P256VERIFY`.
    Arbitrary,
    /// A `P256` entry with the owner as signer, checked by the protocol.
    P256,
    /// No signature: the control registry.
    None,
}

/// The update transaction, its signature entry left empty for [`sign_update`].
#[must_use]
pub fn update_tx(
    registry: &RegistryV3,
    chain_id: u64,
    root: U256,
    slot: u64,
    update: &Update,
    route: Route,
    fees: Fees,
) -> FrameTx {
    let inserts = u64::from(!update.new_commitment.is_zero());
    let payouts = u64::from(update.withdrawn > update.fee);
    let owner_address = Address::from_slice(&update.link.to_be_bytes::<32>()[12..]);
    let signatures = match route {
        Route::Arbitrary => vec![FrameSignature {
            scheme: scheme::ARBITRARY,
            ..FrameSignature::default()
        }],
        Route::P256 => vec![FrameSignature {
            scheme: scheme::P256,
            signer: Some(owner_address),
            ..FrameSignature::default()
        }],
        Route::None => vec![],
    };
    FrameTx {
        chain_id,
        nonce_keys: vec![update.nullifier],
        nonce_seq: 0,
        sender: registry.address(),
        frames: vec![
            recent_root_frame(registry.source_id(), slot, root.into()),
            Frame::verify(approve::EXECUTION_AND_PAYMENT, None)
                .with_execution(VERIFY_EXECUTION)
                .with_state(STORAGE_SET_STATE_GAS),
            Frame::sender(Some(registry.address()))
                .with_data(update_calldata(root, std::slice::from_ref(update)))
                .with_execution(UPDATE_EXECUTION + INSERT_EXECUTION * inserts)
                .with_state(NEW_ACCOUNT_STATE_GAS * payouts + INSERT_STATE * inserts),
        ],
        signatures,
        fees,
        blob_versioned_hashes: vec![],
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OwnerError {
    #[error("expected exactly one signature entry, with an empty msg")]
    Entry,
    #[error("an ARBITRARY entry must be 128 bytes: r || s || qx || qy")]
    Length,
    #[error("the key's address is not the update's owner")]
    NotOwner,
    #[error("s is above half the curve order")]
    HighS,
    #[error("P-256: {0}")]
    P256(#[from] p256::ecdsa::Error),
}

/// Fill entry 0 with `key`'s signature over the signature hash, `r || s || qx || qy` with low
/// `s`. The one request a device's secure element would serve: sign this 32-byte digest.
pub fn sign_update(tx: &mut FrameTx, key: &SigningKey) -> Result<(), OwnerError> {
    let digest = tx.sig_hash();
    let sig: Signature = key.sign_prehash_low_s(digest.as_slice())?;
    let point = key.verifying_key().to_encoded_point(false);
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&sig.to_bytes());
    out.extend_from_slice(&point.as_bytes()[1..]);
    tx.signatures
        .first_mut()
        .ok_or(OwnerError::Entry)?
        .signature = Bytes::from(out);
    Ok(())
}

trait LowS {
    fn sign_prehash_low_s(&self, digest: &[u8]) -> Result<Signature, p256::ecdsa::Error>;
}

impl LowS for SigningKey {
    fn sign_prehash_low_s(&self, digest: &[u8]) -> Result<Signature, p256::ecdsa::Error> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: Signature = self.sign_prehash(digest)?;
        Ok(sig.normalize_s().unwrap_or(sig))
    }
}

/// What the version 3 registry checks of entry 0, offline: one entry with an empty msg; for
/// `ARBITRARY`, 128 bytes whose key's address is `owner`, low `s`, and a valid signature over
/// the signature hash; for `P256`, its signer is `owner` and the same signature checks.
pub fn check_owner(tx: &FrameTx, owner: U256) -> Result<(), OwnerError> {
    let [entry] = tx.signatures.as_slice() else {
        return Err(OwnerError::Entry);
    };
    if !entry.msg.is_empty() {
        return Err(OwnerError::Entry);
    }
    if entry.scheme == scheme::P256
        && entry.signer.map(|a| U256::from_be_slice(a.as_slice())) != Some(owner)
    {
        return Err(OwnerError::NotOwner);
    }
    if entry.scheme != scheme::ARBITRARY && entry.scheme != scheme::P256 {
        return Err(OwnerError::Entry);
    }
    let sig = entry.signature.as_ref();
    if sig.len() != 128 {
        return Err(OwnerError::Length);
    }
    let mut point = [0u8; 65];
    point[0] = 0x04;
    point[1..].copy_from_slice(&sig[64..]);
    let key = P256Key::from_sec1_bytes(&point)?;
    if owner_of(&key) != owner {
        return Err(OwnerError::NotOwner);
    }
    let signature = Signature::from_slice(&sig[..64])?;
    if signature.normalize_s().is_some() {
        return Err(OwnerError::HighS);
    }
    key.verify_prehash(tx.sig_hash().as_slice(), &signature)?;
    Ok(())
}
