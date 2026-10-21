//! A withdrawal's witness, secret-shared for a proving committee instead of proved by the wallet.
//!
//! The withdrawal is the one the frame-native pools take (`kohaku-frame-pool`), and the circuit
//! and its websnark proving key are `kohaku-tornadocash-circuit`'s. The committee is
//! `exp-e2e-frames`' `co-withdraw`, three members running TACEO's co-groth16 REP3 prover. This
//! crate writes the format that committee fixed ("The witness's share format (fixed)",
//! `committee/co-withdraw/README.md` at `exp-e2e-frames` `c8eb5cc`):
//!
//! - the circuit's whole witness as websnark extends it: index 0 the constant 1, then the six
//!   public inputs, then every private signal;
//! - REP3 over BN254's scalar field: member `i` holds `(x_i, x_{i-1})` of `x = x_0 + x_1 + x_2`,
//!   for the private signals only; the constant and the public inputs travel in the clear;
//! - co-snarks' `CompressedRep3SharedWitness<ark_bn254::Fr>` at commit `436f63fa`, serialized with
//!   bincode 1, as `co-circom split-witness` writes it, `Replicated` or `SeededReplicated`;
//! - `share-0.bin`, `share-1.bin`, `share-2.bin` and `public.json`.
//!
//! The sharing itself is co-snarks' own `share_rep3`, unmodified; this crate only feeds it the
//! wallet's witness and writes what it returns.

use std::path::Path;

use anyhow::{Context, ensure};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use co_circom_types::{CompressedRep3SharedWitness, Compression};
use kohaku_tornadocash_circuit::CircuitInputs;
use mpc_core::protocols::rep3::Rep3ShareVecType;
use rand08::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

/// The committee's size.
pub const MEMBERS: usize = 3;

/// The constant 1 and the six public inputs: root, nullifier hash, recipient, relayer, fee,
/// refund.
pub const NUM_INSTANCE_VARIABLES: usize = 7;

/// The withdrawal circuit's whole witness: 28,300 values, 28,293 of them private.
pub const WITNESS_LEN: usize = 28_300;

/// How the replicated shares are written: in full, or as seeds a member expands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Replicated,
    SeededReplicated,
}

/// The three members' shares and the public inputs, as the committee reads them.
pub struct Shares {
    pub members: [Vec<u8>; MEMBERS],
    pub public: Public,
}

/// `public.json`: the six public inputs as decimal strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Public {
    pub inputs: Vec<String>,
}

/// The circuit's whole witness from its inputs, extended by websnark as the wallet extends it
/// before it proves alone.
pub fn extend_witness(inputs: &CircuitInputs) -> anyhow::Result<Vec<Fr>> {
    let signals = inputs.as_signals()?;
    let witness = kohaku_tornadocash_circuit::artifacts::circuit()
        .witness(signals)
        .map_err(|e| anyhow::anyhow!("witness: {e}"))?;
    let witness = witness.to_vec();
    ensure!(
        witness.len() == WITNESS_LEN,
        "the witness has {} values, the circuit {WITNESS_LEN}",
        witness.len()
    );
    ensure!(
        witness[0] == Fr::from(1u64),
        "the witness does not start with the constant 1"
    );
    Ok(witness)
}

/// Splits a whole witness into the members' shares, with co-snarks' `share_rep3`.
pub fn share<R: Rng + CryptoRng>(
    witness: &[Fr],
    encoding: Encoding,
    rng: &mut R,
) -> anyhow::Result<Shares> {
    ensure!(
        witness.len() == WITNESS_LEN,
        "the witness has {} values, the circuit {WITNESS_LEN}",
        witness.len()
    );
    let compression = match encoding {
        Encoding::Replicated => Compression::None,
        Encoding::SeededReplicated => Compression::SeededShares,
    };
    let shares = CompressedRep3SharedWitness::share_rep3(
        circom_types::Witness {
            values: witness.to_vec(),
        },
        NUM_INSTANCE_VARIABLES,
        rng,
        compression,
    );
    let mut members: [Vec<u8>; MEMBERS] = Default::default();
    for (slot, share) in members.iter_mut().zip(shares.iter()) {
        *slot = bincode::serialize(share)?;
    }
    let public = Public {
        inputs: witness[1..NUM_INSTANCE_VARIABLES]
            .iter()
            .map(decimal)
            .collect(),
    };
    Ok(Shares { members, public })
}

/// Writes `share-0.bin` to `share-2.bin` and `public.json` into `dir`. Member `i` is to receive
/// `share-i.bin` alone.
pub fn write(dir: &Path, shares: &Shares) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    for (i, share) in shares.members.iter().enumerate() {
        std::fs::write(dir.join(format!("share-{i}.bin")), share)?;
    }
    std::fs::write(
        dir.join("public.json"),
        serde_json::to_vec_pretty(&shares.public)?,
    )?;
    Ok(())
}

/// Puts the whole witness back together from all three shares, checking on the way that each
/// share is replicated as the format says: member `i`'s second component is member `i-1`'s first.
/// A check for tests and for whoever audits a run; no member can do it, since each holds one
/// share.
pub fn reconstruct(members: &[Vec<u8>; MEMBERS]) -> anyhow::Result<Vec<Fr>> {
    let mut decoded = Vec::with_capacity(MEMBERS);
    for (i, bytes) in members.iter().enumerate() {
        let share: CompressedRep3SharedWitness<Fr> =
            bincode::deserialize(bytes).with_context(|| format!("share {i}"))?;
        let values = match share.witness {
            Rep3ShareVecType::Replicated(w) => w,
            Rep3ShareVecType::SeededReplicated(seeded) => seeded
                .expand_vec()
                .map_err(|e| anyhow::anyhow!("share {i}: {e}"))?,
            Rep3ShareVecType::Additive(_) | Rep3ShareVecType::SeededAdditive(_) => {
                anyhow::bail!("share {i} is additive, which the format refuses")
            }
        };
        decoded.push((share.public_inputs, values));
    }
    let (public, first) = &decoded[0];
    ensure!(
        public.len() == NUM_INSTANCE_VARIABLES,
        "{} values in the clear, expected {NUM_INSTANCE_VARIABLES}",
        public.len()
    );
    for (i, (p, w)) in decoded.iter().enumerate() {
        ensure!(p == public, "share {i} carries different public inputs");
        ensure!(w.len() == first.len(), "share {i} has {} values", w.len());
    }
    let mut witness = public.clone();
    for k in 0..first.len() {
        for i in 0..MEMBERS {
            let prev = (i + MEMBERS - 1) % MEMBERS;
            ensure!(
                decoded[i].1[k].b == decoded[prev].1[k].a,
                "value {k}: share {i} does not replicate share {prev}"
            );
        }
        witness.push(decoded.iter().map(|(_, w)| w[k].a).sum());
    }
    Ok(witness)
}

/// A field element as a decimal string, as `public.json` carries it.
#[must_use]
pub fn decimal(x: &Fr) -> String {
    ruint::aliases::U256::from_be_slice(&x.into_bigint().to_bytes_be()).to_string()
}
