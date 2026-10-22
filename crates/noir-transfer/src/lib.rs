//! A private transfer on Aztec's note and nullifier model, proved from Rust: `exp-frames`
//! experiment 42's wallet side.
//!
//! The circuit is `exp-frames`' `transfer.nr`, compiled by Noir 1.0.0-rc.6 into
//! `fixtures/transfer.json`. This crate does what a wallet does with it:
//!
//! - keeps the note tree, a depth-32 tree under the Poseidon2 sponge the circuit hashes with,
//!   using Noir's own Poseidon2 permutation from `bn254_blackbox_solver`;
//! - builds the circuit's witness with Noir's executor, `acvm`, both unmodified at the pinned
//!   release;
//! - proves it with Barretenberg through `barretenberg-rs`, which drives Barretenberg's `bb`
//!   binary over its msgpack interface.
//!
//! A note is `H(NOTE, owner, value, randomness)` with `owner = H(OWNER, nsk)`; spending it
//! reveals `H(NULLIFIER, note, nsk)`. The two notes a transfer spends are ordered so that their
//! nullifiers ascend, because the pool takes them as the transaction's EIP-8250 nonce keys in
//! that order.

use std::io::Read;
use std::path::Path;

use acvm::acir::circuit::Program;
use acvm::acir::native_types::{Witness, WitnessMap, WitnessStack};
use acvm::pwg::{ACVM, ACVMStatus};
use acvm::{AcirField, FieldElement};
use anyhow::{Context, anyhow, bail, ensure};
use barretenberg_rs::BarretenbergApi;
use barretenberg_rs::backends::PipeBackend;
use barretenberg_rs::generated_types::{CircuitInput, ProofSystemSettings};
use base64::Engine;
use bn254_blackbox_solver::{Bn254BlackBoxSolver, poseidon2_permutation};
use serde::{Deserialize, Serialize};

/// The note tree's depth, as `transfer.nr` fixes it.
pub const DEPTH: usize = 32;

/// Domain separators, the first input of every hash.
pub const OWNER: u128 = 1;
pub const NOTE: u128 = 2;
pub const NULLIFIER: u128 = 3;
pub const NODE: u128 = 4;

/// The compiled circuit, as Noir 1.0.0-rc.6's compiler wrote it.
pub const TRANSFER_JSON: &str = include_str!("../fixtures/transfer.json");

/// The sponge `transfer.nr` hashes with: state `[0, 0, 0, n * 2^64]`, three inputs absorbed per
/// permutation, `state[0]` out.
///
/// # Panics
///
/// Never: the permutation is only refused a state of the wrong width.
#[must_use]
pub fn hash(inputs: &[FieldElement]) -> FieldElement {
    let mut state = [
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::from((inputs.len() as u128) << 64),
    ];
    for chunk in inputs.chunks(3) {
        for (s, x) in state.iter_mut().zip(chunk) {
            *s += *x;
        }
        let out = poseidon2_permutation(&state).expect("the state has the permutation's width");
        state.copy_from_slice(&out);
    }
    state[0]
}

/// `H(OWNER, nsk)`.
#[must_use]
pub fn owner_of(nsk: FieldElement) -> FieldElement {
    hash(&[OWNER.into(), nsk])
}

/// `H(NOTE, owner, value, randomness)`.
#[must_use]
pub fn note_hash(owner: FieldElement, value: u64, randomness: FieldElement) -> FieldElement {
    hash(&[NOTE.into(), owner, u128::from(value).into(), randomness])
}

/// The note tree over the leaves the pool's `Note` events list, in index order.
pub struct Tree {
    layers: Vec<Vec<FieldElement>>,
    zeros: Vec<FieldElement>,
}

impl Tree {
    #[must_use]
    pub fn new(leaves: Vec<FieldElement>) -> Self {
        let mut zeros = vec![FieldElement::zero()];
        for level in 0..DEPTH {
            zeros.push(hash(&[NODE.into(), zeros[level], zeros[level]]));
        }
        let mut layers = vec![leaves];
        for level in 0..DEPTH {
            let below = &layers[level];
            let up = below
                .chunks(2)
                .map(|pair| hash(&[NODE.into(), pair[0], *pair.get(1).unwrap_or(&zeros[level])]))
                .collect();
            layers.push(up);
        }
        Self { layers, zeros }
    }

    #[must_use]
    pub fn root(&self) -> FieldElement {
        self.layers[DEPTH]
            .first()
            .copied()
            .unwrap_or(self.zeros[DEPTH])
    }

    #[must_use]
    pub fn leaf(&self, index: usize) -> Option<FieldElement> {
        self.layers[0].get(index).copied()
    }

    /// The siblings from the leaf up.
    #[must_use]
    pub fn path(&self, index: usize) -> Vec<FieldElement> {
        (0..DEPTH)
            .map(|level| {
                self.layers[level]
                    .get((index >> level) ^ 1)
                    .copied()
                    .unwrap_or(self.zeros[level])
            })
            .collect()
    }
}

/// A transfer to prove: the same request `exp-frames`' `build/prove.mjs` takes. Numbers are
/// decimal or `0x` hex strings.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    pub nsk: String,
    pub spend: Vec<Spend>,
    pub outs: Vec<Out>,
    pub fee: String,
    pub context: String,
    pub leaves: Vec<String>,
    pub target: Target,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Spend {
    pub index: usize,
    pub value: String,
    pub randomness: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Out {
    pub owner: String,
    pub value: String,
    pub randomness: String,
}

/// Barretenberg's two EVM verifier targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum Target {
    #[serde(rename = "evm")]
    Evm,
    #[serde(rename = "evm-no-zk")]
    EvmNoZk,
}

impl Target {
    /// The settings `bb.js` 5.2.1 uses for the target (`getProofSettingsFromOptions`).
    #[must_use]
    pub fn settings(self) -> ProofSystemSettings {
        ProofSystemSettings {
            ipa_accumulation: false,
            oracle_hash_type: "keccak".to_string(),
            disable_zk: self == Target::EvmNoZk,
            optimized_solidity_verifier: false,
        }
    }
}

/// The transfer's public inputs, in the circuit's order, and its whole input in ABI order.
#[derive(Debug, Clone)]
pub struct Transfer {
    pub root: FieldElement,
    pub nullifiers: [FieldElement; 2],
    pub out_hashes: [FieldElement; 2],
    pub fee: u64,
    pub context: FieldElement,
    /// Every parameter of `main`, flattened in declaration order: the initial witness.
    pub inputs: Vec<FieldElement>,
}

impl Transfer {
    #[must_use]
    pub fn public_inputs(&self) -> Vec<FieldElement> {
        vec![
            self.root,
            self.nullifiers[0],
            self.nullifiers[1],
            self.out_hashes[0],
            self.out_hashes[1],
            u128::from(self.fee).into(),
            self.context,
        ]
    }
}

fn field(s: &str) -> anyhow::Result<FieldElement> {
    FieldElement::try_from_str(s).ok_or_else(|| anyhow!("not a field element: {s}"))
}

fn int(s: &str) -> anyhow::Result<u64> {
    field(s)?
        .try_to_u64()
        .ok_or_else(|| anyhow!("not a u64: {s}"))
}

struct Spent {
    index: usize,
    value: u64,
    randomness: FieldElement,
    nullifier: FieldElement,
}

/// The witness's inputs for a request: the root and paths from the leaves, the nullifiers, the
/// spent notes in ascending nullifier order.
pub fn transfer(req: &Request) -> anyhow::Result<Transfer> {
    ensure!(
        req.spend.len() == 2 && req.outs.len() == 2,
        "a transfer spends two notes and creates two"
    );
    let tree = Tree::new(
        req.leaves
            .iter()
            .map(|l| field(l))
            .collect::<anyhow::Result<_>>()?,
    );
    let nsk = field(&req.nsk)?;
    let owner = owner_of(nsk);

    let mut spent = Vec::new();
    for s in &req.spend {
        let (value, randomness) = (int(&s.value)?, field(&s.randomness)?);
        let note = note_hash(owner, value, randomness);
        ensure!(
            tree.leaf(s.index) == Some(note),
            "leaf {} is not this note",
            s.index
        );
        spent.push(Spent {
            index: s.index,
            value,
            randomness,
            nullifier: hash(&[NULLIFIER.into(), note, nsk]),
        });
    }
    spent.sort_by_key(|s| s.nullifier);

    let outs = req
        .outs
        .iter()
        .map(|o| Ok((field(&o.owner)?, int(&o.value)?, field(&o.randomness)?)))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let out_hashes = [
        note_hash(outs[0].0, outs[0].1, outs[0].2),
        note_hash(outs[1].0, outs[1].1, outs[1].2),
    ];
    let fee = int(&req.fee)?;
    let context = field(&req.context)?;
    let root = tree.root();
    let nullifiers = [spent[0].nullifier, spent[1].nullifier];

    // main(root, nullifiers, out_hashes, fee, context, nsk, in_values, in_randomness, in_index,
    //      in_paths, out_owners, out_values, out_randomness)
    let mut inputs = vec![
        root,
        nullifiers[0],
        nullifiers[1],
        out_hashes[0],
        out_hashes[1],
        u128::from(fee).into(),
        context,
        nsk,
    ];
    inputs.extend(
        spent
            .iter()
            .map(|s| FieldElement::from(u128::from(s.value))),
    );
    inputs.extend(spent.iter().map(|s| s.randomness));
    inputs.extend(spent.iter().map(|s| FieldElement::from(s.index as u128)));
    for s in &spent {
        inputs.extend(tree.path(s.index));
    }
    inputs.extend(outs.iter().map(|o| o.0));
    inputs.extend(outs.iter().map(|o| FieldElement::from(u128::from(o.1))));
    inputs.extend(outs.iter().map(|o| o.2));
    Ok(Transfer {
        root,
        nullifiers,
        out_hashes,
        fee,
        context,
        inputs,
    })
}

/// The compiled circuit: the gzipped bytecode Barretenberg takes, and the program Noir's
/// executor runs.
pub struct Circuit {
    pub bytecode: Vec<u8>,
    pub program: Program<FieldElement>,
    pub noir_version: String,
}

impl Circuit {
    pub fn from_json(json: &str) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Artifact {
            noir_version: String,
            bytecode: String,
        }
        let a: Artifact = serde_json::from_str(json)?;
        let bytecode = base64::engine::general_purpose::STANDARD.decode(a.bytecode)?;
        let program = Program::deserialize_program(&bytecode)?;
        ensure!(
            program.functions.len() == 1,
            "expected one ACIR function, found {}",
            program.functions.len()
        );
        Ok(Self {
            bytecode,
            program,
            noir_version: a.noir_version,
        })
    }

    /// Runs `main` on the inputs, in parameter order, and returns the solved witness.
    pub fn execute(&self, inputs: &[FieldElement]) -> anyhow::Result<WitnessStack<FieldElement>> {
        let main = &self.program.functions[0];
        let mut parameters: Vec<Witness> = main
            .private_parameters
            .iter()
            .chain(main.public_parameters.0.iter())
            .copied()
            .collect();
        parameters.sort();
        ensure!(
            parameters.len() == inputs.len(),
            "main takes {} inputs, given {}",
            parameters.len(),
            inputs.len()
        );
        let initial = WitnessMap::from(
            parameters
                .into_iter()
                .zip(inputs.iter().copied())
                .collect::<std::collections::BTreeMap<_, _>>(),
        );
        let solver = Bn254BlackBoxSolver;
        let mut acvm = ACVM::new(
            &solver,
            &main.opcodes,
            initial,
            &self.program.unconstrained_functions,
            &main.assert_messages,
        );
        match acvm.solve() {
            ACVMStatus::Solved => Ok(WitnessStack::from(acvm.finalize())),
            ACVMStatus::Failure(e) => bail!("the circuit refused the inputs: {e}"),
            other => {
                bail!("the circuit asked for something this executor does not provide: {other}")
            }
        }
    }
}

/// A proof as Barretenberg's Solidity verifier takes it: the proof's field elements
/// concatenated, and the public inputs.
#[derive(Debug, Clone)]
pub struct Proof {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
    pub verified: bool,
}

fn gunzip(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes).read_to_end(&mut out)?;
    Ok(out)
}

/// Proves the witness with Barretenberg, through the `bb` binary at `bb`, and verifies the proof
/// with the verification key Barretenberg returns.
pub fn prove(
    bb: &Path,
    circuit: &Circuit,
    witness: &WitnessStack<FieldElement>,
    target: Target,
) -> anyhow::Result<Proof> {
    let backend =
        PipeBackend::new(bb, None).with_context(|| format!("starting {}", bb.display()))?;
    let mut api = BarretenbergApi::new(backend);
    let input = CircuitInput {
        name: "transfer".to_string(),
        bytecode: gunzip(&circuit.bytecode)?,
        verification_key: vec![],
    };
    let witness = gunzip(&witness.serialize()?)?;
    let proved = api.circuit_prove(input, &witness, target.settings())?;
    let verified = api
        .circuit_verify(
            &proved.vk.bytes,
            proved.public_inputs.clone(),
            proved.proof.clone(),
            target.settings(),
        )?
        .verified;
    api.destroy()?;
    let public_inputs = proved
        .public_inputs
        .iter()
        .map(|x| {
            <[u8; 32]>::try_from(x.as_slice())
                .map_err(|_| anyhow!("a public input of {} bytes", x.len()))
        })
        .collect::<anyhow::Result<_>>()?;
    Ok(Proof {
        proof: proved.proof.concat(),
        public_inputs,
        verified,
    })
}

/// `0x`-prefixed, 32 bytes.
#[must_use]
pub fn hex32(x: FieldElement) -> String {
    let bytes = x.to_be_bytes();
    format!("0x{}{}", "00".repeat(32 - bytes.len()), hex(&bytes))
}

#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(2 * bytes.len()), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
