//! `exp-frames` experiment 42's prover, from Rust: reads a request on stdin and writes the proof
//! to the file named on the command line, in the shape `build/prove.mjs` writes.
//!
//! ```text
//! BB=/path/to/bb cargo run --release -p kohaku-noir-transfer --example prove -- response.json < request.json
//! ```
//!
//! `bb` is Barretenberg's binary at 5.2.1; `@aztec/bb.js` 5.2.1 ships it under `build/`.

use std::io::Read;
use std::path::PathBuf;
use std::time::Instant;
use std::{env, fs};

use kohaku_noir_transfer::{Circuit, Request, TRANSFER_JSON, hex, hex32, prove, transfer};
use serde_json::json;

fn main() -> anyhow::Result<()> {
    let out = env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: prove <response.json> < request.json"))?;
    let bb = PathBuf::from(
        env::var("BB").map_err(|_| anyhow::anyhow!("BB is not set to Barretenberg's bb binary"))?,
    );
    let mut request = String::new();
    std::io::stdin().read_to_string(&mut request)?;
    let req: Request = serde_json::from_str(&request)?;

    let circuit = Circuit::from_json(TRANSFER_JSON)?;
    let t = transfer(&req)?;
    let witness = circuit.execute(&t.inputs)?;
    let started = Instant::now();
    let proof = prove(&bb, &circuit, &witness, req.target)?;
    let prove_ms = started.elapsed().as_millis();
    anyhow::ensure!(proof.verified, "Barretenberg did not verify its own proof");
    let expected: Vec<String> = t.public_inputs().into_iter().map(hex32).collect();
    let got: Vec<String> = proof
        .public_inputs
        .iter()
        .map(|x| format!("0x{}", hex(x)))
        .collect();
    anyhow::ensure!(
        expected == got,
        "public inputs {got:?}, expected {expected:?}"
    );

    let response = json!({
        "root": hex32(t.root),
        "nullifiers": t.nullifiers.map(hex32),
        "outHashes": t.out_hashes.map(hex32),
        "fee": t.fee.to_string(),
        "context": hex32(t.context),
        "proof": format!("0x{}", hex(&proof.proof)),
        "publicInputs": got,
        "proveMs": prove_ms,
        "prover": format!("kohaku-noir-transfer, Noir {}, barretenberg-rs 5.2.1", circuit.noir_version),
    });
    fs::write(&out, format!("{}\n", serde_json::to_string(&response)?))?;
    Ok(())
}
