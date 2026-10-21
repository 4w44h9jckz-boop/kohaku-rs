//! `exp-frames` experiment 41: a TFHE input's proof of knowledge made and verified on BLS12-381
//! and on BLS12-446, at tfhe-rs's parameters, beside the floor on what a `VERIFY` frame would pay.
//!
//! ```text
//! RECORD=measure.json cargo run --release -p kohaku-fhe-input --example measure
//! ```

use std::{env, fs};

use kohaku_fhe_input::{PkeParams, floor, run};
use serde_json::json;
use tfhe_zk_pok::{
    curve_api::{Bls12_381, Bls12_446},
    proofs::ComputeLoad,
};

fn main() -> anyhow::Result<()> {
    let mut runs = vec![];
    let mut floors = vec![];
    for k in [1usize, 32] {
        let p = PkeParams::tfhe_zkv2(k);
        let f = floor(&p);
        println!("k = {k}: floor {f:?}");
        floors.push(json!({ "params": format!("{p:?}"), "k": k, "floor": f }));
        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            let r = run::<Bls12_381>("BLS12-381", &p, load, 41);
            println!("{r:?}");
            runs.push(serde_json::to_value(&r)?);
        }
        let r = run::<Bls12_446>("BLS12-446", &p, ComputeLoad::Proof, 41);
        println!("{r:?}");
        runs.push(serde_json::to_value(&r)?);
    }
    if let Ok(path) = env::var("RECORD") {
        let record = json!({ "floors": floors, "runs": runs });
        fs::write(&path, format!("{}\n", serde_json::to_string_pretty(&record)?))?;
        println!("recorded in {path}");
    }
    Ok(())
}
