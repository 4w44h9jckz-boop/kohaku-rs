//! Prove one TFHE input's well-formedness with leanVM, verify it, and record what it cost.
//!
//! ```text
//! D=2048 K=1 SEED=1 RECORD=prove.json PROOF_OUT=proof.bin \
//!   RUSTFLAGS="-C target-cpu=native" cargo run --release -p kohaku-fhe-input-pq --example prove
//! ```
//!
//! `SPOIL=noise` makes one noise coefficient one past its bound, which must not prove. `MU` (hex,
//! 32 bytes) is the request's message; zero by default. `PROGRAM_OUT` writes the program's source,
//! for a verifier that finds it by its key.

use std::{env, fs, time::Instant};

use kohaku_fhe_input::{PkeParams, encrypt};
use kohaku_fhe_input_pq::{PROGRAM, Spoil, instance, program_key};
use rand08::SeedableRng;
use serde_json::json;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() -> anyhow::Result<()> {
    let d: usize = env::var("D").map_or(Ok(2048), |v| v.parse())?;
    let k: usize = env::var("K").map_or(Ok(1), |v| v.parse())?;
    let seed: u64 = env::var("SEED").map_or(Ok(1), |v| v.parse())?;
    let spoil = match env::var("SPOIL").as_deref() {
        Ok("noise") => Spoil::NoiseOutOfBound,
        _ => Spoil::None,
    };
    let mut mu = [0u8; 32];
    if let Ok(h) = env::var("MU") {
        let h = h.trim_start_matches("0x");
        for (i, b) in mu.iter_mut().enumerate() {
            *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16)?;
        }
    }
    let p = PkeParams { d, ..PkeParams::tfhe_zkv2(k) };
    let enc = encrypt(&p, &mut rand08::rngs::StdRng::seed_from_u64(seed));
    let t = Instant::now();
    let inst = instance(&p, &enc, mu, spoil);
    let witness_ms = t.elapsed().as_secs_f64() * 1e3;
    if let Ok(path) = env::var("PROGRAM_OUT") {
        fs::write(path, PROGRAM)?;
    }

    let t = Instant::now();
    let ast = lean_compiler::parse_with_replacements(PROGRAM, &inst.replacements).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    let mut program = lean_compiler::compile(&ast);
    let compile_ms = t.elapsed().as_secs_f64() * 1e3;
    let bytecode = program.prog.len();
    for (name, entries) in inst.streams {
        program.set_witness(name, entries);
    }
    let t = Instant::now();
    let proved = leanvm_core::cpu::prove(&program, inst.public, 1);
    let prove_ms = t.elapsed().as_secs_f64() * 1e3;
    let mut record = json!({
        "d": d, "k": k, "seed": seed, "spoil": format!("{spoil:?}"),
        "programKey": format!("0x{}", hex(&program_key())),
        "digest": format!("0x{}", hex(&inst.digest)),
        "pkKeccak": format!("0x{}", hex(&sha3::Keccak256::digest_bytes(&inst.pk_bytes))),
        "ctBytes": inst.ct_bytes.len(),
        "witnessMs": witness_ms, "compileMs": compile_ms, "bytecodeLen": bytecode,
        "threads": std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
    });
    match proved {
        Err(e) => {
            record["proved"] = json!(false);
            record["error"] = json!(format!("{e:?}"));
            record["proveMs"] = json!(prove_ms);
        }
        Ok((proof, stats)) => {
            let bytes = bincode::serialize(&proof)?;
            let t = Instant::now();
            let verified = leanvm_core::cpu::verify(&program, &inst.public, &proof).is_ok();
            let verify_ms = t.elapsed().as_secs_f64() * 1e3;
            if let Ok(path) = env::var("PROOF_OUT") {
                fs::write(path, &bytes)?;
            }
            record["proved"] = json!(true);
            record["verified"] = json!(verified);
            record["cycles"] = json!(stats.cycles);
            record["details"] = json!(stats.details());
            record["proveMs"] = json!(prove_ms);
            record["verifyMs"] = json!(verify_ms);
            record["proofBytes"] = json!(bytes.len());
            record["proofKeccak"] = json!(format!("0x{}", hex(&sha3::Keccak256::digest_bytes(&bytes))));
        }
    }
    record["peakRssBytes"] = json!(bench::peak_rss_bytes());
    println!("{record}");
    if let Ok(path) = env::var("RECORD") {
        fs::write(path, serde_json::to_string_pretty(&record)? + "\n")?;
    }
    Ok(())
}

trait DigestBytes {
    fn digest_bytes(b: &[u8]) -> [u8; 32];
}
impl DigestBytes for sha3::Keccak256 {
    fn digest_bytes(b: &[u8]) -> [u8; 32] {
        use sha3::Digest;
        sha3::Keccak256::digest(b).into()
    }
}
