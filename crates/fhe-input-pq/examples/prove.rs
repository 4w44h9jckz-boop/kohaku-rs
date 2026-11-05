//! Prove one TFHE input's well-formedness with leanVM, verify it, and record what it cost.
//!
//! ```text
//! D=2048 K=1 SEED=1 RECORD=prove.json PROOF_OUT=proof.bin \
//!   RUSTFLAGS="-C target-cpu=native" cargo run --release -p kohaku-fhe-input-pq --example prove
//! ```
//!
//! `VERSION=1` runs the first program (two 32-bit halves under `g`); the default is version 2.
//! `SPOIL=noise` makes one noise coefficient one past its bound, which must not prove. `MU` (hex,
//! 32 bytes) is the request's message; zero by default. `PROGRAM_OUT` writes the program's source,
//! for a verifier that finds it by its key.

use std::{env, fs, time::Instant};

use kohaku_fhe_input::{PkeParams, encrypt};
use kohaku_fhe_input_pq::{PROGRAM, Spoil, instance, program_key, v2};
use rand08::SeedableRng;
use serde_json::json;

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        use std::fmt::Write;
        let _ = write!(s, "{x:02x}");
        s
    })
}

#[allow(clippy::many_single_char_names, clippy::too_many_lines)]
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
    let p = PkeParams {
        d,
        ..PkeParams::tfhe_zkv2(k)
    };
    let enc = encrypt(&p, &mut rand08::rngs::StdRng::seed_from_u64(seed));
    let version: u32 = env::var("VERSION").map_or(Ok(2), |v| v.parse())?;
    let t = Instant::now();
    let (source, replacements, streams, pk_bytes, ct_len, digest, public, key) = if version == 1 {
        let i = instance(&p, &enc, mu, spoil);
        (
            PROGRAM.to_owned(),
            i.replacements,
            i.streams,
            i.pk_bytes,
            i.ct_bytes.len(),
            i.digest,
            i.public,
            program_key(),
        )
    } else {
        let i = v2::instance(&p, &enc, mu, spoil);
        let key = v2::key(&i.source);
        (
            i.source,
            std::collections::BTreeMap::new(),
            i.streams,
            i.pk_bytes,
            i.ct_bytes.len(),
            i.digest,
            i.public,
            key,
        )
    };
    let witness_ms = t.elapsed().as_secs_f64() * 1e3;
    if let Ok(path) = env::var("PROGRAM_OUT") {
        fs::write(path, &source)?;
    }

    let t = Instant::now();
    let ast = lean_compiler::parse_with_replacements(&source, &replacements)
        .map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    let mut program = lean_compiler::compile(&ast);
    let compile_ms = t.elapsed().as_secs_f64() * 1e3;
    let bytecode = program.prog.len();
    for (name, entries) in streams {
        program.set_witness(name, entries);
    }
    let t = Instant::now();
    let proved = leanvm_core::cpu::prove(&program, public, 1);
    let prove_ms = t.elapsed().as_secs_f64() * 1e3;
    let mut record = json!({
        "version": version, "d": d, "k": k, "seed": seed, "spoil": format!("{spoil:?}"),
        "programKey": format!("0x{}", hex(&key)),
        "digest": format!("0x{}", hex(&digest)),
        "pkKeccak": format!("0x{}", hex(&sha3::Keccak256::digest_bytes(&pk_bytes))),
        "ctBytes": ct_len,
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
            let verified = leanvm_core::cpu::verify(&program, &public, &proof).is_ok();
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
            record["proofKeccak"] =
                json!(format!("0x{}", hex(&sha3::Keccak256::digest_bytes(&bytes))));
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
