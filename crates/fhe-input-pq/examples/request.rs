//! A TFHE input submitted to `FheRequest`, its well-formedness proved by leanVM and declared as
//! one leanSTARK dependency (`exp-frames` experiment 41, the post-quantum run).
//!
//! ```text
//! PRIVATE_KEY=0x... RECORD=request.json \
//!   RUSTFLAGS="-C target-cpu=native" cargo run --release -p kohaku-fhe-input-pq --example request
//! ```
//!
//! `CARRIER=modelled` (the default, the test network): the triple travels in the contract's own
//! `VERIFY` data, and the proof is checked here, off chain. `CARRIER=dependency` (a chain that runs
//! EIP-8288 extended to leanSTARK): the triple is a dependency frame, the proof is handed to the
//! block builder as `WITNESS_DIR/w-<keccak256(0x11 || D || key)>.bin` and the program written to
//! `PROGRAMS_DIR`. With `PRIVATE_KEY` unset the funder is the leanSPHINCS account
//! `sphincs/funder` of `SEED_FILE`, as `kohaku-frame-pq`'s example has it. `D`, `K`, `SEED` pick
//! the encryption; `RPC_URL` the chain.
//!
//! Then two refusals: the same request with one ciphertext coefficient changed, and, after it is
//! mined, the same proof at the next request number.

use std::{env, fs, time::Instant};

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, ensure};
use kohaku_fhe_input::{PkeParams, encrypt};
use kohaku_fhe_input_pq::{Spoil, v2};
use kohaku_frame_accounts::{
    account::{Eoa, Signer},
    builder::{Envelope, TxPlan},
    contracts::{create2_address, deploy_frame},
};
use kohaku_frame_kit::{
    Frame, FrameSigner, FrameTx,
    constants::{NEW_ACCOUNT_STATE_GAS, approve},
    rpc, sign_all,
};
use kohaku_frame_pq::{
    DEP_VERIFY_FRAME_MODE, SphincsKey,
    account::{Carrier, Fresh, SphincsSender, declare, witnesses},
};
use rand08::SeedableRng;
use serde_json::{Value, json};

const TIP: u128 = 1_000_000_000;
/// The scheme byte of a leanSTARK dependency, and the 30,000 gas this family models for it.
const LEANSTARK: u8 = 0x11;
const LEANSTARK_GAS: u64 = 30_000;
/// keccak256("exp-frames/41/fhe-request")
const DOMAIN: B256 = alloy::primitives::b256!("0x5afdea4a76df0aacc9b2ece5c97651c4dabacc3289d313ea887e6611dee94613");
/// A fresh slot's state gas.
const FRESH_SLOT: u64 = 97_920;

fn hex(b: &[u8]) -> String {
    alloy::hex::encode(b)
}

fn carrier() -> anyhow::Result<Carrier> {
    match env::var("CARRIER").as_deref() {
        Err(_) | Ok("" | "modelled") => Ok(Carrier::Modelled),
        Ok("dependency") => Ok(Carrier::Dependency),
        Ok(o) => anyhow::bail!("CARRIER {o}?"),
    }
}

fn code() -> Vec<u8> {
    alloy::hex::decode(include_str!("../contracts/FheRequest.hex").trim()).expect("hex")
}

fn initcode(hpk: B256, vk: B256, ctlen: usize, carrier: Carrier) -> Vec<u8> {
    let mut c = code();
    c.extend_from_slice(hpk.as_slice());
    c.extend_from_slice(vk.as_slice());
    c.extend_from_slice(&U256::from(ctlen).to_be_bytes::<32>());
    c.extend_from_slice(&U256::from(u8::from(carrier == Carrier::Modelled)).to_be_bytes::<32>());
    c
}

fn triple(d: B256, vk: B256) -> Vec<u8> {
    let mut t = vec![0u8; 96];
    t[31] = LEANSTARK;
    t[32..64].copy_from_slice(d.as_slice());
    t[64..].copy_from_slice(vk.as_slice());
    t
}

/// mu = keccak256(DOMAIN || chain id || contract || request number || requester).
fn mu(chain: u64, contract: Address, number: u64, requester: Address) -> [u8; 32] {
    let mut b = Vec::with_capacity(160);
    b.extend_from_slice(DOMAIN.as_slice());
    b.extend_from_slice(&U256::from(chain).to_be_bytes::<32>());
    b.extend_from_slice(B256::left_padding_from(contract.as_slice()).as_slice());
    b.extend_from_slice(&U256::from(number).to_be_bytes::<32>());
    b.extend_from_slice(B256::left_padding_from(requester.as_slice()).as_slice());
    keccak256(b).0
}

/// The funder: the test network's secp256k1 key, which only funds, or a genesis-funded
/// leanSPHINCS account.
enum Funder {
    Eoa(PrivateKeySigner),
    Pq { key: SphincsKey, sender: SphincsSender },
}

impl Funder {
    fn load() -> anyhow::Result<Self> {
        if let Some(k) = env::var("PRIVATE_KEY").ok().filter(|k| !k.is_empty()) {
            return Ok(Funder::Eoa(k.parse()?));
        }
        let path = env::var("SEED_FILE").context("PRIVATE_KEY or SEED_FILE")?;
        let seed = kohaku_frame_secrets::Seed::from_mnemonic(fs::read_to_string(path)?.trim())?;
        let key = SphincsKey::derive(&seed, "sphincs/funder");
        let sender = SphincsSender {
            key: key.public_key(),
            carrier: carrier()?,
            salt: B256::from(seed.key("sphincs/funder/salt")),
        };
        Ok(Funder::Pq { key, sender })
    }

    fn address(&self) -> Address {
        match self {
            Funder::Eoa(k) => k.address(),
            Funder::Pq { sender, .. } => sender.address(),
        }
    }

    async fn send<P: Provider>(&self, provider: &P, calls: Vec<Frame>, what: &str) -> anyhow::Result<Value> {
        let tx = match self {
            Funder::Eoa(k) => {
                let account = Eoa::new(Signer::secp256k1(k.address()));
                let envelope = Envelope::fetch(provider, k.address(), vec![U256::ZERO], TIP).await?;
                let mut tx = TxPlan::new(&account).calls(calls).build(&envelope)?;
                sign_all(&mut tx, &[FrameSigner::Secp256k1(k.clone())])?;
                tx
            }
            Funder::Pq { key, sender } => {
                let deploy = provider.get_code_at(sender.address()).await?.is_empty();
                let f = Fresh { sender, key, deploy };
                let envelope = Envelope::fetch(provider, sender.address(), vec![U256::ZERO], TIP).await?;
                let mut tx = TxPlan::new(&f).calls(calls).build(&envelope)?;
                if carrier()? == Carrier::Dependency {
                    declare(&mut tx, &[key]);
                }
                for w in witnesses(&tx, &[key])? {
                    hand_in_sphincs(&w)?;
                }
                tx
            }
        };
        mined(provider, &tx, what).await
    }
}

fn hand_in_sphincs(w: &kohaku_frame_pq::account::Witness) -> anyhow::Result<()> {
    let Some(dir) = env::var("WITNESS_DIR").ok().filter(|d| !d.is_empty()) else { return Ok(()) };
    let k = keccak256([&[0x10u8][..], w.message.as_slice(), w.key.as_slice()].concat());
    let body = json!({ "publicKey": w.key, "signature": format!("0x{}", hex(&w.signature)), "message": w.message });
    fs::write(std::path::Path::new(&dir).join(format!("w-{}.json", hex(k.as_slice()))), body.to_string())?;
    Ok(())
}

async fn mined<P: Provider>(provider: &P, tx: &FrameTx, what: &str) -> anyhow::Result<Value> {
    let done = rpc::execute(provider, tx, true).await?;
    let r = &done.receipt;
    println!("{what}: {} block {} gasUsed {}", done.hash, r.block_number, r.gas_used);
    Ok(json!({
        "what": what, "hash": done.hash, "block": r.block_number, "gasUsed": r.gas_used, "payer": r.payer,
        "frames": r.frame_receipts.iter().map(|f| json!({ "gasUsed": f.gas_used, "stateGasUsed": f.state_gas_used, "status": f.status })).collect::<Vec<_>>(),
    }))
}

async fn refused<P: Provider>(provider: &P, tx: &FrameTx, what: &str) -> anyhow::Result<Value> {
    let sim = rpc::simulate(provider, tx, "latest").await?;
    let sent = match rpc::send(provider, tx).await {
        Ok(h) => json!({ "result": h }),
        Err(e) => json!({ "error": e.to_string() }),
    };
    println!("{what}: simulation valid {}, {:?}; sent: {sent}", sim.valid, sim.violation);
    ensure!(!sim.valid && sent.get("error").is_some(), "{what} was not refused");
    Ok(json!({ "what": what, "hash": tx.hash(), "simulation": { "valid": sim.valid, "violation": sim.violation }, "sent": sent }))
}

/// The request transaction: the contract its own sender, paying its own gas.
#[allow(clippy::too_many_arguments)]
fn request_tx(chain: u64, contract: Address, number: u64, fees: kohaku_frame_kit::Fees, requester: Address, ct: &[u8], t: &[u8], carrier: Carrier) -> FrameTx {
    let mut data = B256::left_padding_from(requester.as_slice()).to_vec();
    data.extend_from_slice(ct);
    let verify_data = if carrier == Carrier::Modelled { t.to_vec() } else { Vec::new() };
    let mut frames = vec![Frame::verify(approve::EXECUTION_AND_PAYMENT, None).with_data(verify_data).with_execution(100_000)];
    if carrier == Carrier::Dependency {
        frames.push(Frame { mode: DEP_VERIFY_FRAME_MODE, data: Bytes::from(t.to_vec()), ..Frame::default() }.with_execution(LEANSTARK_GAS));
    }
    frames.push(Frame::sender(Some(contract)).with_data(data).with_execution(150_000).with_state(FRESH_SLOT));
    FrameTx { chain_id: chain, nonce_keys: vec![U256::ZERO], nonce_seq: number, sender: contract, frames, signatures: vec![], fees, blob_versioned_hashes: vec![] }
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> anyhow::Result<()> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| rpc::HEGOTA_RPC_URL.to_owned());
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    let carrier = carrier()?;
    let d: usize = env::var("D").map_or(Ok(2048), |v| v.parse())?;
    let k: usize = env::var("K").map_or(Ok(1), |v| v.parse())?;
    let seed: u64 = env::var("SEED").map_or(Ok(1), |v| v.parse())?;
    let funder = Funder::load()?;
    let chain = provider.get_chain_id().await?;

    let p = PkeParams { d, ..PkeParams::tfhe_zkv2(k) };
    let enc = encrypt(&p, &mut rand08::rngs::StdRng::seed_from_u64(seed));
    let source = v2::program(d, k);
    let vk = B256::from(v2::key(&source));
    let probe = v2::instance(&p, &enc, [0u8; 32], Spoil::None);
    let hpk = keccak256(&probe.pk_bytes);
    let ct = probe.ct_bytes.clone();
    let init = initcode(hpk, vk, ct.len(), carrier);
    let salt = keccak256(format!("exp-frames/41/fhe-request/{d}/{k}/{seed}/{carrier:?}"));
    let contract = create2_address(&init, salt);
    let mut steps = vec![];
    if provider.get_code_at(contract).await?.is_empty() {
        steps.push(
            funder
                .send(
                    &provider,
                    vec![
                        deploy_frame(&init, salt, 0),
                        Frame::sender(Some(contract)).with_value(U256::from(20_000_000_000_000_000u64)).with_execution(10_000).with_state(NEW_ACCOUNT_STATE_GAS),
                    ],
                    "the funder deploys FheRequest for the key and the program, and funds it",
                )
                .await?,
        );
    }
    if let Ok(dir) = env::var("PROGRAMS_DIR") {
        fs::write(std::path::Path::new(&dir).join(format!("fhe_input_v2_d{d}_k{k}.py")), &source)?;
    }

    // The request: mu for this contract and number, the proof for that mu.
    let requester = funder.address();
    let number = rpc::nonce_seq(&provider, contract, &[U256::ZERO]).await?;
    let m = mu(chain, contract, number, requester);
    let inst = v2::instance(&p, &enc, m, Spoil::None);
    ensure!(inst.ct_bytes == ct, "the ciphertext moved");
    let ast = lean_compiler::parse(&inst.source).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    let mut program = lean_compiler::compile(&ast);
    for (name, entries) in inst.streams {
        program.set_witness(name, entries);
    }
    let started = Instant::now();
    let (proof, stats) = leanvm_core::cpu::prove(&program, inst.public, 1).map_err(|e| anyhow::anyhow!("prove: {e:?}"))?;
    let prove_ms = started.elapsed().as_secs_f64() * 1e3;
    let verified = leanvm_core::cpu::verify(&program, &inst.public, &proof).is_ok();
    ensure!(verified, "the proof does not verify");
    let proof_bytes = bincode::serialize(&proof)?;
    let dg = B256::from(inst.digest);
    let t = triple(dg, vk);
    if carrier == Carrier::Dependency {
        let dir = env::var("WITNESS_DIR").context("WITNESS_DIR")?;
        let key = keccak256([&[LEANSTARK][..], dg.as_slice(), vk.as_slice()].concat());
        fs::write(std::path::Path::new(&dir).join(format!("w-{}.bin", hex(key.as_slice()))), &proof_bytes)?;
    }
    println!("proved in {prove_ms:.0} ms, {} cycles, {} bytes; verified off chain", stats.cycles, proof_bytes.len());

    let fees = rpc::suggest_fees(&provider, TIP).await?;
    let mut refusals = vec![];
    // One coefficient changed, the triple kept.
    {
        let mut bad = ct.clone();
        bad[0] ^= 1;
        let tx = request_tx(chain, contract, number, fees, requester, &bad, &t, carrier);
        refusals.push(refused(&provider, &tx, "the request with one ciphertext coefficient changed").await?);
    }
    let tx = request_tx(chain, contract, number, fees, requester, &ct, &t, carrier);
    let mut s = mined(&provider, &tx, "a TFHE input requested, its well-formedness a leanSTARK dependency").await?;
    s["proof"] = json!({ "bytes": proof_bytes.len(), "keccak": keccak256(&proof_bytes), "cycles": stats.cycles, "proveMs": prove_ms, "verifiedOffChain": verified });
    steps.push(s);
    // The same proof at the next request number.
    {
        let tx = request_tx(chain, contract, number + 1, fees, requester, &ct, &t, carrier);
        refusals.push(refused(&provider, &tx, "the same proof at the next request number").await?);
    }
    let stored = provider.get_storage_at(contract, U256::from_be_bytes(keccak256(U256::from(number).to_be_bytes::<32>()).0)).await?;
    ensure!(B256::from(stored) == keccak256(&ct), "the request's ciphertext hash is not recorded");

    let record = json!({
        "carrier": format!("{carrier:?}"),
        "chainId": chain,
        "d": d, "k": k, "seed": seed,
        "contract": contract,
        "programKey": vk,
        "pkKeccak": hpk,
        "ciphertextBytes": ct.len(),
        "requestNumber": number,
        "requester": requester,
        "mu": B256::from(m),
        "digest": dg,
        "steps": steps,
        "refused": refusals,
    });
    if let Ok(path) = env::var("RECORD") {
        fs::write(path, serde_json::to_string_pretty(&record)? + "\n")?;
    }
    Ok(())
}
