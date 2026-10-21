//! One seed, every secret derived, and the wallet rebuilt from the seed and the chain:
//! `exp-frames` experiment 45, on the ethrex Hegota testnet.
//!
//! ```text
//! SEED_FILE=/path/outside/the/repo PRIVATE_KEY=0x... PUBLIC=public.json RECORD=build.json \
//!   MODE=build cargo run --release -p kohaku-frame-secrets --example seed_wallet
//! SEED_FILE=/path/outside/the/repo PUBLIC=public.json RECORD=restore.json \
//!   MODE=restore cargo run --release -p kohaku-frame-secrets --example seed_wallet
//! ```
//!
//! `MODE=build` is the device that will be lost. It makes a 24-word mnemonic in `SEED_FILE` if
//! there is none, and from the seed alone:
//! 1. deploys experiment 31's `DeviceRecoveryAccount` at an address the seed fixes, and funds it;
//! 2. deposits a keychain note into experiment 06's keyed pool, and a note into experiment 40's
//!    fixed-amount vault;
//! 3. deploys a ticket paymaster for a new committee of four issuers, buys two tickets, has them
//!    issued blind with seed-derived senders, salts and blinding factors, and posts each blinded
//!    answer beside its request on experiment 33's board;
//! 4. sends a transaction from the account.
//!
//! The funder (`PRIVATE_KEY`) pays owner 0, and makes a vault note for the wallet with secrets of
//! its own, sealing the opening to the wallet's viewing key on the board.
//!
//! `MODE=restore` is a fresh device. It reads the mnemonic and `PUBLIC`, the contracts'
//! addresses and the committee's public key, and nothing the build kept. It rebuilds the account,
//! the pool notes, the vault notes, the sealed note and the tickets from the chain; then it
//! withdraws a pool note to a derived recipient, spends a ticket from a fresh sender, and sends a
//! transaction from the account.
//!
//! Neither mode prints or records the mnemonic or a derived secret.

use std::{env, fs, os::unix::fs::PermissionsExt};

use alloy::{
    primitives::{Address, B256, Bytes, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    signers::{SignerSync, local::PrivateKeySigner},
    sol,
    sol_types::{SolCall, SolEvent},
};
use anyhow::{Context, ensure};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::bls12381::primitives::{
    group::{G1, G2},
    ops,
    variant::{MinSig, PartialSignature},
};
use commonware_math::algebra::Field as _;
use kohaku_frame_accounts::{
    account::{Eoa, Signer},
    builder::{Envelope, TxPlan},
    recovery::{DeviceRecoveryAccount, TimeRule},
};
use kohaku_frame_kit::{Frame, FrameSigner, FrameTx, rpc, sign_all};
use kohaku_frame_pool::{
    chain, prove,
    withdrawal::{DENOMINATION, FramePool, PoolMode, WithdrawalOpts, withdrawal_tx},
};
use kohaku_frame_registry::{
    announce::{self, Keys, board_messages, post_frame},
    custody::{self, abi as registry_abi},
    note::{Secrets, field},
};
use kohaku_frame_secrets::{PATHS, Seed, derive::lower};
use kohaku_frame_ticket::{
    Claim, Committee, Slot, Ticket, TicketPaymaster, TicketSponsor, blind,
    issuers::{Count, Ledger, request_id},
    paymaster::Bought,
    ticket::{NAMESPACE, epoch_of},
};
use kohaku_frame_wallet::recovery::{keychain_pool, pool_events, root_slot};
use kohaku_tornadocash::{Payer, merkle_tree::MerkleTree};
use kohaku_tornadocash_keychain::{Keychain, recovery::recover};
use rand::RngExt;
use serde_json::{Value, json};

/// Experiment 06's keyed pool.
const KEYED_POOL: Address = address!("0x73e47a8DA2C83Beb802708Fc473B5B7D094f3eE6");
/// Experiment 40's vaulted registry and its first fixed-amount vault.
const REGISTRY: Address = address!("0x246FBf1ca115E6f9993658e0e46F24E4C9054Df6");
const VAULT: Address = address!("0x7Bc7902c7DEABFbD7Abd783C49BA7Bf946D13314");
/// What the vault takes per note, and what its notes hold.
const VAULT_AMOUNT: u64 = 1_000_000_000_000_000;
/// Experiment 33's board.
const BOARD: Address = address!("0x93DD748B72dA1b1B6F1d5ec78Cb91ee52F01727d");
/// 0.001 ETH a ticket, as in experiment 36.
const TICKET_PRICE: U256 = U256::from_limbs([1_000_000_000_000_000, 0, 0, 0]);
const TICKETS: u32 = 2;
const ISSUERS: usize = 4;
const TIP: u128 = 1_000_000_000;
/// What the funder gives owner 0, and owner 0 the account.
const OWNER_FUNDS: U256 = U256::from_limbs([60_000_000_000_000_000, 0, 0, 0]);
const ACCOUNT_FUNDS: U256 = U256::from_limbs([5_000_000_000_000_000, 0, 0, 0]);
/// The account's recovery delay, seconds.
const DELAY: u64 = 120;
/// What a withdrawal pays the pool for its gas, as experiment 06's examples pay.
const POOL_FEE: u64 = 10_000_000_000;
/// How many unused indices end a scan.
const GAP: u32 = 3;
/// A board message carrying a ticket's request and the committee's blinded answer.
const ANSWER_TAG: u8 = 0x10;

sol! {
    function post(bytes message);
}

/// The account index 0 of a seed, as deployed: owner 0, no recovery commitment yet.
fn account(seed: &Seed, i: u32) -> anyhow::Result<DeviceRecoveryAccount> {
    Ok(DeviceRecoveryAccount {
        owner: seed.owner(i)?.address(),
        commitment: B256::ZERO,
        delay: DELAY,
        rule: TimeRule::Eip,
        salt: seed.account_salt(i),
    })
}

fn pool() -> FramePool {
    FramePool {
        address: KEYED_POOL,
        mode: PoolMode::Keyed,
        salt: keccak256("exp-frames/06/pool-keyed"),
    }
}

fn hex(b: &[u8]) -> String {
    format!("0x{}", ::hex::encode(b))
}

fn unhex(s: &str) -> anyhow::Result<Vec<u8>> {
    Ok(::hex::decode(s.trim_start_matches("0x"))?)
}

/// The mnemonic in `SEED_FILE`, made if `create` and missing. Never printed.
fn load_seed(create: bool) -> anyhow::Result<Seed> {
    let path = env::var("SEED_FILE").context("SEED_FILE names where the mnemonic is kept")?;
    if let Ok(phrase) = fs::read_to_string(&path) {
        return Ok(Seed::from_mnemonic(phrase.trim())?);
    }
    ensure!(create, "no mnemonic in SEED_FILE");
    let (phrase, seed) = Seed::generate(&mut rand::rng())?;
    fs::write(&path, format!("{phrase}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    println!("a new mnemonic is in SEED_FILE");
    Ok(seed)
}

/// `key`'s own transaction making `calls`, simulated, sent and confirmed.
async fn send<P: Provider>(
    provider: &P,
    key: &PrivateKeySigner,
    calls: Vec<Frame>,
    what: &str,
) -> anyhow::Result<Value> {
    let account = Eoa::new(Signer::secp256k1(key.address()));
    let envelope = Envelope::fetch(provider, key.address(), vec![U256::ZERO], TIP).await?;
    let mut tx = TxPlan::new(&account).calls(calls).build(&envelope)?;
    sign_all(&mut tx, &[FrameSigner::Secp256k1(key.clone())])?;
    executed(provider, &tx, what).await
}

async fn executed<P: Provider>(provider: &P, tx: &FrameTx, what: &str) -> anyhow::Result<Value> {
    let done = rpc::execute(provider, tx, true).await?;
    println!(
        "{what}: {} block {} gasUsed {}",
        done.hash, done.receipt.block_number, done.receipt.gas_used
    );
    Ok(json!({
        "what": what,
        "hash": done.hash,
        "raw": tx.encode(),
        "block": done.receipt.block_number,
        "gasUsed": done.receipt.gas_used,
        "payer": done.receipt.payer,
    }))
}

/// A transaction from the account, signed by its owner: one post to the board.
async fn account_tx<P: Provider>(
    provider: &P,
    acct: &DeviceRecoveryAccount,
    owner: &PrivateKeySigner,
    message: &[u8],
) -> anyhow::Result<Value> {
    let signer = acct.signed_by(owner.address());
    let envelope = Envelope::fetch(provider, acct.address(), vec![U256::ZERO], TIP).await?;
    let mut tx = TxPlan::new(&signer)
        .call(post_frame(BOARD, message))
        .build(&envelope)?;
    sign_all(&mut tx, &[FrameSigner::Secp256k1(owner.clone())])?;
    executed(provider, &tx, "the account, signed by its owner").await
}

/// A fresh sender's first transaction, paid with `ticket`: it posts to the board.
fn spend(
    chain_id: u64,
    fees: kohaku_frame_kit::Fees,
    sender: &PrivateKeySigner,
    ticket: &Ticket,
    paymaster: Address,
    message: &[u8],
) -> anyhow::Result<FrameTx> {
    let account = Eoa::new(Signer::secp256k1(sender.address()));
    let mut sponsor = TicketSponsor::new(paymaster, ticket);
    let mut tx = TxPlan::new(&account)
        .sponsored_by(&mut sponsor)
        .call(
            Frame::sender(Some(BOARD))
                .with_data(
                    postCall {
                        message: message.to_vec().into(),
                    }
                    .abi_encode(),
                )
                .with_execution(30_000),
        )
        .build(&Envelope {
            chain_id,
            nonce_keys: vec![U256::ZERO],
            nonce_seq: 0,
            fees,
        })?;
    sign_all(&mut tx, &[FrameSigner::Secp256k1(sender.clone())])?;
    Ok(tx)
}

/// The k-th ticket's claim, from the seed and its epoch.
fn claim(seed: &Seed, chain_id: u64, k: u32, epoch: u64) -> anyhow::Result<Claim> {
    let t = seed.ticket(k)?;
    Ok(Claim {
        slot: Slot {
            chain_id,
            sender: t.sender.address(),
            nonce_keys: vec![U256::ZERO],
            nonce_seq: 0,
        },
        epoch,
        salt: t.salt,
    })
}

/// `ANSWER_TAG || epoch || B || x * B`.
fn answer_message(epoch: u64, blinded: &G1, answer: &G1) -> Vec<u8> {
    let mut m = vec![ANSWER_TAG];
    m.extend_from_slice(&epoch.to_be_bytes());
    m.extend_from_slice(&blinded.encode());
    m.extend_from_slice(&answer.encode());
    m
}

/// The opening of a vault note, as the funder seals it to the viewing key.
fn received_plaintext(vault: Address, s: &Secrets, state: u64) -> Vec<u8> {
    let mut p = vault.to_vec();
    p.extend_from_slice(&B256::from(s.nullifier_secret).0);
    p.extend_from_slice(&B256::from(s.secret).0);
    p.extend_from_slice(&state.to_be_bytes());
    p
}

fn parse_received(p: &[u8]) -> Option<(Address, Secrets, u64)> {
    if p.len() != 92 {
        return None;
    }
    let f = |b: &[u8]| field(U256::from_be_slice(b));
    Some((
        Address::from_slice(&p[..20]),
        Secrets {
            nullifier_secret: f(&p[20..52]),
            secret: f(&p[52..84]),
        },
        u64::from_be_bytes(p[84..92].try_into().ok()?),
    ))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| rpc::HEGOTA_RPC_URL.to_owned());
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    match env::var("MODE").as_deref() {
        Ok("build") => build(&provider).await,
        Ok("restore") => restore(&provider).await,
        _ => anyhow::bail!("MODE is build or restore"),
    }
}

#[allow(clippy::too_many_lines)]
async fn build<P: Provider>(provider: &P) -> anyhow::Result<()> {
    let funder: PrivateKeySigner = env::var("PRIVATE_KEY")
        .context("PRIVATE_KEY funds owner 0")?
        .parse()?;
    let seed = load_seed(true)?;
    let chain_id = provider.get_chain_id().await?;
    let mut rng = rand::rng();
    let owner = seed.owner(0)?;
    let acct = account(&seed, 0)?;
    println!("owner 0 {}, account 0 {}", owner.address(), acct.address());
    ensure!(
        provider.get_code_at(acct.address()).await?.is_empty(),
        "account 0 of this seed is already deployed: use a new SEED_FILE"
    );
    let mut steps = vec![];

    // The funder pays owner 0.
    steps.push(
        send(
            provider,
            &funder,
            vec![
                Frame::sender(Some(owner.address()))
                    .with_value(OWNER_FUNDS)
                    .with_execution(10_000)
                    .with_state(TicketSponsor::NEW_ACCOUNT_STATE),
            ],
            "the funder pays owner 0",
        )
        .await?,
    );

    // 1 and 3, the setup: the account and the paymaster deployed, the account funded, tickets
    // bought.
    let mut committee = Committee::dkg(&mut rng, ISSUERS)?;
    let paymaster = TicketPaymaster {
        key: *committee.sharing.public(),
        denomination: TICKET_PRICE,
        salt: B256::from(rng.random::<[u8; 32]>()),
    };
    steps.push(
        send(
            provider,
            &owner,
            vec![
                acct.deploy_frame(),
                Frame::sender(Some(acct.address()))
                    .with_value(ACCOUNT_FUNDS)
                    .with_execution(10_000),
                paymaster.deploy_frame(),
                paymaster.buy_frame(u64::from(TICKETS)),
            ],
            "owner 0 deploys account 0 and a ticket paymaster, funds the account, buys 2 tickets",
        )
        .await?,
    );

    // 2. The notes. The keychain's next note into the pool.
    let kpool = keychain_pool(&pool(), chain_id, 0);
    let keychain = seed.keychain()?;
    let events = pool_events(provider, KEYED_POOL, 0).await?;
    let nonce =
        kohaku_tornadocash_keychain::recovery::next_nonce(&keychain, &kpool, &events, None).await?;
    let note = keychain.note(&kpool, nonce).await?.note;
    let deposited = chain::deposit(
        provider,
        &pool(),
        &FrameSigner::Secp256k1(owner.clone()),
        &note,
    )
    .await?;
    println!(
        "pool note {nonce}: {} block {}, leaf {}",
        deposited.receipt.transaction_hash, deposited.receipt.block_number, deposited.leaf_index
    );
    steps.push(json!({
        "what": "owner 0 deposits the keychain's next pool note",
        "hash": deposited.receipt.transaction_hash,
        "block": deposited.receipt.block_number,
        "leaf": deposited.leaf_index,
        "keychainNonce": nonce,
    }));

    // The vault note j = 0.
    let mine = seed.custody(VAULT, 0);
    steps.push(
        send(
            provider,
            &owner,
            vec![custody::deposit_frame(
                REGISTRY,
                VAULT,
                mine.inner(),
                U256::from(VAULT_AMOUNT),
                false,
            )],
            "owner 0 deposits vault note 0",
        )
        .await?,
    );

    // A note the funder makes for the wallet, its opening sealed to the viewing key.
    let view = seed.view()?;
    let theirs = Secrets {
        nullifier_secret: field(U256::from_be_bytes(rng.random::<[u8; 32]>())),
        secret: field(U256::from_be_bytes(rng.random::<[u8; 32]>())),
    };
    let ephemeral = Keys::from_secret(B256::from(rng.random::<[u8; 32]>()))?;
    let sealed = announce::seal(
        &view.public,
        &received_plaintext(VAULT, &theirs, VAULT_AMOUNT),
        &ephemeral,
    )?;
    steps.push(
        send(
            provider,
            &funder,
            vec![
                custody::deposit_frame(
                    REGISTRY,
                    VAULT,
                    theirs.inner(),
                    U256::from(VAULT_AMOUNT),
                    false,
                ),
                post_frame(BOARD, &sealed),
            ],
            "the funder deposits a vault note for the wallet and seals its opening to the viewing key",
        )
        .await?,
    );

    // 3. Issuance, against the issuers' shared list of what each buyer bought.
    let bought = bought_by(provider, paymaster.address(), owner.address()).await?;
    ensure!(bought == u64::from(TICKETS));
    let mut ledger = Ledger::new([(owner.address(), bought)].into());
    let head = provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await?
        .context("no head")?;
    let epoch = epoch_of(head.header.timestamp);
    let mut issued = vec![];
    for k in 0..TICKETS {
        let c = claim(&seed, chain_id, k, epoch)?;
        let (blinded, blinding) =
            blind::blind_with(seed.ticket(k)?.blinding, NAMESPACE, &c.message())
                .context("a zero blinding factor")?;
        let digest = keccak256([b"kohaku-ticket-request".as_slice(), &blinded.encode()].concat());
        let request = owner.sign_hash_sync(&digest)?;
        let left_out = k as usize % ISSUERS;
        let mut answers: Vec<PartialSignature<MinSig>> = vec![];
        for (i, issuer) in committee.issuers.iter_mut().enumerate() {
            if i == left_out {
                continue;
            }
            let buyer = request.recover_address_from_prehash(&digest)?;
            ledger.admit(Count::Shared, i, buyer, request_id(&blinded))?;
            let a = issuer.answer(&blinded);
            blind::check_answer(&committee.sharing, &blinded, &a)
                .map_err(|e| anyhow::anyhow!("an answer does not check: {e:?}"))?;
            answers.push(a);
        }
        let signature = blind::unblind(&committee.sharing, &answers, &blinding)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let ticket = Ticket {
            claim: c,
            signature,
        };
        ticket
            .verify(&committee.sharing)
            .map_err(|e| anyhow::anyhow!("a ticket does not verify: {e:?}"))?;
        // x * B, what the committee's answers interpolate to.
        let blinded_answer = signature * &seed.ticket(k)?.blinding;
        issued.push((blinded, blinded_answer));
        println!("ticket {k} issued, issuer {left_out} left out");
    }
    steps.push(
        send(
            provider,
            &owner,
            issued
                .iter()
                .map(|(b, a)| post_frame(BOARD, &answer_message(epoch, b, a)))
                .collect(),
            "owner 0 posts each ticket's request and blinded answer",
        )
        .await?,
    );

    // 4. The account, used.
    steps.push(account_tx(provider, &acct, &owner, b"account 0, before the loss").await?);

    let public = json!({
        "chainId": chain_id,
        "pool": KEYED_POOL,
        "registry": REGISTRY,
        "vault": VAULT,
        "vaultAmount": VAULT_AMOUNT,
        "board": BOARD,
        "paymaster": paymaster.address(),
        "committeeKey": hex(&committee.sharing.public().encode()),
        "delay": DELAY,
    });
    fs::write(
        env::var("PUBLIC").context("PUBLIC names where the public addresses go")?,
        format!("{}\n", serde_json::to_string_pretty(&public)?),
    )?;
    if let Ok(path) = env::var("RECORD") {
        let record = json!({
            "public": public,
            "owner0": owner.address(),
            "account0": acct.address(),
            "epoch": epoch,
            "steps": steps,
            "issuers": committee.issuers.iter().map(|i| json!({
                "index": i.index(),
                "saw": i.transcript.iter().map(|b| hex(&b.encode())).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "posted": issued.iter().map(|(b, a)| json!({
                "blinded": hex(&b.encode()),
                "blindedAnswer": hex(&a.encode()),
            })).collect::<Vec<_>>(),
        });
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&record)?),
        )?;
        println!("recorded in {path}");
    }
    println!("the device is lost: nothing of this run is kept but SEED_FILE and PUBLIC");
    Ok(())
}

/// Tickets `buyer` bought from `paymaster`, from its `Bought` logs.
async fn bought_by<P: Provider>(
    provider: &P,
    paymaster: Address,
    buyer: Address,
) -> anyhow::Result<u64> {
    let logs = provider
        .get_logs(
            &Filter::new()
                .address(paymaster)
                .event_signature(Bought::SIGNATURE_HASH)
                .from_block(0),
        )
        .await?;
    let mut n = 0;
    for l in &logs {
        let e = Bought::decode_log(&l.inner)?;
        if e.buyer == buyer {
            n += e.count.to::<u64>();
        }
    }
    Ok(n)
}

/// A vault's inserted leaves and spent nullifiers, from the registry's events.
async fn vault_events<P: Provider>(
    provider: &P,
    vault: Address,
) -> anyhow::Result<(Vec<(B256, u32, B256)>, Vec<B256>)> {
    let topic = B256::left_padding_from(vault.as_slice());
    let logs = provider
        .get_logs(
            &Filter::new()
                .address(REGISTRY)
                .event_signature(vec![
                    registry_abi::Inserted::SIGNATURE_HASH,
                    registry_abi::Updated::SIGNATURE_HASH,
                ])
                .topic1(topic)
                .from_block(0),
        )
        .await?;
    let mut inserted = vec![];
    let mut spent = vec![];
    for l in &logs {
        if let Ok(e) = registry_abi::Inserted::decode_log(&l.inner) {
            inserted.push((
                e.leaf,
                e.index,
                l.transaction_hash.context("a mined event")?,
            ));
        } else if let Ok(e) = registry_abi::Updated::decode_log(&l.inner) {
            spent.push(e.nullifier);
        }
    }
    Ok((inserted, spent))
}

#[allow(clippy::too_many_lines)]
async fn restore<P: Provider>(provider: &P) -> anyhow::Result<()> {
    let seed = load_seed(false)?;
    let public: Value = serde_json::from_str(&fs::read_to_string(
        env::var("PUBLIC").context("PUBLIC names the public addresses")?,
    )?)?;
    let chain_id = provider.get_chain_id().await?;
    ensure!(public["chainId"].as_u64() == Some(chain_id));
    let paymaster: Address = public["paymaster"].as_str().context("paymaster")?.parse()?;
    let committee_key =
        G2::decode(unhex(public["committeeKey"].as_str().context("committeeKey")?)?.as_slice())
            .map_err(|e| anyhow::anyhow!("committeeKey: {e:?}"))?;
    let mut found = vec![];

    // The account: its address follows from the seed; the chain says whether it exists.
    let owner = seed.owner(0)?;
    let mut accounts = vec![];
    for i in 0..GAP {
        let a = account(&seed, i)?;
        let code = provider.get_code_at(a.address()).await?;
        if code.is_empty() {
            continue;
        }
        let slot0 = provider.get_storage_at(a.address(), U256::ZERO).await?;
        let slot1 = provider.get_storage_at(a.address(), U256::from(1)).await?;
        let balance = provider.get_balance(a.address()).await?;
        ensure!(
            Address::from_word(slot0.into()) == seed.owner(i)?.address(),
            "account {i}'s owner is no longer owner {i}"
        );
        println!(
            "account {i}: {} owned by owner {i}, recovery commitment {}, balance {balance}",
            a.address(),
            B256::from(slot1)
        );
        accounts.push(json!({
            "index": i,
            "address": a.address(),
            "owner": seed.owner(i)?.address(),
            "commitment": B256::from(slot1),
            "balance": balance,
            "from": "CREATE2(account/<i>/salt, owner i), then its code and slots 0 and 1",
        }));
    }
    ensure!(!accounts.is_empty(), "no account found");
    found.push(json!({ "accounts": accounts }));

    // The pool notes: the keychain against the pool's events.
    let kpool = keychain_pool(&pool(), chain_id, 0);
    let keychain = seed.keychain()?;
    let events = pool_events(provider, KEYED_POOL, 0).await?;
    let notes = recover(&keychain, &kpool, &events, None).await?;
    let unspent: Vec<_> = notes.iter().filter(|r| r.withdrawal.is_none()).collect();
    println!(
        "pool: {} note(s) of this keychain among {} events, {} unspent",
        notes.len(),
        events.len(),
        unspent.len()
    );
    found.push(json!({ "poolNotes": notes.iter().map(|r| json!({
        "keychainNonce": r.nonce,
        "leaf": r.deposit.leaf_index,
        "depositBlock": r.deposit.block_number,
        "spent": r.withdrawal.is_some(),
    })).collect::<Vec<_>>() }));

    // The vault notes: the seed's own, by index, then those sealed to the viewing key.
    let scope_raw = provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(REGISTRY)
                .input(Bytes::from(registry_abi::scopeOfCall { vault: VAULT }.abi_encode()).into()),
        )
        .await?;
    let scope = field(U256::from_be_slice(&scope_raw));
    let (inserted, spent) = vault_events(provider, VAULT).await?;
    let find = |s: &Secrets, state: u64| {
        let leaf = B256::from(custody::leaf(scope, s.inner(), state));
        let nullifier = B256::from(custody::nullifier(scope, s));
        inserted
            .iter()
            .find(|(l, _, _)| *l == leaf)
            .map(|(_, index, tx)| (*index, *tx, spent.contains(&nullifier)))
    };
    let mut vault_notes = vec![];
    let (mut j, mut misses) = (0u32, 0u32);
    while misses < GAP {
        if let Some((index, tx, is_spent)) = find(&seed.custody(VAULT, j), VAULT_AMOUNT) {
            println!("vault note {j}: leaf {index}, deposited in {tx}, spent {is_spent}");
            vault_notes.push(json!({ "from": format!("custody/{}/{j}/...", lower(VAULT)),
                "leaf": index, "depositTx": tx, "spent": is_spent }));
            misses = 0;
        } else {
            misses += 1;
        }
        j += 1;
    }
    let view = seed.view()?;
    let board = board_messages(provider, BOARD).await?;
    for (posted, plaintext) in announce::scan(view.secret, &board) {
        let Some((vault, s, state)) = parse_received(&plaintext) else {
            continue;
        };
        ensure!(vault == VAULT);
        let (index, tx, is_spent) =
            find(&s, state).context("a sealed note that is not in the vault")?;
        println!(
            "a sealed note, opened with the viewing key from {}: leaf {index}, deposited in {tx}, spent {is_spent}",
            posted.tx
        );
        vault_notes.push(
            json!({ "from": "view: a sealed announcement", "announcement": posted.tx,
            "leaf": index, "depositTx": tx, "spent": is_spent }),
        );
    }
    ensure!(vault_notes.len() >= 2, "a vault note was not found");
    found.push(json!({ "vaultNotes": vault_notes }));

    // The tickets: how many owner 0 bought, then each one's request recomputed and found on
    // the board with the committee's blinded answer.
    let bought = bought_by(provider, paymaster, owner.address()).await?;
    let mut tickets = vec![];
    for k in 0..u32::try_from(bought)? {
        let t = seed.ticket(k)?;
        let posted = board.iter().find_map(|p| {
            let m = &p.message;
            if m.len() != 1 + 8 + 48 + 48 || m[0] != ANSWER_TAG {
                return None;
            }
            let epoch = u64::from_be_bytes(m[1..9].try_into().ok()?);
            let c = claim(&seed, chain_id, k, epoch).ok()?;
            let (blinded, _) = blind::blind_with(t.blinding.clone(), NAMESPACE, &c.message())?;
            (m[9..57] == blinded.encode()[..]).then(|| (c, G1::decode(&m[57..105]).ok(), p.tx))
        });
        let (c, answer, post) = posted.context("a bought ticket with no answer on the board")?;
        let signature = answer.context("a malformed answer")? * &t.blinding.inv();
        ops::verify_message::<MinSig>(&committee_key, NAMESPACE, &c.message(), &signature)
            .map_err(|e| anyhow::anyhow!("a rebuilt ticket does not verify: {e:?}"))?;
        let nonce = provider.get_transaction_count(t.sender.address()).await?;
        println!(
            "ticket {k}: rebuilt from the answer posted in {post}, verifies; sender {} nonce {nonce}",
            t.sender.address()
        );
        tickets.push((
            Ticket {
                claim: c,
                signature,
            },
            t.sender,
            nonce,
            post,
        ));
    }
    found.push(
        json!({ "tickets": tickets.iter().enumerate().map(|(k, (t, s, n, post))| json!({
        "index": k, "sender": s.address(), "epoch": t.claim.epoch, "answerPost": post,
        "unspent": *n == 0,
    })).collect::<Vec<_>>() }),
    );

    // Spend: a pool note to a derived recipient, a ticket, and the account.
    let mut spends = vec![];
    let mine = unspent.first().context("no unspent pool note")?;
    let note = keychain.note(&kpool, mine.nonce).await?.note;
    let leaves = chain::leaves(provider, KEYED_POOL, mine.deposit.leaf_index as usize).await?;
    let root = B256::from(MerkleTree::from_leaves(&leaves)?.root()?);
    let slot = root_slot(provider, KEYED_POOL, mine.deposit.block_number, root)
        .await?
        .context("no EIP-8272 slot for this root")?;
    let n = next_recipient(provider, &seed).await?;
    let recipient = seed.recipient(n)?.address();
    let payer = Payer {
        address: KEYED_POOL,
        fee: U256::from(POOL_FEE),
        refund: U256::ZERO,
    };
    let proof = prove(note, &leaves, recipient, payer, &mut rand::rng())?;
    let opts = WithdrawalOpts {
        root_slot: Some(slot),
        ..WithdrawalOpts::new(chain_id)
    };
    let tx = withdrawal_tx(&pool(), &proof.inputs, &proof.proof, &opts)?;
    let mut w = executed(provider, &tx, "the rebuilt pool note, withdrawn").await?;
    let received = provider.get_balance(recipient).await?;
    ensure!(received == U256::from(DENOMINATION - u128::from(POOL_FEE)));
    w["recipient"] = json!({ "path": format!("pool/recipient/{n}"), "address": recipient, "received": received });
    spends.push(w);

    let (ticket, sender, _, _) = tickets
        .iter()
        .find(|(_, _, n, _)| *n == 0)
        .context("no unspent ticket")?;
    let fees = rpc::suggest_fees(provider, TIP).await?;
    let tx = spend(
        chain_id,
        fees,
        sender,
        ticket,
        paymaster,
        b"paid with a ticket rebuilt from the seed",
    )?;
    let s = executed(provider, &tx, "a rebuilt ticket, spent").await?;
    ensure!(s["payer"] == json!(paymaster), "the paymaster did not pay");
    spends.push(s);

    let acct = account(&seed, 0)?;
    spends.push(account_tx(provider, &acct, &owner, b"account 0, after the rebuild").await?);

    if let Ok(path) = env::var("RECORD") {
        let record = json!({
            "given": ["the 24 words", "PUBLIC: the contracts' addresses and the committee's public key"],
            "boardMessages": board.len(),
            "found": found,
            "spends": spends,
            "paths": PATHS,
        });
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&record)?),
        )?;
        println!("recorded in {path}");
    }
    Ok(())
}

/// The first `pool/recipient/<n>` with nothing received.
async fn next_recipient<P: Provider>(provider: &P, seed: &Seed) -> anyhow::Result<u32> {
    for n in 0.. {
        let a = seed.recipient(n)?.address();
        if provider.get_balance(a).await?.is_zero() && provider.get_transaction_count(a).await? == 0
        {
            return Ok(n);
        }
    }
    unreachable!()
}
