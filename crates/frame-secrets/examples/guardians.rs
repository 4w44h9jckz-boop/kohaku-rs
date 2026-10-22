//! Guardians who hold shares of a recovery key, never of the seed: `exp-frames` experiment 46,
//! on the ethrex Hegota testnet, with experiment 45's account 0.
//!
//! ```text
//! SEED_FILE=... STATE_DIR=... PRIVATE_KEY=0x... PUBLIC=public46.json RECORD=setup.json \
//!   MODE=setup cargo run --release -p kohaku-frame-secrets --example guardians
//! STATE_DIR=... PUBLIC=public46.json RECORD=recover.json \
//!   MODE=recover cargo run --release -p kohaku-frame-secrets --example guardians
//! ```
//!
//! `STATE_DIR` stands for the parties' separate storage: `phrase.txt`, the phrase the user keeps
//! in mind, and `guardian-<g>.json`, each guardian's own. A party reads only its own.
//!
//! `MODE=setup`, while the owner's device holds the seed:
//! 1. the user picks a phrase; the funder pays six guardians a little gas;
//! 2. the owner buys three tickets from a new committee, issued for the seed's tickets 2 to 4;
//! 3. a recovery key `R0`, split 2-of-3 to guardians 1 to 3; the account's commitment set to it;
//!    the seed's envelope under `R0` and the phrase posted from ticket 2's fresh sender; `R0`
//!    erased;
//! 4. guardians 2 and 3, told the account and its salt, start a recovery to a key of their own;
//!    the owner cancels; their finish is refused. The same two also open an envelope sealed
//!    under `R0` alone, the construction the claim fails under, and fail on the real one;
//! 5. rotation: `R1`, split to guardians 4 to 6, a new commitment and envelope (ticket 3);
//!    guardians 1 and 2's attempt with `R0` is refused before inclusion.
//!
//! `MODE=recover`, after every device is lost. The new device has the phrase and `PUBLIC`.
//! Guardians 4 and 6 post their shares sealed to its transport key. It joins `R1`, opens the
//! envelope, and so has the seed; `R1` starts a recovery to owner 1, which finishes after the
//! delay. Then owner 1 rotates to `R2` and guardians 7 to 9, posting the envelope from ticket 4,
//! rebuilt from the board. Last, guardians 1 and 2 with the phrase open the first envelope, which
//! is still on the board.
//!
//! With `RECOVERED_SEED_FILE` set, `MODE=recover` writes the recovered mnemonic there (mode 0600)
//! for the next step, such as `seed_wallet MODE=restore` with that file as its `SEED_FILE`.
//!
//! No key, share, phrase or word is printed or recorded.

mod common;

use std::{env, fs, path::PathBuf, time::Instant};

use alloy::{
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, ensure};
use common::{
    BOARD, account, account_tx, buy_tickets, executed, hex, load_seed, rebuild_ticket, refused,
    send, spend, unhex, wait_until,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::bls12381::primitives::group::G2;
use kohaku_frame_accounts::{builder::Envelope, recovery::Devices};
use kohaku_frame_kit::{Frame, constants::STORAGE_SET_STATE_GAS, rpc};
use kohaku_frame_registry::announce::{self, Keys, board_messages, post_frame};
use kohaku_frame_secrets::{
    Seed,
    guardians::{self, ENVELOPE_LEN, ENVELOPE_TAG, Share, locator},
};
use kohaku_frame_ticket::TicketSponsor;
use kohaku_tornadocash_keychain::recovery::recover;
use rand::RngExt;
use serde_json::{Value, json};

const T: usize = 2;
const N: usize = 3;
const GUARDIAN_GAS: U256 = U256::from_limbs([2_000_000_000_000_000, 0, 0, 0]);
/// The seed's ticket indices this run uses; experiment 45 used 0 and 1.
const FIRST_TICKET: u32 = 2;
const TIP: u128 = common::TIP;
/// A board message carrying a guardian's share, sealed to the new device.
const SHARE_TAG: &[u8] = b"kohaku-guardian-share-v1";

fn state(name: &str) -> anyhow::Result<PathBuf> {
    Ok(PathBuf::from(env::var("STATE_DIR").context("STATE_DIR")?).join(name))
}

/// A guardian's own storage.
#[derive(serde::Serialize, serde::Deserialize)]
struct Guardian {
    /// Its own key, to post with.
    key: String,
    /// Which set it belongs to, and its share of that set's recovery key.
    set: u32,
    share: String,
}

impl Guardian {
    fn load(g: usize) -> anyhow::Result<(PrivateKeySigner, Share)> {
        let s: Self =
            serde_json::from_str(&fs::read_to_string(state(&format!("guardian-{g}.json"))?)?)?;
        Ok((s.key.parse()?, Share::decode(&unhex(&s.share)?)?))
    }

    fn store(g: usize, key: &PrivateKeySigner, set: u32, share: &Share) -> anyhow::Result<()> {
        let s = Self {
            key: hex(key.to_bytes().as_slice()),
            set,
            share: hex(&share.encode()),
        };
        fs::write(
            state(&format!("guardian-{g}.json"))?,
            serde_json::to_string(&s)?,
        )?;
        Ok(())
    }
}

fn guardian_key(g: usize) -> anyhow::Result<PrivateKeySigner> {
    let path = state(&format!("guardian-{g}.key"))?;
    if let Ok(k) = fs::read_to_string(&path) {
        return Ok(k.trim().parse()?);
    }
    let k = PrivateKeySigner::random();
    fs::write(&path, hex(k.to_bytes().as_slice()))?;
    Ok(k)
}

/// Five words from BIP-39's list, about 55 bits: the phrase the user keeps.
fn new_phrase() -> anyhow::Result<String> {
    use alloy::signers::local::coins_bip39::{English, Wordlist};
    let mut rng = rand::rng();
    let words: Vec<&str> = (0..5)
        .map(|_| English::get(rng.random_range(0..2048)))
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    Ok(words.join(" "))
}

/// The commitment for recovery key `r` of the account's `set`-th guardian set.
fn devices(seed: &Seed, set: u32, r: Address) -> Devices {
    Devices {
        salt: seed.recovery_salt(0, set),
        m: 1,
        devices: vec![r],
    }
}

/// A recovery key, its commitment, its envelope, and its shares stored with guardians `first..`.
fn new_set(
    seed: &Seed,
    words: &str,
    phrase: &str,
    set: u32,
    first: usize,
) -> anyhow::Result<(Address, Devices, Vec<u8>, Vec<u8>)> {
    let mut rng = rand::rng();
    let r = PrivateKeySigner::random();
    let started = Instant::now();
    let stretched = guardians::stretch(phrase, r.address());
    println!(
        "Argon2id of the phrase: {} ms",
        started.elapsed().as_millis()
    );
    let envelope = guardians::seal(words, &r, Some(&stretched), &mut rng)?;
    let weak = guardians::seal(words, &r, None, &mut rng)?;
    for (g, share) in guardians::split(&r, T, N, &mut rng).iter().enumerate() {
        Guardian::store(first + g, &guardian_key(first + g)?, set, share)?;
    }
    let d = devices(seed, set, r.address());
    Ok((r.address(), d, envelope, weak))
    // `r` is dropped here: the recovery key is not kept.
}

/// The account's `VERIFY` envelope for its own transactions.
async fn envelope<P: Provider>(provider: &P, account: Address) -> anyhow::Result<Envelope> {
    Ok(Envelope::fetch(provider, account, vec![U256::ZERO], TIP).await?)
}

fn words_of(seed_file: &str) -> anyhow::Result<String> {
    Ok(fs::read_to_string(seed_file)?.trim().to_owned())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| rpc::HEGOTA_RPC_URL.to_owned());
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    match env::var("MODE").as_deref() {
        Ok("setup") => setup(&provider).await,
        Ok("recover") => recover_mode(&provider).await,
        _ => anyhow::bail!("MODE is setup or recover"),
    }
}

#[allow(clippy::too_many_lines)]
async fn setup<P: Provider>(provider: &P) -> anyhow::Result<()> {
    let funder: PrivateKeySigner = env::var("PRIVATE_KEY").context("PRIVATE_KEY")?.parse()?;
    let seed = load_seed()?;
    let words = words_of(&env::var("SEED_FILE")?)?;
    let chain_id = provider.get_chain_id().await?;
    let owner = seed.owner(0)?;
    let acct = account(&seed, 0)?;
    ensure!(
        !provider.get_code_at(acct.address()).await?.is_empty(),
        "no account 0: run experiment 45 first"
    );
    let mut steps = vec![];

    // 1. The phrase, and gas for the guardians.
    let phrase = new_phrase()?;
    fs::write(state("phrase.txt")?, &phrase)?;
    let guardians: Vec<PrivateKeySigner> = (1..=9).map(guardian_key).collect::<Result<_, _>>()?;
    steps.push(
        send(
            provider,
            &funder,
            guardians
                .iter()
                .map(|g| {
                    Frame::sender(Some(g.address()))
                        .with_value(GUARDIAN_GAS)
                        .with_execution(10_000)
                        .with_state(TicketSponsor::NEW_ACCOUNT_STATE)
                })
                .collect(),
            "the funder pays nine guardians gas",
        )
        .await?,
    );

    // 2. Tickets for the envelopes' posts.
    let tickets = buy_tickets(provider, &seed, &owner, FIRST_TICKET, 3).await?;
    steps.extend(tickets.steps.iter().cloned());
    let post_envelope = |k: usize, envelope: &[u8], what: &'static str| {
        let ticket = tickets.issued[k].clone();
        let sender = seed.ticket(FIRST_TICKET + k as u32).map(|t| t.sender);
        let envelope = envelope.to_vec();
        async move {
            let fees = rpc::suggest_fees(provider, TIP).await?;
            let tx = spend(
                chain_id,
                fees,
                &sender?,
                &ticket,
                tickets.paymaster,
                &envelope,
            )?;
            executed(provider, &tx, what).await
        }
    };

    // 3. Set 0.
    let (r0, d0, e0, weak0) = new_set(&seed, &words, &phrase, 0, 1)?;
    let tx = account_tx(
        &envelope(provider, acct.address()).await?,
        &acct.signed_by(owner.address()),
        std::slice::from_ref(&owner),
        // The account was deployed with an empty commitment: the first one is a fresh slot.
        vec![acct.set_devices(&d0).with_state(STORAGE_SET_STATE_GAS)],
    )?;
    steps.push(executed(provider, &tx, "the owner commits the account to R0").await?);
    steps.push(
        post_envelope(
            0,
            &e0,
            "the envelope under R0 and the phrase, posted from a fresh sender paid with a ticket",
        )
        .await?,
    );

    // 4. A hostile attempt by guardians 2 and 3, who also know the account and its salt.
    let (_, s2) = Guardian::load(2)?;
    let (_, s3) = Guardian::load(3)?;
    let quorum = guardians::join(&[s2, s3], T)?;
    ensure!(quorum.address() == r0);
    let thief = PrivateKeySigner::random();
    let tx = account_tx(
        &envelope(provider, acct.address()).await?,
        &acct.signed_by_devices(&d0),
        std::slice::from_ref(&quorum),
        vec![acct.start(thief.address())],
    )?;
    steps.push(
        executed(
            provider,
            &tx,
            "guardians 2 and 3 start a recovery to their own key",
        )
        .await?,
    );
    let slot2 = provider
        .get_storage_at(acct.address(), U256::from(2))
        .await?;
    let unlock = (slot2 & U256::from(u128::MAX >> 32)).to::<u64>();
    let tx = account_tx(
        &envelope(provider, acct.address()).await?,
        &acct.signed_by(owner.address()),
        std::slice::from_ref(&owner),
        vec![acct.cancel()],
    )?;
    let cancel = executed(provider, &tx, "the owner cancels inside the delay").await?;
    steps.push(cancel);
    wait_until(provider, unlock).await?;
    let tx = account_tx(
        &envelope(provider, acct.address()).await?,
        &acct.signed_by(thief.address()),
        std::slice::from_ref(&thief),
        vec![acct.finish()],
    )?;
    let mut refusals = vec![
        refused(
            provider,
            &tx,
            "their finish, after the delay, once cancelled",
        )
        .await?,
    ];

    // What the same two get from the envelopes. Under R0 alone: the seed, at once.
    let mut quorum_view = vec![];
    let opened = guardians::open(&weak0, &quorum, None)?;
    let theirs = Seed::from_mnemonic(&opened)?;
    let keychain = theirs.keychain()?;
    let pool = common_pool(chain_id);
    let events = kohaku_frame_wallet::recovery::pool_events(provider, pool.address, 0).await?;
    let notes = recover(&keychain, &pool, &events, None).await?;
    quorum_view.push(json!({
        "envelope": "under R0 alone (not posted)",
        "opened": true,
        "owner0Matches": theirs.owner(0)?.address() == owner.address(),
        "poolNotesListed": notes.len(),
        "delayApplied": false,
    }));
    println!(
        "guardians 2 and 3 open an envelope under R0 alone: the seed, owner 0 matches, {} pool note(s) listed, no delay",
        notes.len()
    );
    let without_phrase = guardians::open(&e0, &quorum, None).is_ok();
    let wrong_phrase =
        guardians::open(&e0, &quorum, Some(&guardians::stretch("a guess", r0))).is_ok();
    quorum_view.push(json!({
        "envelope": "under R0 and the phrase (posted)",
        "openedWithoutThePhrase": without_phrase,
        "openedWithAGuess": wrong_phrase,
    }));
    ensure!(!without_phrase && !wrong_phrase);
    drop(quorum);

    // 5. Rotation to set 1, with nothing from set 0.
    let (r1, d1, e1, _) = new_set(&seed, &words, &phrase, 1, 4)?;
    let tx = account_tx(
        &envelope(provider, acct.address()).await?,
        &acct.signed_by(owner.address()),
        std::slice::from_ref(&owner),
        vec![acct.set_devices(&d1)],
    )?;
    steps.push(executed(provider, &tx, "the owner rotates to R1, guardians 4 to 6").await?);
    steps.push(
        post_envelope(
            1,
            &e1,
            "the envelope under R1 and the phrase, posted from a fresh sender paid with a ticket",
        )
        .await?,
    );
    let (_, s1) = Guardian::load(1)?;
    let (_, s2) = Guardian::load(2)?;
    let old = guardians::join(&[s1, s2], T)?;
    ensure!(old.address() == r0);
    let tx = account_tx(
        &envelope(provider, acct.address()).await?,
        &acct.signed_by_devices(&d0),
        &[old],
        vec![acct.start(PrivateKeySigner::random().address())],
    )?;
    refusals.push(refused(provider, &tx, "the old set's start, after the rotation").await?);

    let public = json!({
        "chainId": chain_id,
        "account": acct.address(),
        "paymaster": tickets.paymaster,
        "committeeKey": hex(&tickets.committee_key.encode()),
        "firstTicket": FIRST_TICKET,
        "board": BOARD,
        "threshold": T,
        "guardians": N,
    });
    fs::write(
        env::var("PUBLIC").context("PUBLIC")?,
        format!("{}\n", serde_json::to_string_pretty(&public)?),
    )?;
    if let Ok(path) = env::var("RECORD") {
        let record = json!({
            "public": public,
            "owner0": owner.address(),
            "recoveryKeys": [r0, r1],
            "commitments": [d0.commitment(), d1.commitment()],
            "guardians": guardians.iter().enumerate().map(|(g, k)| json!({
                "guardian": g + 1, "address": k.address(),
                "set": match g { 0..=2 => json!(0), 3..=5 => json!(1), _ => json!(2) },
            })).collect::<Vec<_>>(),
            "unlock": unlock,
            "steps": steps,
            "refusals": refusals,
            "quorumOfSet0": quorum_view,
        });
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&record)?),
        )?;
        println!("recorded in {path}");
    }
    println!(
        "the owner's devices are lost: the user keeps the phrase; guardians 4 to 6 keep their shares"
    );
    Ok(())
}

fn common_pool(chain_id: u64) -> kohaku_tornadocash::Pool {
    kohaku_frame_wallet::recovery::keychain_pool(
        &kohaku_frame_pool::withdrawal::FramePool {
            address: alloy::primitives::address!("0x73e47a8DA2C83Beb802708Fc473B5B7D094f3eE6"),
            mode: kohaku_frame_pool::withdrawal::PoolMode::Keyed,
            salt: alloy::primitives::keccak256("exp-frames/06/pool-keyed"),
        },
        chain_id,
        0,
    )
}

/// `SHARE_TAG || announcement sealed to the device`.
fn share_message(to: &[u8; 33], share: &Share) -> anyhow::Result<Vec<u8>> {
    let ephemeral = Keys::from_secret(B256::from(rand::rng().random::<[u8; 32]>()))?;
    let mut m = SHARE_TAG.to_vec();
    m.extend(announce::seal(to, &share.encode(), &ephemeral)?);
    Ok(m)
}

#[allow(clippy::too_many_lines)]
async fn recover_mode<P: Provider>(provider: &P) -> anyhow::Result<()> {
    let public: Value =
        serde_json::from_str(&fs::read_to_string(env::var("PUBLIC").context("PUBLIC")?)?)?;
    let chain_id = provider.get_chain_id().await?;
    let account_address: Address = public["account"].as_str().context("account")?.parse()?;
    let mut steps = vec![];

    // 1. The new device's transport key; guardians 4 and 6 post their shares sealed to it.
    let transport = Keys::from_secret(B256::from(rand::rng().random::<[u8; 32]>()))?;
    for g in [4, 6] {
        let (key, share) = Guardian::load(g)?;
        steps.push(
            send(
                provider,
                &key,
                vec![post_frame(
                    BOARD,
                    &share_message(&transport.public, &share)?,
                )],
                &format!("guardian {g} posts its share, sealed to the new device"),
            )
            .await?,
        );
    }

    // 2. The device: the shares, R1, the envelope, the seed.
    let board = board_messages(provider, BOARD).await?;
    let shares: Vec<Share> = board
        .iter()
        .filter(|p| p.message.starts_with(SHARE_TAG))
        .filter_map(|p| announce::open(transport.secret, &p.message[SHARE_TAG.len()..]))
        .filter_map(|b| Share::decode(&b).ok())
        .collect();
    let r1 = guardians::join(&shares, T)?;
    let phrase = fs::read_to_string(state("phrase.txt")?)?;
    let found = board
        .iter()
        .find(|p| {
            p.message.len() == ENVELOPE_LEN
                && p.message[0] == ENVELOPE_TAG
                && p.message[1..33] == locator(r1.address())[..]
        })
        .context("no envelope for R1 on the board")?;
    let started = Instant::now();
    let words = guardians::open(
        &found.message,
        &r1,
        Some(&guardians::stretch(&phrase, r1.address())),
    )?;
    let open_ms = started.elapsed().as_millis();
    let seed = Seed::from_mnemonic(&words)?;
    if common::hand_on_recovered(&words)? {
        println!("the recovered mnemonic is in RECOVERED_SEED_FILE");
    }
    let acct = account(&seed, 0)?;
    ensure!(
        acct.address() == account_address,
        "the seed does not give the account"
    );
    let d1 = devices(&seed, 1, r1.address());
    let slot1 = provider
        .get_storage_at(acct.address(), U256::from(1))
        .await?;
    ensure!(
        B256::from(slot1) == d1.commitment(),
        "the account is not committed to R1"
    );
    println!(
        "the new device joined {} shares into R1, found its envelope in {}, opened it with the phrase ({open_ms} ms): the seed gives account {}",
        shares.len(),
        found.tx,
        acct.address()
    );

    // 3. R1 starts a recovery to owner 1; owner 1 finishes after the delay.
    let owner1 = seed.owner(1)?;
    let tx = account_tx(
        &envelope(provider, acct.address()).await?,
        &acct.signed_by_devices(&d1),
        std::slice::from_ref(&r1),
        vec![acct.start(owner1.address())],
    )?;
    steps.push(executed(provider, &tx, "R1 starts a recovery to owner 1").await?);
    let slot2 = provider
        .get_storage_at(acct.address(), U256::from(2))
        .await?;
    let unlock = (slot2 & U256::from(u128::MAX >> 32)).to::<u64>();
    let reached = wait_until(provider, unlock).await?;
    println!("unlock at {unlock}, head at {reached}");
    let tx = account_tx(
        &envelope(provider, acct.address()).await?,
        &acct.signed_by(owner1.address()),
        std::slice::from_ref(&owner1),
        vec![acct.finish()],
    )?;
    steps.push(executed(provider, &tx, "owner 1 finishes after the delay").await?);
    let slot0 = provider.get_storage_at(acct.address(), U256::ZERO).await?;
    ensure!(
        Address::from_word(slot0.into()) == owner1.address(),
        "owner 1 does not own the account"
    );

    // 4. Owner 1 rotates to R2, guardians 7 to 9, posting from ticket 4, rebuilt from the board.
    let words_now = seed_words(&seed, &words);
    let (r2, d2, e2, _) = new_set(&seed, &words_now, &phrase, 2, 7)?;
    let tx = account_tx(
        &envelope(provider, acct.address()).await?,
        &acct.signed_by(owner1.address()),
        std::slice::from_ref(&owner1),
        vec![acct.set_devices(&d2)],
    )?;
    steps.push(executed(provider, &tx, "owner 1 rotates to R2, guardians 7 to 9").await?);
    let key = G2::decode(unhex(public["committeeKey"].as_str().context("key")?)?.as_slice())
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let paymaster: Address = public["paymaster"].as_str().context("paymaster")?.parse()?;
    let k = FIRST_TICKET + 2;
    let (ticket, answer_post) = rebuild_ticket(&seed, chain_id, k, &board, &key)?;
    println!("ticket {k} rebuilt from {answer_post}");
    let fees = rpc::suggest_fees(provider, TIP).await?;
    let tx = spend(
        chain_id,
        fees,
        &seed.ticket(k)?.sender,
        &ticket,
        paymaster,
        &e2,
    )?;
    steps.push(executed(provider, &tx, "the envelope under R2 and the phrase, posted from a fresh sender paid with a rebuilt ticket").await?);

    // 5. The first envelope is still on the board: set 0 and the phrase open it.
    let (_, s1) = Guardian::load(1)?;
    let (_, s2) = Guardian::load(2)?;
    let r0 = guardians::join(&[s1, s2], T)?;
    let e0 = board
        .iter()
        .find(|p| p.message.len() == ENVELOPE_LEN && p.message[1..33] == locator(r0.address())[..])
        .context("no envelope for R0")?;
    let old_opens = guardians::open(
        &e0.message,
        &r0,
        Some(&guardians::stretch(&phrase, r0.address())),
    )
    .is_ok_and(|w| w == words);
    println!(
        "set 0 and the phrase open the envelope still on the board from {}: {old_opens}",
        e0.tx
    );

    if let Ok(path) = env::var("RECORD") {
        let record = json!({
            "given": ["the phrase", "PUBLIC", "guardians 4 and 6, who post their shares"],
            "sharesJoined": shares.len(),
            "envelopeFound": found.tx,
            "openMillis": open_ms,
            "account": acct.address(),
            "owner1": owner1.address(),
            "recoveryKeys": [r1.address(), r2],
            "commitment2": d2.commitment(),
            "unlock": unlock,
            "steps": steps,
            "ticketRebuiltFrom": answer_post,
            "oldEnvelope": { "tx": e0.tx, "openedBySet0WithThePhrase": old_opens },
        });
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&record)?),
        )?;
        println!("recorded in {path}");
    }
    Ok(())
}

/// The seed's words as the envelope carries them.
fn seed_words(_seed: &Seed, words: &str) -> String {
    words.to_owned()
}
