//! Checked reads, offline: a state trie of random accounts built with `alloy-trie`, a header
//! that commits to its root, an honest server and two lying ones, and the third party.

use std::{collections::BTreeMap, sync::Arc};

use alloy::{
    primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256, keccak256},
    rlp::Encodable,
    trie::{EMPTY_ROOT_HASH, HashBuilder, Nibbles, proof::ProofRetainer},
};
use kohaku_checked_read::{
    Checked, CheckedLookup, CheckedReader, CheckedTable, Entry, Evidence, Header, Server, Verdict,
    evidence::Dismissed,
    judge, statement,
    table::CLAIM,
    trie::{self, AccountState, Nodes},
};
use kohaku_frame_ticket::{Committee, blind};
use kohaku_pir_rpc::{CallPath, PirRouter};
use kohaku_ticket_read::{
    Account, ReadClaim, ReadTicket, pir,
    server::{hex_to_words, words_to_hex},
    table::bucket,
    ticket::READ_NAMESPACE,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use serde_json::json;

const BLOCK: u64 = 4_242;

fn state_of(a: &Account) -> AccountState {
    AccountState {
        nonce: a.nonce,
        balance: a.balance,
        storage_root: EMPTY_ROOT_HASH,
        code_hash: if a.delegate.is_zero() {
            KECCAK256_EMPTY
        } else {
            keccak256([&[0xef, 0x01, 0x00][..], a.delegate.as_slice()].concat())
        },
    }
}

/// `n` random accounts, one with a delegate, in a state trie: its root, and each account's
/// branch from the root down.
fn state(rng: &mut StdRng, n: usize) -> (B256, BTreeMap<Address, Entry>) {
    let accounts: BTreeMap<Address, Account> = (0..n)
        .map(|i| {
            (
                Address::from(rng.random::<[u8; 20]>()),
                Account {
                    delegate: if i == 0 {
                        Address::repeat_byte(0x77)
                    } else {
                        Address::ZERO
                    },
                    balance: U256::from(rng.random::<u64>()),
                    nonce: rng.random_range(0..1_000),
                },
            )
        })
        .collect();
    let mut leaves: Vec<(Nibbles, Address)> = accounts
        .keys()
        .map(|a| (Nibbles::unpack(keccak256(a)), *a))
        .collect();
    leaves.sort();
    let mut hb = HashBuilder::default()
        .with_proof_retainer(ProofRetainer::new(leaves.iter().map(|(k, _)| *k).collect()));
    for (k, a) in &leaves {
        hb.add_leaf(*k, &state_of(&accounts[a]).encode());
    }
    let root = hb.root();
    let proofs = hb.take_proof_nodes();
    let entries = leaves
        .iter()
        .map(|(k, a)| {
            let proof = proofs
                .matching_nodes_sorted(k)
                .into_iter()
                .map(|(_, n)| n)
                .collect();
            (
                *a,
                Entry {
                    account: accounts[a],
                    proof,
                },
            )
        })
        .collect();
    (root, entries)
}

/// A header of block [`BLOCK`] whose state root is `root`.
fn header(root: B256) -> Header {
    let mut payload = vec![];
    for i in 0..23 {
        match i {
            3 => root.encode(&mut payload),
            8 => BLOCK.encode(&mut payload),
            _ => B256::repeat_byte(i).encode(&mut payload),
        }
    }
    Header::decode(&trie::list(&payload)).unwrap()
}

fn issue(rng: &mut StdRng, committee: &mut Committee, server: B256) -> ReadTicket {
    let claim = ReadClaim {
        server,
        serial: B256::from(rng.random::<[u8; 32]>()),
    };
    let (b, r) = blind::blind(rng, READ_NAMESPACE, &claim.message());
    let quorum = committee.quorum();
    let answers: Vec<_> = committee
        .issuers
        .iter_mut()
        .take(quorum)
        .map(|i| i.answer(&b))
        .collect();
    ReadTicket {
        claim,
        signature: blind::unblind(&committee.sharing, &answers, &r).unwrap(),
    }
}

struct Running {
    reader: Arc<CheckedReader>,
    server: Arc<Server>,
    table: CheckedTable,
}

/// A server for `entries` on a local port, and a reader of it holding `header`.
async fn serve(
    rng: &mut StdRng,
    committee: &Committee,
    entries: &BTreeMap<Address, Entry>,
    split: usize,
    header: &Header,
) -> Running {
    let salts: Vec<B256> = (0..64)
        .map(|_| B256::from(rng.random::<[u8; 32]>()))
        .collect();
    let table = CheckedTable::build(entries, 4, split, salts).unwrap();
    let signer = alloy::signers::local::PrivateKeySigner::random();
    let server = Arc::new(Server::new(
        table.clone(),
        *committee.sharing.public(),
        signer,
        B256::repeat_byte(9),
        header.number,
        header.state_root,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(axum::serve(listener, server.clone().router()).into_future());
    let reader = CheckedReader::with_header(&base, server.manifest.clone(), header.clone())
        .await
        .unwrap();
    Running {
        reader: Arc::new(reader),
        server,
        table,
    }
}

#[test]
fn the_walk_proves_each_account_and_the_absence_of_others() {
    let mut rng = StdRng::seed_from_u64(1);
    let (root, entries) = state(&mut rng, 200);
    let all: Nodes = entries.values().flat_map(|e| e.proof.iter()).collect();
    for (a, e) in &entries {
        let own: Nodes = e.proof.iter().collect();
        let st = trie::account(root, *a, &own).unwrap().unwrap();
        assert!(st.is(&e.account.value()));
    }
    for _ in 0..50 {
        let absent = Address::from(rng.random::<[u8; 20]>());
        assert_eq!(trie::account(root, absent, &all), Ok(None));
    }
    // A branch with its leaf forged does not reach the root.
    let (a, e) = entries.iter().nth(5).unwrap();
    let mut forged = state_of(&e.account);
    forged.balance += U256::from(1);
    let mut proof = e.proof.clone();
    let leaf = proof.pop().unwrap();
    proof.push(trie::reencode_leaf(&leaf, &forged).unwrap().into());
    let nodes: Nodes = proof.iter().collect();
    assert!(matches!(
        trie::account(root, *a, &nodes),
        Err(trie::TrieError::Missing(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_checked_read_through_the_router_and_two_lies_refused_and_judged() {
    let mut rng = StdRng::seed_from_u64(5);
    let mut committee = Committee::dkg(&mut rng, 4).unwrap();
    let (root, entries) = state(&mut rng, 120);
    let header = header(root);
    let (target, true_entry) = entries
        .iter()
        .nth(17)
        .map(|(a, e)| (*a, e.clone()))
        .unwrap();

    // The honest server, the branch split at depth 1: a read through the router, proven.
    let honest = serve(&mut rng, &committee, &entries, 1, &header).await;
    honest.reader.add_tickets([issue(
        &mut rng,
        &mut committee,
        honest.server.manifest.server,
    )]);
    let router = PirRouter::with_rpc(
        Arc::new(CheckedLookup {
            reader: honest.reader.clone(),
            runtime: tokio::runtime::Handle::current(),
        }),
        "http://127.0.0.1:1",
        vec![],
    )
    .unwrap();
    let (value, path) = router
        .request_with_path("eth_getBalance", json!([target, "latest"]))
        .await
        .unwrap();
    assert!(matches!(path, CallPath::Pir), "{path:?}");
    assert_eq!(value, json!(format!("{:#x}", true_entry.account.balance)));
    assert!(honest.table.top_bytes() > 0);

    // An address the table does not hold: no record, so no answer, never an empty account.
    honest.reader.add_tickets([issue(
        &mut rng,
        &mut committee,
        honest.server.manifest.server,
    )]);
    let absent = Address::from(rng.random::<[u8; 20]>());
    let err = honest.reader.read(absent).await.unwrap_err().to_string();
    assert!(err.contains("unanswered"), "{err}");

    // Lie 1: the balance changed in the record, the true branch kept.
    let mut lied = entries.clone();
    lied.get_mut(&target).unwrap().account.balance += U256::from(10u64.pow(18));
    // Lie 2: the leaf re-encoded with the changed balance as well.
    let mut forged = lied.clone();
    {
        let e = forged.get_mut(&target).unwrap();
        let leaf = e.proof.pop().unwrap();
        e.proof.push(
            trie::reencode_leaf(&leaf, &state_of(&e.account))
                .unwrap()
                .into(),
        );
    }
    let chain: Nodes = true_entry.proof.iter().collect();
    for (lie, split, why) in [
        (&lied, 0, "the branch proves another account"),
        (&forged, 2, "does not reach the header's state root"),
    ] {
        let liar = serve(&mut rng, &committee, lie, split, &header).await;
        liar.reader
            .add_tickets([issue(&mut rng, &mut committee, liar.server.manifest.server)]);
        let Checked::Refused { why: got, evidence } = liar.reader.read(target).await.unwrap()
        else {
            panic!("a lie was accepted");
        };
        assert!(got.contains(why), "{got}");
        assert_eq!(liar.reader.refused().len(), 1);

        // The third party: the evidence, its own header and its own branch of the account.
        let verdict = judge(&evidence, &header, &chain).unwrap();
        let Verdict::Wrong {
            address,
            signed,
            chain: Some(st),
        } = verdict
        else {
            panic!("{verdict:?}");
        };
        assert_eq!(address, target);
        assert_eq!(signed, lie[&target].account.value());
        assert!(st.is(&true_entry.account.value()));

        // Evidence tampered with is dismissed.
        let mut e = (*evidence).clone();
        e.claimed = Bytes::from([target.as_slice(), &true_entry.account.value()].concat());
        assert_eq!(judge(&e, &header, &chain), Err(Dismissed::Claim));
        let mut e = (*evidence).clone();
        e.hint_rows[3] = words_to_hex(&vec![1u32; pir::N]);
        assert!(matches!(
            judge(&e, &header, &chain),
            Err(Dismissed::HintRow(_))
        ));
        let mut e = (*evidence).clone();
        let mut answer = hex_to_words(&e.answer).unwrap();
        answer[0] ^= 1;
        e.answer = words_to_hex(&answer);
        assert_eq!(judge(&e, &header, &chain), Err(Dismissed::Signature));
        let mut other = header.clone();
        other.number += 1;
        assert!(matches!(
            judge(&evidence, &other, &chain),
            Err(Dismissed::Header(_))
        ));
    }
}

/// Evidence assembled by hand against `run`'s server: what a reader would publish for `query`.
fn evidence_for(
    run: &Running,
    query: &[u32],
    secret: &[u32],
    column: usize,
    slot: usize,
    answer: &[u32],
    signature: String,
) -> Evidence {
    let m = &run.server.manifest;
    let a = pir::public_matrix(m.seed.0, m.cols);
    let hint = run.table.db.hint(&a);
    let rows: Vec<usize> = (0..CLAIM).map(|k| slot * m.record + k).collect();
    let mut claimed = vec![];
    for &r in &rows {
        let hs = hint[r * pir::N..(r + 1) * pir::N]
            .iter()
            .zip(secret)
            .fold(0u32, |acc, (&x, &y)| acc.wrapping_add(x.wrapping_mul(y)));
        claimed.push((answer[r].wrapping_sub(hs).wrapping_add(pir::DELTA / 2) >> 24) as u8);
    }
    Evidence {
        manifest: m.clone(),
        query: words_to_hex(query),
        answer: words_to_hex(answer),
        signature,
        secret: words_to_hex(secret),
        column,
        slot,
        hint_rows: rows
            .iter()
            .map(|&r| words_to_hex(&hint[r * pir::N..(r + 1) * pir::N]))
            .collect(),
        hint_paths: statement::hint_paths(&hint, pir::N, rows.iter().copied()),
        claimed: claimed.into(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reader_cannot_frame_an_honest_server() {
    let mut rng = StdRng::seed_from_u64(8);
    let mut committee = Committee::dkg(&mut rng, 4).unwrap();
    let (root, entries) = state(&mut rng, 60);
    let header = header(root);
    let run = serve(&mut rng, &committee, &entries, 1, &header).await;
    let m = run.server.manifest.clone();
    let (target, e) = entries.iter().next().unwrap();
    let chain: Nodes = e.proof.iter().collect();
    let col = bucket(m.salt, target.as_slice(), m.cols);
    let a = pir::public_matrix(m.seed.0, m.cols);
    let slot = {
        let column = &run.table.db.data[col * m.rows..(col + 1) * m.rows];
        kohaku_checked_read::table::find(column, m.record, target.as_slice())
            .unwrap()
            .slot
    };

    // A well-formed query, opened: the honest answer is judged correct.
    let (q, secret) = pir::query(&mut rng, &a, m.cols, col);
    let ticket = issue(&mut rng, &mut committee, m.server);
    let (answer, sig) = run.reader.send(&q, &ticket).await.unwrap();
    let ev = evidence_for(&run, &q, secret.open(), col, slot, &answer, sig);
    assert_eq!(
        judge(&ev, &header, &chain),
        Ok(Verdict::Correct { address: *target })
    );

    // A query with an error far too large decodes to noise, and is dismissed as malformed.
    let mut noisy = q.clone();
    for (i, x) in noisy.iter_mut().enumerate() {
        if i != col {
            *x = x.wrapping_add(1 << 22);
        }
    }
    let ticket = issue(&mut rng, &mut committee, m.server);
    let (answer, sig) = run.reader.send(&noisy, &ticket).await.unwrap();
    let ev = evidence_for(&run, &noisy, secret.open(), col, slot, &answer, sig);
    assert!(matches!(
        judge(&ev, &header, &chain),
        Err(Dismissed::Query(_))
    ));
}
