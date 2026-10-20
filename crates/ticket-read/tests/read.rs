//! A private read paid with a ticket, offline: the committee issues blind read tickets, a server
//! on a local port answers PIR queries for a table of random accounts, and `kohaku-pir-rpc`'s
//! router reads a balance through the ticket-paying backend.

use std::{collections::BTreeMap, sync::Arc};

use alloy::primitives::{Address, B256, U256};
use kohaku_frame_ticket::{Committee, blind};
use kohaku_pir_rpc::{CallPath, PirRouter};
use kohaku_ticket_read::{
    Account, ReadClaim, ReadTicket, Reader, Server, Table, TicketLookup, ticket::READ_NAMESPACE,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use serde_json::{Value, json};

fn accounts(rng: &mut StdRng, n: usize) -> BTreeMap<Address, Account> {
    (0..n)
        .map(|_| {
            (
                Address::from(rng.random::<[u8; 20]>()),
                Account {
                    delegate: Address::ZERO,
                    balance: U256::from(rng.random::<u64>()),
                    nonce: rng.random_range(0..1_000),
                },
            )
        })
        .collect()
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

#[tokio::test(flavor = "multi_thread")]
async fn a_balance_read_through_the_router_costs_one_ticket() {
    let mut rng = StdRng::seed_from_u64(5);
    let mut committee = Committee::dkg(&mut rng, 4).unwrap();
    let accounts = accounts(&mut rng, 300);
    let salts: Vec<B256> = (0..64)
        .map(|_| B256::from(rng.random::<[u8; 32]>()))
        .collect();
    let table = Table::build(&accounts, 8, salts).unwrap();
    let server_id = B256::from(rng.random::<[u8; 32]>());
    let server = Arc::new(Server::new(
        table,
        *committee.sharing.public(),
        server_id,
        B256::repeat_byte(7),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(axum::serve(listener, server.clone().router()).into_future());

    let reader = Arc::new(Reader::connect(&base).await.unwrap());
    let good = issue(&mut rng, &mut committee, server_id);
    let other_server = issue(&mut rng, &mut committee, B256::ZERO);
    reader.add_tickets([good]);
    let router = PirRouter::with_rpc(
        Arc::new(TicketLookup {
            reader: reader.clone(),
            runtime: tokio::runtime::Handle::current(),
        }),
        "http://127.0.0.1:1",
        vec![],
    )
    .unwrap();

    // One read through the router: the balance, from PIR.
    let (address, account) = accounts.iter().nth(123).unwrap();
    let (value, path) = router
        .request_with_path("eth_getBalance", json!([address, "latest"]))
        .await
        .unwrap();
    assert!(matches!(path, CallPath::Pir), "{path:?}");
    assert_eq!(value, json!(format!("{:#x}", account.balance)));

    // No ticket left: the next read is not sent.
    assert!(
        router
            .request("eth_getTransactionCount", json!([address, "latest"]))
            .await
            .is_err()
    );

    // The spent ticket again, and a ticket for another server: refused before any work.
    let q = vec![0u32; reader.manifest.cols];
    let again = reader.send(&q, &good).await.unwrap_err().to_string();
    assert!(again.contains("a spent ticket"), "{again}");
    let wrong = reader
        .send(&q, &other_server)
        .await
        .unwrap_err()
        .to_string();
    assert!(wrong.contains("no ticket for this server"), "{wrong}");

    let log: Vec<Value> = reqwest::get(format!("{base}/log"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(log.len(), 3);
    assert!(log[0].get("answerMicros").is_some());
    for refused in &log[1..] {
        assert!(refused.get("answerMicros").is_none());
    }
    // What the server saw: serials, verdicts, timings and sizes. No address.
    let seen = serde_json::to_string(&log).unwrap().to_lowercase();
    assert!(!seen.contains(&format!("{address:x}")[2..]));
}
