//! `exp-frames` experiment 47's run, read back from its public record
//! (`tests/fixtures/record47.json`, copied from that experiment): each backup was posted as its
//! locator, a nonce, whole buckets and a tag, from a fresh sender; and the fresh device reopened
//! exactly what the lost one wrote, by SHA-256.

use alloy::{
    primitives::{B256, Bytes},
    sol_types::SolCall,
};
use kohaku_frame_kit::{FrameTx, constants::mode};
use kohaku_frame_secrets::backup::{BUCKET, OVERHEAD};
use serde::Deserialize;

alloy::sol! {
    function post(bytes message);
}

#[derive(Deserialize)]
struct Record {
    write: Write,
    reopen: Reopen,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Write {
    backups: Vec<Backup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Backup {
    hash: B256,
    raw: Bytes,
    locator: B256,
    plaintext_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Reopen {
    versions: Vec<Version>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Version {
    tx: B256,
    plaintext_sha256: String,
}

#[test]
fn backups_are_posted_as_buckets_and_reopened_unchanged() {
    let r: Record = serde_json::from_str(include_str!("fixtures/record47.json")).unwrap();
    assert_eq!(r.write.backups.len(), 2);
    for (b, v) in r.write.backups.iter().zip(&r.reopen.versions) {
        let tx = FrameTx::decode(&b.raw).unwrap();
        assert_eq!(tx.hash(), b.hash);
        assert_eq!(tx.nonce_seq, 0, "a fresh sender");
        let post = tx.frames.iter().find(|f| f.mode == mode::SENDER).unwrap();
        let m = postCall::abi_decode(&post.data).unwrap().message;
        assert_eq!(&m[..32], b.locator.as_slice());
        assert_eq!((m.len() - OVERHEAD) % BUCKET, 0);
        assert_eq!((v.tx, &v.plaintext_sha256), (b.hash, &b.plaintext_sha256));
    }
}
