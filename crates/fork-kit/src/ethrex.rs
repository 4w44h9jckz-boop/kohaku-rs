//! A local ethrex node with EIP-8141 frame transactions live, for tests that send them.
//!
//! anvil has no type `0x06` support, so frame transactions cannot be tested against the anvil
//! fixtures. [`EthrexBuilder`] starts an `ethrex` binary on ethrex's own single-node Hegota
//! genesis (`fixtures/ethrex-l1-hegota.json`, from ethrex `fixtures/genesis/l1-hegota.json` at
//! `379bff04`), with every fork through Hegota active from genesis, and produces blocks itself
//! over the engine API. ethrex's `--dev` mode cannot do this: its block producer sends
//! `engine_forkchoiceUpdatedV4`, which refuses Hegota payload attributes, and the node stops.
//!
//! Build the binary from the commit the ethrex Hegota testnet runs, so that the rules are the
//! testnet's, and point [`ETHREX_BIN`] at it:
//!
//! ```text
//! git clone https://github.com/lambdaclass/ethrex && cd ethrex
//! git checkout 64b8fc09d47d7787eb1a4e3f082aa9e831dc5f8c   # hegota-testnet-hotfix
//! cargo build --release --bin ethrex
//! export ETHREX_BIN=$PWD/target/release/ethrex
//! ```
//!
//! The node installs the EIP-8141 expiry verifier, the EIP-8250 nonce manager and the EIP-8272
//! recent-root predeploys itself, in the first Hegota block, which [`EthrexBuilder::spawn`]
//! produces before it returns. Its mempool admits a `VERIFY` prefix of up to
//! [`TESTNET_MAX_VERIFY_GAS`], as the testnet's nodes do, and the block gas limit and base fee
//! are the testnet's.

use std::{
    net::TcpListener,
    path::PathBuf,
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    primitives::{Address, B256, U256},
    transports::http::reqwest,
};
use anyhow::{Context, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    process::{Child, Command},
    task::JoinHandle,
    time::{Instant, sleep},
};

/// The environment variable naming the `ethrex` binary.
pub const ETHREX_BIN: &str = "ETHREX_BIN";
/// `--mempool.max-verify-gas` on the ethrex Hegota testnet's nodes; EIP-8141 says 100,000.
pub const TESTNET_MAX_VERIFY_GAS: u64 = 500_000;
/// The ethrex Hegota testnet's block gas limit.
pub const TESTNET_GAS_LIMIT: u64 = 200_000_000;
/// The base fee the ethrex Hegota testnet sits at, its EIP-1559 floor: the genesis starts there
/// rather than at 1 gwei, so fees priced for the testnet are valid from the first block.
pub const TESTNET_BASE_FEE: u64 = 7;

const GENESIS: &str = include_str!("../fixtures/ethrex-l1-hegota.json");
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Builder for a local ethrex node.
pub struct EthrexBuilder {
    bin: PathBuf,
    prefund: Vec<(Address, U256)>,
    max_verify_gas: u64,
    block_time: Duration,
}

/// A running ethrex node and the task producing its blocks. Both stop when it is dropped.
pub struct EthrexInstance {
    child: Child,
    producer: JoinHandle<()>,
    rpc_url: String,
    chain_id: u64,
    _dir: tempfile::TempDir,
}

impl EthrexBuilder {
    pub fn new(bin: impl Into<PathBuf>) -> Self {
        Self {
            bin: bin.into(),
            prefund: Vec::new(),
            max_verify_gas: TESTNET_MAX_VERIFY_GAS,
            block_time: Duration::from_secs(1),
        }
    }

    /// The binary named by [`ETHREX_BIN`], or `None` when it is not set.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        std::env::var_os(ETHREX_BIN).map(Self::new)
    }

    /// Give `who` a balance of `wei` at genesis.
    #[must_use]
    pub fn prefund(mut self, who: Address, wei: U256) -> Self {
        self.prefund.push((who, wei));
        self
    }

    /// `--mempool.max-verify-gas`, [`TESTNET_MAX_VERIFY_GAS`] by default.
    #[must_use]
    pub fn max_verify_gas(mut self, gas: u64) -> Self {
        self.max_verify_gas = gas;
        self
    }

    /// How long the producer waits between blocks, one second by default.
    #[must_use]
    pub fn block_time(mut self, block_time: Duration) -> Self {
        self.block_time = block_time;
        self
    }

    /// Start the node, produce its first block, and keep producing one every block time.
    ///
    /// # Errors
    /// Returns an error if the genesis cannot be written, the binary does not start, its RPC
    /// does not answer within 30 seconds, or the first block is refused.
    pub async fn spawn(self) -> Result<EthrexInstance, anyhow::Error> {
        let dir = tempfile::tempdir()?;
        let mut genesis: Value = serde_json::from_str(GENESIS)?;
        genesis["gasLimit"] = json!(format!("{TESTNET_GAS_LIMIT:#x}"));
        genesis["baseFeePerGas"] = json!(format!("{TESTNET_BASE_FEE:#x}"));
        let alloc = genesis["alloc"]
            .as_object_mut()
            .context("genesis has no alloc")?;
        for (who, wei) in &self.prefund {
            alloc.insert(who.to_string(), json!({ "balance": format!("{wei:#x}") }));
        }
        let genesis_path = dir.path().join("genesis.json");
        std::fs::write(&genesis_path, serde_json::to_vec(&genesis)?)?;
        let secret = B256::from(rand::random::<[u8; 32]>());
        let jwt_path = dir.path().join("jwt.hex");
        std::fs::write(&jwt_path, hex::encode(secret))?;
        let log = std::fs::File::create(dir.path().join("ethrex.log"))?;

        let (http_port, auth_port) = (free_port()?, free_port()?);
        let child = Command::new(&self.bin)
            .arg("--network")
            .arg(&genesis_path)
            .arg("--datadir")
            .arg(dir.path().join("db"))
            .args(["--syncmode", "full", "--p2p.disabled"])
            .args([
                "--http.addr",
                "127.0.0.1",
                "--http.port",
                &http_port.to_string(),
            ])
            // `ethrex` for `ethrex_simulateFrameTransaction`, which the testnet also serves.
            .args(["--http.api", "eth,net,web3,ethrex,txpool"])
            .args([
                "--authrpc.addr",
                "127.0.0.1",
                "--authrpc.port",
                &auth_port.to_string(),
            ])
            .arg("--authrpc.jwtsecret")
            .arg(&jwt_path)
            .args(["--mempool.max-verify-gas", &self.max_verify_gas.to_string()])
            .stdout(Stdio::null())
            .stderr(log)
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("starting {}", self.bin.display()))?;

        let rpc_url = format!("http://127.0.0.1:{http_port}");
        let client = reqwest::Client::new();
        let deadline = Instant::now() + READY_TIMEOUT;
        let chain_id = loop {
            if let Ok(id) = rpc(&client, &rpc_url, None, "eth_chainId", json!([])).await {
                break hex_u64(&id)?;
            }
            if Instant::now() >= deadline {
                bail!(
                    "ethrex did not answer on {rpc_url} within {READY_TIMEOUT:?}; its log is {}",
                    dir.path().join("ethrex.log").display()
                );
            }
            sleep(Duration::from_millis(200)).await;
        };

        let mut engine = Engine::new(
            client,
            &rpc_url,
            format!("http://127.0.0.1:{auth_port}"),
            secret,
        )
        .await?;
        engine.produce().await?;
        let block_time = self.block_time;
        let producer = tokio::spawn(async move {
            loop {
                sleep(block_time).await;
                if let Err(e) = engine.produce().await {
                    tracing::error!("ethrex block production failed: {e:#}");
                }
            }
        });
        Ok(EthrexInstance {
            child,
            producer,
            rpc_url,
            chain_id,
            _dir: dir,
        })
    }
}

impl EthrexInstance {
    #[must_use]
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// The genesis's chain id, 9: not the testnet's, so nothing signed here is valid there.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

impl Drop for EthrexInstance {
    fn drop(&mut self) {
        self.producer.abort();
        let _ = self.child.start_kill();
    }
}

/// Stands in for a consensus client: builds each block on the last, with empty withdrawals and
/// inclusion lists, one slot after the last and at least a second later.
struct Engine {
    client: reqwest::Client,
    auth_url: String,
    secret: B256,
    head: Value,
    timestamp: u64,
    slot: u64,
}

impl Engine {
    async fn new(
        client: reqwest::Client,
        rpc_url: &str,
        auth_url: String,
        secret: B256,
    ) -> Result<Self, anyhow::Error> {
        let latest = rpc(
            &client,
            rpc_url,
            None,
            "eth_getBlockByNumber",
            json!(["latest", false]),
        )
        .await?;
        let timestamp = hex_u64(&latest["timestamp"])?;
        let slot = latest
            .get("slotNumber")
            .map(hex_u64)
            .transpose()?
            .unwrap_or(0);
        Ok(Self {
            client,
            auth_url,
            secret,
            head: latest["hash"].clone(),
            timestamp,
            slot,
        })
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, anyhow::Error> {
        rpc(
            &self.client,
            &self.auth_url,
            Some(&jwt(self.secret)?),
            method,
            params,
        )
        .await
    }

    async fn produce(&mut self) -> Result<(), anyhow::Error> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let timestamp = now.max(self.timestamp + 1);
        let slot = self.slot + 1;
        let zero = B256::ZERO.to_string();
        let state = |head: &Value| json!({ "headBlockHash": head, "safeBlockHash": head, "finalizedBlockHash": head });
        let attributes = json!({
            "timestamp": format!("{timestamp:#x}"),
            "prevRandao": zero,
            "suggestedFeeRecipient": Address::ZERO.to_string(),
            "withdrawals": [],
            "parentBeaconBlockRoot": zero,
            "slotNumber": format!("{slot:#x}"),
            "inclusionListTransactions": [],
            "targetGasLimit": format!("{TESTNET_GAS_LIMIT:#x}"),
        });
        let updated = self
            .call(
                "engine_forkchoiceUpdatedV5",
                json!([state(&self.head), attributes, null]),
            )
            .await?;
        let id = updated["payloadId"].clone();
        if id.is_null() {
            bail!("engine_forkchoiceUpdatedV5 returned no payload: {updated}");
        }
        let built = self.call("engine_getPayloadV6", json!([id])).await?;
        let payload = &built["executionPayload"];
        let requests = built.get("executionRequests").cloned().unwrap_or(json!([]));
        let status = self
            .call(
                "engine_newPayloadV6",
                json!([payload, [], zero, requests, []]),
            )
            .await?;
        if status["status"] != "VALID" {
            bail!("engine_newPayloadV6 refused the block it built: {status}");
        }
        let head = payload["blockHash"].clone();
        self.call(
            "engine_forkchoiceUpdatedV5",
            json!([state(&head), null, null]),
        )
        .await?;
        self.head = head;
        self.timestamp = timestamp;
        self.slot = slot;
        Ok(())
    }
}

async fn rpc(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    method: &str,
    params: Value,
) -> Result<Value, anyhow::Error> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let mut req = client
        .post(url)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body)?);
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let mut res: Value = serde_json::from_slice(&req.send().await?.bytes().await?)?;
    if let Some(e) = res.get("error") {
        bail!("{method}: {e}");
    }
    Ok(res["result"].take())
}

fn hex_u64(v: &Value) -> Result<u64, anyhow::Error> {
    let s = v.as_str().context("expected a hex string")?;
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

fn free_port() -> Result<u16, anyhow::Error> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

/// The engine API's HS256 token over `{"iat": now}`.
fn jwt(secret: B256) -> Result<String, anyhow::Error> {
    let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let signing = format!(
        "{}.{}",
        base64url(br#"{"alg":"HS256","typ":"JWT"}"#),
        base64url(format!(r#"{{"iat":{iat}}}"#).as_bytes())
    );
    let mac = hmac_sha256(secret.as_slice(), signing.as_bytes());
    Ok(format!("{signing}.{}", base64url(&mac)))
}

/// HMAC-SHA256 (RFC 2104) for a key no longer than the 64-byte block.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..key.len()].copy_from_slice(key);
    let pad = |byte: u8| block.map(|b| b ^ byte);
    let inner = Sha256::new()
        .chain_update(pad(0x36))
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .into()
}

/// Base64url without padding (RFC 4648 section 5).
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc_4231_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn base64url_has_no_padding() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }
}
