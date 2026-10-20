//! The wallet: one account, its batches and the sessions it granted.

use std::collections::HashMap;

use alloy::{
    primitives::{Address, B256, U64, U256},
    providers::{DynProvider, Provider},
    transports::http::reqwest,
};
use kohaku_frame_accounts::{
    account::{Eoa, FrameAccount, Signer},
    builder::{Envelope, TxPlan},
    session::SessionAccount,
};
use kohaku_frame_kit::{
    Frame, FrameSignature, FrameSigner, FrameTx,
    constants::ENTRY_POINT,
    gas::max_cost,
    rpc::{self, ExecuteError},
    sign_all,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    binding::{PaymasterResult, QuotedSponsor, RpcFrameTx},
    calls::{
        DRAFT_EXECUTION, SendCallsParams, batch_tx, call_frame_indexes, call_frames, status_code,
        tightened,
    },
    error::ProviderError,
    permissions::{Granted, PermissionRequest, context_of, supported},
};

/// The tip the wallet offers: 1 gwei, over twice the base fee.
pub const TIP: u128 = 1_000_000_000;

/// Who sends: an account with no code, or a `SessionAccount` the key owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletAccount {
    Eoa(Eoa),
    Session(SessionAccount),
}

impl FrameAccount for WalletAccount {
    fn address(&self) -> Address {
        match self {
            Self::Eoa(a) => a.address(),
            Self::Session(a) => a.address(),
        }
    }

    fn verify_frame(&self, scope: u8) -> Frame {
        match self {
            Self::Eoa(a) => a.verify_frame(scope),
            Self::Session(a) => a.verify_frame(scope),
        }
    }

    fn signature_entries(&self) -> Vec<FrameSignature> {
        match self {
            Self::Eoa(a) => a.signature_entries(),
            Self::Session(a) => a.signature_entries(),
        }
    }
}

/// Gas limits before and after estimation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Estimate {
    pub draft_max_cost: U256,
    pub final_max_cost: U256,
    pub draft_limits: U64,
    pub final_limits: U64,
}

/// What the wallet remembers about a batch: enough to answer `wallet_getCallsStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Batch {
    pub id: String,
    pub chain_id: U64,
    pub hash: B256,
    #[serde(skip)]
    pub tx: FrameTx,
    pub atomic: bool,
    /// Index of each call's frame in the transaction.
    pub call_frames: Vec<usize>,
    /// Every round trip and signature this batch cost, in order.
    pub trace: Vec<String>,
    pub estimate: Estimate,
}

pub struct Wallet {
    provider: DynProvider,
    http: reqwest::Client,
    key: FrameSigner,
    account: WalletAccount,
    chain_id: u64,
    batches: HashMap<String, Batch>,
    granted: Vec<Granted>,
    owner_txs: Vec<OwnerTx>,
}

/// A transaction the account's owner sent for the dapp: a grant or a revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerTx {
    pub purpose: String,
    pub hash: B256,
    pub block_number: U256,
    pub gas_used: U256,
}

fn limits(tx: &FrameTx) -> U64 {
    U64::from(
        tx.frames
            .iter()
            .map(|f| f.limits.execution + f.limits.state)
            .sum::<u64>(),
    )
}

fn internal(e: impl std::fmt::Display) -> ProviderError {
    ProviderError::internal(e.to_string())
}

impl Wallet {
    /// A wallet for `key`'s account on the node `provider` talks to.
    pub async fn new(
        provider: DynProvider,
        key: FrameSigner,
        account: WalletAccount,
    ) -> Result<Self, ProviderError> {
        let chain_id = provider.get_chain_id().await.map_err(internal)?;
        Ok(Self {
            provider,
            http: reqwest::Client::new(),
            key,
            account,
            chain_id,
            batches: HashMap::new(),
            granted: Vec::new(),
            owner_txs: Vec::new(),
        })
    }

    /// An account with no code for `key`.
    #[must_use]
    pub fn eoa(key: &FrameSigner) -> WalletAccount {
        WalletAccount::Eoa(Eoa::new(Signer::from(key)))
    }

    #[must_use]
    pub fn address(&self) -> Address {
        self.account.address()
    }

    #[must_use]
    pub fn provider(&self) -> &DynProvider {
        &self.provider
    }

    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The grants and revocations the owner has sent, in order.
    #[must_use]
    pub fn owner_txs(&self) -> &[OwnerTx] {
        &self.owner_txs
    }

    #[must_use]
    pub fn batch(&self, id: &str) -> Option<&Batch> {
        self.batches.get(id)
    }

    /// `wallet_getCapabilities`. Every account here batches atomically without an upgrade: an
    /// EOA through the protocol's default code, so `supported` rather than `ready`.
    #[must_use]
    pub fn capabilities(&self, chains: Option<Vec<U64>>) -> Value {
        let mine = U64::from(self.chain_id);
        let mut out = serde_json::Map::new();
        for c in chains.unwrap_or_else(|| vec![mine]) {
            if c == mine {
                out.insert(
                    format!("{mine:#x}"),
                    json!({ "atomic": { "status": "supported" }, "paymasterService": { "supported": true } }),
                );
            }
        }
        Value::Object(out)
    }

    async fn envelope(&self) -> Result<Envelope, ProviderError> {
        Envelope::fetch(&self.provider, self.address(), vec![U256::ZERO], TIP)
            .await
            .map_err(internal)
    }

    async fn paymaster(
        &self,
        url: &str,
        method: &str,
        tx: &FrameTx,
        context: Option<&Value>,
        trace: &mut Vec<String>,
    ) -> Result<PaymasterResult, ProviderError> {
        trace.push(method.to_owned());
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": [RpcFrameTx::from(tx), ENTRY_POINT, U64::from(self.chain_id), context.cloned().unwrap_or(json!({}))],
        });
        let res = self
            .http
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(internal)?
            .bytes()
            .await
            .map_err(internal)?;
        let mut reply: Value = serde_json::from_slice(&res).map_err(internal)?;
        if let Some(e) = reply.get("error") {
            let message = e.get("message").and_then(Value::as_str).unwrap_or_default();
            return Err(ProviderError::internal(format!(
                "paymaster service refused ({method}): {message}"
            )));
        }
        serde_json::from_value(reply["result"].take()).map_err(internal)
    }

    fn sign(
        &self,
        mut tx: FrameTx,
        trace: &mut Vec<String>,
        what: &str,
    ) -> Result<FrameTx, ProviderError> {
        trace.push(format!("user signs ({what})"));
        sign_all(&mut tx, std::slice::from_ref(&self.key)).map_err(internal)?;
        Ok(tx)
    }

    async fn simulate(
        &self,
        tx: &FrameTx,
        trace: &mut Vec<String>,
        what: &str,
    ) -> Result<Vec<u64>, ProviderError> {
        trace.push(format!("simulate ({what})"));
        let sim = rpc::simulate(&self.provider, tx, "latest")
            .await
            .map_err(internal)?;
        if !sim.valid {
            return Err(ProviderError::internal(format!(
                "{what}: {}",
                sim.violation.unwrap_or_default()
            )));
        }
        Ok(sim
            .frames
            .unwrap_or_default()
            .iter()
            .map(|f| f.gas_used.to())
            .collect())
    }

    /// `wallet_sendCalls`: build the batch's frame transaction, estimate it with a signed draft,
    /// tighten the call frames, sign and send. Returns the batch id.
    pub async fn send_calls(&mut self, p: SendCallsParams) -> Result<Value, ProviderError> {
        p.check(self.chain_id, self.address())?;
        if let Some(id) = &p.id
            && self.batches.contains_key(id)
        {
            return Err(ProviderError::new(5720, format!("duplicate id {id}")));
        }
        let service = p.paymaster_service()?;
        let atomic = p.atomic_required;
        let mut trace = Vec::new();
        let envelope = self.envelope().await?;
        let n = p.calls.len();
        let build = |execution: &[u64], sponsor: Option<&mut QuotedSponsor>| {
            let frames = call_frames(&p.calls, atomic, execution);
            batch_tx(
                &self.account,
                sponsor.map(|s| s as &mut dyn kohaku_frame_accounts::sponsor::Sponsor),
                frames,
                &envelope,
            )
            .map_err(internal)
        };
        let quote = |r: &PaymasterResult| QuotedSponsor::from_result(r).map_err(internal);

        let draft_execution = vec![DRAFT_EXECUTION; n];
        let mut sponsor = service.as_ref().map(|_| QuotedSponsor::default());
        let mut tx = build(&draft_execution, sponsor.as_mut())?;
        if let Some(s) = &service {
            let stub = self
                .paymaster(
                    &s.url,
                    "pm_getPaymasterStubData",
                    &tx,
                    s.context.as_ref(),
                    &mut trace,
                )
                .await?;
            sponsor = Some(quote(&stub)?);
            tx = build(&draft_execution, sponsor.as_mut())?;
            // The node simulates only a transaction whose prefix approves, so the stub cannot
            // be simulated: the draft needs the payer's real signature and the user's.
            let data = self
                .paymaster(
                    &s.url,
                    "pm_getPaymasterData",
                    &tx,
                    s.context.as_ref(),
                    &mut trace,
                )
                .await?;
            sponsor = Some(quote(&data)?);
            tx = build(&draft_execution, sponsor.as_mut())?;
        }
        let draft = self.sign(tx.clone(), &mut trace, "draft, for estimation")?;
        let used = self.simulate(&draft, &mut trace, "draft").await?;
        let draft_max_cost = max_cost(&draft, 0).map_err(internal)?;
        let draft_limits = limits(&draft);

        // The final transaction: call frames tightened, everything else as estimated.
        let indexes = call_frame_indexes(&tx);
        let execution: Vec<u64> = indexes
            .iter()
            .map(|&i| tightened(used.get(i).copied().unwrap_or(DRAFT_EXECUTION)))
            .collect();
        tx = build(&execution, sponsor.as_mut())?;
        if let Some(s) = &service {
            let data = self
                .paymaster(
                    &s.url,
                    "pm_getPaymasterData",
                    &tx,
                    s.context.as_ref(),
                    &mut trace,
                )
                .await?;
            sponsor = Some(quote(&data)?);
            tx = build(&execution, sponsor.as_mut())?;
        }
        let tx = self.sign(tx, &mut trace, "final")?;
        self.simulate(&tx, &mut trace, "final").await?;
        trace.push("eth_sendRawTransaction".to_owned());
        let hash = rpc::send(&self.provider, &tx).await.map_err(internal)?;
        let estimate = Estimate {
            draft_max_cost,
            final_max_cost: max_cost(&tx, 0).map_err(internal)?,
            draft_limits,
            final_limits: limits(&tx),
        };
        let id = self.record(p.id.clone(), hash, tx, atomic, indexes, trace, estimate);
        Ok(json!({ "id": id }))
    }

    /// Keep what `wallet_getCallsStatus` will need, under the dapp's id or a fresh one.
    #[allow(clippy::too_many_arguments)]
    fn record(
        &mut self,
        id: Option<String>,
        hash: B256,
        tx: FrameTx,
        atomic: bool,
        call_frames: Vec<usize>,
        trace: Vec<String>,
        estimate: Estimate,
    ) -> String {
        let id = id.unwrap_or_else(|| B256::from(rand::random::<[u8; 32]>()).to_string());
        let batch = Batch {
            id: id.clone(),
            chain_id: U64::from(self.chain_id),
            hash,
            tx,
            atomic,
            call_frames,
            trace,
            estimate,
        };
        self.batches.insert(id.clone(), batch);
        id
    }

    /// `wallet_getCallsStatus`, from the frame receipts. Logs come only from the calls' frames:
    /// not the payer's, not a post-op's.
    pub async fn calls_status(&self, id: &str) -> Result<Value, ProviderError> {
        let b = self
            .batches
            .get(id)
            .ok_or_else(|| ProviderError::new(5730, format!("unknown bundle id {id}")))?;
        let receipt: Option<Value> = self
            .provider
            .raw_request("eth_getTransactionReceipt".into(), (b.hash,))
            .await
            .map_err(internal)?;
        let mut out =
            json!({ "version": "2.0.0", "id": id, "chainId": b.chain_id, "atomic": b.atomic });
        let Some(r) = receipt else {
            out["status"] = json!(100);
            return Ok(out);
        };
        let frames = r["frameReceipts"].as_array().cloned().unwrap_or_default();
        let status_of = |f: &Value| {
            f["status"]
                .as_str()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0)
        };
        let calls: Vec<u64> = b
            .call_frames
            .iter()
            .map(|&i| frames.get(i).map_or(0, status_of))
            .collect();
        let status = status_code(b.atomic, &calls);
        let logs: Vec<Value> = b
            .call_frames
            .iter()
            .filter_map(|&i| frames.get(i))
            .flat_map(|f| f["logs"].as_array().cloned().unwrap_or_default())
            .collect();
        out["status"] = json!(status);
        out["receipts"] = json!([{
            "logs": logs,
            "status": if status == 200 { "0x1" } else { "0x0" },
            "blockHash": r["blockHash"],
            "blockNumber": r["blockNumber"],
            "gasUsed": r["gasUsed"],
            "transactionHash": r["transactionHash"],
        }]);
        out["capabilities"] = json!({ "frames": {
            "payer": r["payer"],
            "frameStatuses": frames.iter().map(status_of).collect::<Vec<_>>(),
        }});
        Ok(out)
    }

    fn session_account(&self) -> Result<SessionAccount, ProviderError> {
        match self.account {
            WalletAccount::Session(a) => Ok(a),
            WalletAccount::Eoa(_) => Err(ProviderError::unsupported_method(
                "execution permissions need a SessionAccount: an account with no code cannot check a session key",
            )),
        }
    }

    /// `wallet_getSupportedExecutionPermissions`.
    pub fn supported_permissions(&self) -> Result<Value, ProviderError> {
        self.session_account()?;
        Ok(supported(self.chain_id))
    }

    /// The owner's own transaction making `frames`, sent and confirmed.
    async fn owner_tx(&mut self, purpose: &str, frames: Vec<Frame>) -> Result<B256, ProviderError> {
        let envelope = self.envelope().await?;
        let mut tx = TxPlan::new(&self.account)
            .calls(frames)
            .build(&envelope)
            .map_err(internal)?;
        sign_all(&mut tx, std::slice::from_ref(&self.key)).map_err(internal)?;
        let executed = rpc::execute(&self.provider, &tx, true)
            .await
            .map_err(|e: ExecuteError| ProviderError::internal(e.to_string()))?;
        if executed.receipt.status != U256::from(1) {
            return Err(ProviderError::internal(format!(
                "the owner's transaction {} failed",
                executed.hash
            )));
        }
        self.owner_txs.push(OwnerTx {
            purpose: purpose.to_owned(),
            hash: executed.hash,
            block_number: executed.receipt.block_number,
            gas_used: executed.receipt.gas_used,
        });
        Ok(executed.hash)
    }

    /// `wallet_requestExecutionPermissions`: one session per request, each granted by an owner
    /// transaction before the answer is returned. Nothing is granted unless every request can be.
    pub async fn request_permissions(
        &mut self,
        requests: Vec<PermissionRequest>,
    ) -> Result<Value, ProviderError> {
        let account = self.session_account()?;
        let address = account.address();
        let code = self.provider.get_code_at(address).await.map_err(internal)?;
        if code.is_empty() {
            return Err(ProviderError::new(
                4100,
                format!(
                    "{address} is not deployed; a SessionAccount cannot deploy itself in a validation prefix"
                ),
            ));
        }
        let policies = requests
            .iter()
            .map(|r| r.policy(self.chain_id, address))
            .collect::<Result<Vec<_>, _>>()?;
        let frames = requests
            .iter()
            .zip(&policies)
            .map(|(r, p)| account.add_session(r.to, p))
            .collect();
        self.owner_tx("grant", frames).await?;
        let granted: Vec<Granted> = requests
            .into_iter()
            .zip(policies)
            .map(|(request, policy)| Granted {
                key: request.to,
                request,
                account: address,
                policy,
            })
            .collect();
        let out = granted.iter().map(Granted::response).collect();
        self.granted.extend(granted);
        Ok(Value::Array(out))
    }

    /// `wallet_getGrantedExecutionPermissions`: every grant not revoked.
    #[must_use]
    pub fn granted_permissions(&self) -> Value {
        Value::Array(self.granted.iter().map(Granted::response).collect())
    }

    /// `wallet_revokeExecutionPermission`: the owner removes the session `context` names.
    pub async fn revoke_permission(&mut self, context: &[u8]) -> Result<Value, ProviderError> {
        let account = self.session_account()?;
        let i = self
            .granted
            .iter()
            .position(|g| context_of(g.account, g.key)[..] == *context)
            .ok_or_else(|| {
                ProviderError::invalid_params("no granted permission has this context")
            })?;
        self.owner_tx("revoke", vec![account.revoke_session(self.granted[i].key)])
            .await?;
        self.granted.remove(i);
        Ok(json!({}))
    }
}
