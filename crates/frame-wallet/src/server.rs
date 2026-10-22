//! The wallet as an EIP-1193 provider over HTTP JSON-RPC, so a dapp in any language can talk to
//! it: `wallet_*` methods are the wallet's, everything else goes to the node.
//!
//! `kohaku_getBatch` and `kohaku_getOwnerTransactions` are not standard methods. They return
//! what the wallet recorded about a batch (its hash, round trips and limits) and the grants and
//! revocations it sent, for experiments that report them.

use std::sync::Arc;

use alloy::{
    primitives::{Bytes, U64},
    providers::Provider,
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

use crate::{
    calls::SendCallsParams, error::ProviderError, permissions::PermissionRequest, wallet::Wallet,
};

fn param<T: serde::de::DeserializeOwned>(params: &Value, i: usize) -> Result<T, ProviderError> {
    serde_json::from_value(params.get(i).cloned().unwrap_or(Value::Null))
        .map_err(|e| ProviderError::invalid_params(format!("parameter {i}: {e}")))
}

/// Answer one request.
pub async fn dispatch(
    wallet: &Mutex<Wallet>,
    method: &str,
    params: &Value,
) -> Result<Value, ProviderError> {
    let mut w = wallet.lock().await;
    match method {
        "eth_chainId" => Ok(json!(U64::from(w.chain_id()))),
        "eth_accounts" | "eth_requestAccounts" => Ok(json!([w.address()])),
        "wallet_getCapabilities" => Ok(w.capabilities(param::<Option<Vec<U64>>>(params, 1)?)),
        "wallet_sendCalls" => w.send_calls(param::<SendCallsParams>(params, 0)?).await,
        "wallet_getCallsStatus" => w.calls_status(&param::<String>(params, 0)?).await,
        "wallet_showCallsStatus" => {
            let id = param::<String>(params, 0)?;
            w.batch(&id)
                .map(|_| Value::Null)
                .ok_or_else(|| ProviderError::new(5730, "unknown bundle id"))
        }
        "wallet_getSupportedExecutionPermissions" => w.supported_permissions(),
        "wallet_requestExecutionPermissions" => {
            w.request_permissions(param::<Vec<PermissionRequest>>(params, 0)?)
                .await
        }
        "wallet_getGrantedExecutionPermissions" => Ok(w.granted_permissions()),
        "wallet_revokeExecutionPermission" => {
            let p: Value = param(params, 0)?;
            let context: Bytes = serde_json::from_value(p["permissionContext"].clone())
                .map_err(|e| ProviderError::invalid_params(format!("permissionContext: {e}")))?;
            w.revoke_permission(&context).await
        }
        "kohaku_getBatch" => {
            let id = param::<String>(params, 0)?;
            w.batch(&id)
                .map(|b| serde_json::to_value(b).unwrap_or_default())
                .ok_or_else(|| ProviderError::new(5730, "unknown bundle id"))
        }
        "kohaku_getOwnerTransactions" => {
            Ok(serde_json::to_value(w.owner_txs()).unwrap_or_default())
        }
        // A wallet method this wallet does not have is its own answer to give, not the node's.
        m if m.starts_with("wallet_") => Err(ProviderError::unsupported_method(format!(
            "{m} is not supported"
        ))),
        _ => {
            let provider = w.provider().clone();
            drop(w);
            provider
                .raw_request::<_, Value>(method.to_owned().into(), params.clone())
                .await
                .map_err(|e| ProviderError::internal(e.to_string()))
        }
    }
}

async fn handle(wallet: Arc<Mutex<Wallet>>, stream: TcpStream) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await?;
    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = request.get("params").cloned().unwrap_or(json!([]));
    let reply = match dispatch(&wallet, method, &params).await {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(e) => {
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": e.code, "message": e.message } })
        }
    }
    .to_string();
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        reply.len()
    );
    write.write_all(head.as_bytes()).await?;
    write.write_all(reply.as_bytes()).await?;
    write.shutdown().await
}

/// Serve `wallet` on `listener` until the process ends.
pub async fn serve(wallet: Wallet, listener: TcpListener) -> std::io::Result<()> {
    let wallet = Arc::new(Mutex::new(wallet));
    loop {
        let (stream, _) = listener.accept().await?;
        let wallet = wallet.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(wallet, stream).await {
                eprintln!("frame-wallet: {e}");
            }
        });
    }
}
