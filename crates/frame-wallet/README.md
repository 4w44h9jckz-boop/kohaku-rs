# kohaku-frame-wallet

Experimental. An EIP-5792 wallet over EIP-8141 frame transactions, on top of
`kohaku-frame-accounts`: `wallet_sendCalls`, `wallet_getCallsStatus` and `wallet_getCapabilities`
as an EIP-1193 provider, with ERC-7677's `paymasterService` bound to frames as `exp-frames`
experiment 28 binds it. The binary `frame-wallet` serves one account over HTTP JSON-RPC.
