//! 4337 `SimpleSmartAccount` deployment.
//!
//! `SimpleSmartAccount` is a minimal ERC-7702 impl that can be used for testing purposes. The
//! bytecode is pulled from pimlicolabs/alto's [e2e tests](https://github.com/pimlicolabs/alto/blob/main/test/e2e/deploy-contracts/constants.ts).

use alloy::{
    network::TransactionBuilder,
    primitives::{Address, Bytes, address},
    providers::{DynProvider, Provider},
    rpc::types::TransactionRequest,
};

const DETERMINISTIC_DEPLOYER: Address = address!("0x4e59b44847b379578588920ca78fbf26c0b4956c");

const SIMPLE_7702_ACCOUNT_IMPLEMENTATION_V08_CREATECALL: &str =
    include_str!("../fixtures/simple_7702_account_v08.createcall.hex");
pub const SIMPLE_7702_ACCOUNT_IMPLEMENTATION_V08: Address =
    address!("0xe6Cae83BdE06E4c305530e199D7217f42808555B");

/// Deploys a new `SimpleSmartAccount` implementation contract.
///
/// Returns the address of the deployed implementation ([`SIMPLE_7702_ACCOUNT_IMPLEMENTATION_V08`]).
///
/// # Errors
/// Returns an error if the deploy transaction fails.
pub async fn deploy_simple_account(provider: &DynProvider) -> Result<Address, anyhow::Error> {
    let data: Bytes = SIMPLE_7702_ACCOUNT_IMPLEMENTATION_V08_CREATECALL
        .trim()
        .parse()?;

    provider
        .send_transaction(
            TransactionRequest::default()
                .with_to(DETERMINISTIC_DEPLOYER)
                .with_input(data)
                .with_gas_limit(15_000_000),
        )
        .await?
        .get_receipt()
        .await?;

    anyhow::ensure!(
        !provider
            .get_code_at(SIMPLE_7702_ACCOUNT_IMPLEMENTATION_V08)
            .await?
            .is_empty(),
        "expected contract code at {SIMPLE_7702_ACCOUNT_IMPLEMENTATION_V08} after deploying \
         Simple7702Account implementation"
    );

    Ok(SIMPLE_7702_ACCOUNT_IMPLEMENTATION_V08)
}
