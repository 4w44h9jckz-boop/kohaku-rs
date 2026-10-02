use alloy::{
    network::TransactionBuilder, primitives::Address, rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use ruint::aliases::U256;

use crate::{
    abis::{erc20::ERC20, tornado::Tornado},
    asset::Asset,
    note::Note,
    pool::Pool,
};

/// A Tornado Cash deposit.
#[derive(Debug, Clone)]
pub struct Deposit {
    pub pool: Pool,
    pub note: Note,
}

impl Deposit {
    #[must_use]
    pub fn new(pool: &Pool, note: Note) -> Self {
        Self {
            pool: pool.clone(),
            note,
        }
    }

    /// Returns the value required for this deposit transaction.
    ///
    /// For ERC20 pools, this will be zero since the ERC20 token is transferred via
    /// a `transferFrom` call.
    #[must_use]
    pub fn value(&self) -> U256 {
        match self.pool.asset {
            Asset::Native { .. } => U256::from(self.pool.amount_wei),
            Asset::Erc20 { .. } => U256::ZERO,
        }
    }

    /// Returns the input data for this deposit transaction.
    #[must_use]
    pub fn input(&self) -> Vec<u8> {
        let deposit_call = Tornado::depositCall {
            _commitment: self.note().commitment().into(),
        };

        deposit_call.abi_encode()
    }

    /// Returns the target address for this deposit transaction.
    #[must_use]
    pub fn target(&self) -> Address {
        self.pool.address
    }

    /// Returns the ERC20 approval transaction this deposit requires, if any.
    ///
    /// Native-asset pools return [`None`]. ERC20 pools pull the deposit with `transferFrom`, so
    /// the depositor must approve the pool to spend the pool's denomination first, or the
    /// deposit transaction will revert.
    #[must_use]
    pub fn approval(&self) -> Option<TransactionRequest> {
        let Asset::Erc20 { address, .. } = self.pool.asset else {
            return None;
        };

        let approve_call = ERC20::approveCall {
            spender: self.pool.address,
            amount: U256::from(self.pool.amount_wei),
        };

        Some(
            TransactionRequest::default()
                .with_to(address)
                .input(approve_call.abi_encode().into()),
        )
    }

    /// Returns the note associated with this deposit.
    #[must_use]
    pub fn note(&self) -> Note {
        self.note.clone()
    }
}

impl From<Deposit> for TransactionRequest {
    fn from(deposit: Deposit) -> Self {
        TransactionRequest::default()
            .with_to(deposit.target())
            .with_value(deposit.value())
            .input(deposit.input().into())
    }
}
