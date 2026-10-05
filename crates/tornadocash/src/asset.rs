use std::borrow::Cow;

use alloy::primitives::{Address, address};
use serde::{Deserialize, Serialize};

/// Represents an asset in a tornadocash pool.
///
/// Assets can either be native (e.g. ETH, MATIC) or ERC20 tokens.
///
/// Defines a set of known Tornado Cash assets as constants. The constants are
/// named in the format `<ASSET>` for native tokens, and `<CHAIN>_<ASSET>` for ERC20
/// tokens. E.g. `ETH` for native ETH, and `ETHEREUM_DAI` for the DAI token on
/// Ethereum mainnet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Asset {
    Native {
        symbol: Cow<'static, str>,
        decimals: u8,
    },
    Erc20 {
        address: Address,
        symbol: Cow<'static, str>,
        decimals: u8,
    },
}

impl Asset {
    pub const ETH: Asset = Asset::Native {
        symbol: Cow::Borrowed("eth"),
        decimals: 18,
    };

    pub const MATIC: Asset = Asset::Native {
        symbol: Cow::Borrowed("matic"),
        decimals: 18,
    };

    pub const ETHEREUM_DAI: Asset = Asset::Erc20 {
        address: address!("0x6B175474E89094C44Da98b954EedeAC495271d0F"),
        symbol: Cow::Borrowed("dai"),
        decimals: 18,
    };

    #[must_use]
    pub fn symbol(&self) -> &str {
        match self {
            Asset::Native { symbol, .. } | Asset::Erc20 { symbol, .. } => symbol,
        }
    }

    #[must_use]
    pub fn decimals(&self) -> u8 {
        match self {
            Asset::Native { decimals, .. } | Asset::Erc20 { decimals, .. } => *decimals,
        }
    }
}
