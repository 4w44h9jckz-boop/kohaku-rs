//! Applying a format to decoded values: ERC-7730's field formats and interpolated intents.

use alloy::primitives::{Address, U256};
use serde_json::Value;

use crate::{
    descriptor::{Field, Format, Metadata, Token, json_u256, json_val},
    value::{Val, Values},
};

/// ERC-7730's container values for one call: `@.from`, `@.to`, `@.value` and `@.chainId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Container {
    pub chain_id: u64,
    /// The caller: the sender for a `SENDER` frame, the entry point for a `DEFAULT` frame.
    pub from: Address,
    pub to: Address,
    pub value: U256,
}

/// What a format needs from the wallet: trusted names and token metadata.
pub trait Book {
    /// A name for `address`, or `None` to show it checksummed.
    fn name(&self, chain_id: u64, address: Address) -> Option<String>;
    fn token(&self, chain_id: u64, address: Address) -> Option<&Token>;
}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("no value at {0}")]
    Path(String),
    #[error("{0} is not a {1}")]
    Kind(String, &'static str),
    #[error("the interpolated intent names {0}, which no field formats")]
    Interpolation(String),
}

/// A format applied: its intent, and each field as a label and a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub intent: String,
    pub fields: Vec<(String, String)>,
}

struct Scope<'a> {
    values: &'a Values,
    container: Container,
    metadata: &'a Metadata,
    book: &'a dyn Book,
}

impl Scope<'_> {
    fn resolve(&self, path: &str) -> Result<Val, FormatError> {
        let missing = || FormatError::Path(path.to_owned());
        match path {
            "@.from" => return Ok(Val::Address(self.container.from)),
            "@.to" => return Ok(Val::Address(self.container.to)),
            "@.value" => return Ok(Val::Uint(self.container.value)),
            "@.chainId" => return Ok(Val::Uint(U256::from(self.container.chain_id))),
            _ => {}
        }
        if let Some(name) = path.strip_prefix("$.metadata.constants.") {
            return self
                .metadata
                .constants
                .get(name)
                .and_then(json_val)
                .ok_or_else(missing);
        }
        let name = path.strip_prefix("#.").unwrap_or(path);
        self.values
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .ok_or_else(missing)
    }

    fn address(v: &Val, path: &str) -> Result<Address, FormatError> {
        match v {
            Val::Address(a) => Ok(*a),
            _ => Err(FormatError::Kind(path.to_owned(), "address")),
        }
    }

    fn uint(v: &Val, path: &str) -> Result<U256, FormatError> {
        match v {
            Val::Uint(u) => Ok(*u),
            _ => Err(FormatError::Kind(path.to_owned(), "integer")),
        }
    }

    /// A parameter that is a constant or a path: `token` or `tokenPath`.
    fn param(&self, field: &Field, name: &str) -> Result<Option<Val>, FormatError> {
        if let Some(Value::String(path)) = field.params.get(&format!("{name}Path")) {
            return self.resolve(path).map(Some);
        }
        match field.params.get(name) {
            Some(Value::String(s)) if s.starts_with("$.") => self.resolve(s).map(Some),
            Some(v) => Ok(json_val(v)),
            None => Ok(None),
        }
    }

    fn show(&self, field: &Field) -> Result<String, FormatError> {
        let (v, path) = match (&field.path, &field.value) {
            (Some(path), _) => (self.resolve(path)?, path.as_str()),
            (None, Some(value)) => (
                json_val(value).unwrap_or(Val::Str(value.to_string())),
                "value",
            ),
            (None, None) => return Err(FormatError::Path("(none)".to_owned())),
        };
        match field.format.as_deref().unwrap_or("raw") {
            "addressName" => {
                let a = Self::address(&v, path)?;
                Ok(self
                    .book
                    .name(self.container.chain_id, a)
                    .unwrap_or_else(|| a.to_checksum(None)))
            }
            "amount" => Ok(ether(Self::uint(&v, path)?)),
            "tokenAmount" => self.token_amount(field, &v, path),
            "date" => Ok(date(Self::uint(&v, path)?)),
            "enum" => {
                let n = Self::uint(&v, path)?;
                let named = field
                    .params
                    .get("$ref")
                    .and_then(Value::as_str)
                    .and_then(|r| r.strip_prefix("$.metadata.enums."))
                    .and_then(|e| self.metadata.enums.get(e))
                    .and_then(|e| e.get(&n.to_string()));
                Ok(named.cloned().unwrap_or_else(|| format!("{n:#x}")))
            }
            _ => Ok(v.raw()),
        }
    }

    fn token_amount(&self, field: &Field, v: &Val, path: &str) -> Result<String, FormatError> {
        let amount = Self::uint(v, path)?;
        let token = self
            .param(field, "token")?
            .map(|t| Self::address(&t, "token"))
            .transpose()?
            .and_then(|t| self.book.token(self.container.chain_id, t));
        let Some(token) = token else {
            return Ok(format!("{amount} (unknown token)"));
        };
        if let Some(threshold) = field.params.get("threshold").and_then(json_u256)
            && amount >= threshold
        {
            let message = field
                .params
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("Unlimited");
            return Ok(format!("{message} {}", token.ticker));
        }
        Ok(format!(
            "{} {}",
            decimal(amount, token.decimals),
            token.ticker
        ))
    }
}

/// Apply `format` to `values` in `container`.
pub fn apply(
    format: &Format,
    values: &Values,
    container: Container,
    metadata: &Metadata,
    book: &dyn Book,
) -> Result<Applied, FormatError> {
    let scope = Scope {
        values,
        container,
        metadata,
        book,
    };
    let mut fields = Vec::with_capacity(format.fields.len());
    for field in &format.fields {
        let label = field
            .label
            .clone()
            .unwrap_or_else(|| field.path.clone().unwrap_or_default());
        fields.push((
            field.path.clone().unwrap_or_default(),
            label,
            scope.show(field)?,
        ));
    }
    let intent = match &format.interpolated_intent {
        Some(template) => interpolate(template, &fields)?,
        None => plain_intent(&format.intent),
    };
    Ok(Applied {
        intent,
        fields: fields.into_iter().map(|(_, l, v)| (l, v)).collect(),
    })
}

fn plain_intent(intent: &Value) -> String {
    match intent {
        Value::String(s) => s.clone(),
        Value::Object(o) => o
            .iter()
            .map(|(k, v)| format!("{k}: {}", v.as_str().unwrap_or_default()))
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

fn interpolate(template: &str, fields: &[(String, String, String)]) -> Result<String, FormatError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..]
            .find('}')
            .map(|c| open + c)
            .ok_or_else(|| FormatError::Interpolation(rest.to_owned()))?;
        let path = &rest[open + 1..close];
        let shown = fields
            .iter()
            .find(|(p, _, _)| p == path)
            .ok_or_else(|| FormatError::Interpolation(path.to_owned()))?;
        out.push_str(&shown.2);
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// `amount` with `decimals`, trailing zeros dropped: `1.5`, `1`, `0.0001`.
#[must_use]
pub fn decimal(amount: U256, decimals: u8) -> String {
    let unit = U256::from(10).pow(U256::from(decimals));
    let whole = amount / unit;
    let frac = amount % unit;
    if frac.is_zero() {
        return whole.to_string();
    }
    let digits = format!("{frac:0>width$}", width = usize::from(decimals));
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

/// Wei as ether: `0.0001 ETH`.
#[must_use]
pub fn ether(wei: U256) -> String {
    format!("{} ETH", decimal(wei, 18))
}

/// A Unix timestamp as RFC 3339 in UTC.
#[must_use]
pub fn date(timestamp: U256) -> String {
    let Ok(secs) = u64::try_from(timestamp) else {
        return format!("timestamp {timestamp}");
    };
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's `civil_from_days`).
fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimals() {
        assert_eq!(
            decimal(U256::from(15) * U256::from(10).pow(U256::from(17)), 18),
            "1.5"
        );
        assert_eq!(ether(U256::from(100_000_000_000_000u64)), "0.0001 ETH");
        assert_eq!(decimal(U256::from(7), 0), "7");
    }

    #[test]
    fn dates() {
        assert_eq!(date(U256::from(0)), "1970-01-01T00:00:00Z");
        assert_eq!(date(U256::from(1_709_191_632u64)), "2024-02-29T07:27:12Z");
        assert_eq!(date(U256::from(1_900_000_000u64)), "2030-03-17T17:46:40Z");
    }
}
