//! Decoded values, and the two calldata layouts a descriptor can name: an ABI function fragment,
//! which is how ERC-7730 keys a contract's formats, and a packed fragment, a tag followed by
//! fixed-width fields, which is how the experiments' accounts encode the calls they make to
//! themselves. ERC-7730 has no key for the second.

use alloy::{
    dyn_abi::{DynSolValue, JsonAbiExt},
    json_abi::Function,
    primitives::{Address, U256, hex},
};

/// A decoded value, as a field format receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Val {
    Address(Address),
    Uint(U256),
    Bytes(Vec<u8>),
    Bool(bool),
    Str(String),
}

impl Val {
    /// The value as `raw` formats it: decimal for integers, checksummed addresses, hex bytes.
    #[must_use]
    pub fn raw(&self) -> String {
        match self {
            Self::Address(a) => a.to_checksum(None),
            Self::Uint(u) => u.to_string(),
            Self::Bytes(b) => format!("0x{}", hex::encode(b)),
            Self::Bool(b) => b.to_string(),
            Self::Str(s) => s.clone(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LayoutError {
    #[error("not a fragment: {0}")]
    Fragment(String),
    #[error("type {0} is not supported")]
    Type(String),
    #[error("the data does not decode as {0}")]
    Decode(String),
}

/// Named values in fragment order.
pub type Values = Vec<(String, Val)>;

/// The first 4 bytes of calldata.
#[must_use]
pub fn selector_of(data: &[u8]) -> Option<[u8; 4]> {
    data.get(..4).and_then(|s| s.try_into().ok())
}

/// An ERC-7730 contract key: a human-readable ABI fragment with parameter names, such as
/// `transfer(address to,uint256 value)`.
#[derive(Debug, Clone)]
pub struct AbiLayout {
    function: Function,
}

impl AbiLayout {
    pub fn parse(key: &str) -> Result<Self, LayoutError> {
        let function = Function::parse(key).map_err(|_| LayoutError::Fragment(key.to_owned()))?;
        Ok(Self { function })
    }

    /// `keccak256` of the type-only signature, first 4 bytes: what ERC-7730 matches calldata by.
    #[must_use]
    pub fn selector(&self) -> [u8; 4] {
        self.function.selector().0
    }

    /// Decode `data`, selector included, into the fragment's named parameters.
    pub fn decode(&self, data: &[u8]) -> Result<Values, LayoutError> {
        let signature = self.function.signature();
        let body = data
            .get(4..)
            .ok_or_else(|| LayoutError::Decode(signature.clone()))?;
        let decoded = self
            .function
            .abi_decode_input(body)
            .map_err(|_| LayoutError::Decode(signature.clone()))?;
        // ERC-7730 decodes against the fragment's types; calldata longer than they take is not
        // that function.
        let canonical = self
            .function
            .abi_encode_input_raw(&decoded)
            .map_err(|_| LayoutError::Decode(signature.clone()))?;
        if canonical.len() != body.len() {
            return Err(LayoutError::Decode(signature));
        }
        self.function
            .inputs
            .iter()
            .zip(decoded)
            .map(|(param, value)| Ok((param.name.clone(), from_dyn(value)?)))
            .collect()
    }
}

fn from_dyn(value: DynSolValue) -> Result<Val, LayoutError> {
    Ok(match value {
        DynSolValue::Address(a) => Val::Address(a),
        DynSolValue::Uint(u, _) => Val::Uint(u),
        DynSolValue::Bool(b) => Val::Bool(b),
        DynSolValue::FixedBytes(word, n) => Val::Bytes(word[..n].to_vec()),
        DynSolValue::Bytes(b) => Val::Bytes(b),
        DynSolValue::String(s) => Val::Str(s),
        other => {
            let name = other
                .sol_type_name()
                .map_or_else(|| "?".to_owned(), std::borrow::Cow::into_owned);
            return Err(LayoutError::Type(name));
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Packed {
    Address,
    /// An unsigned integer of this many bytes.
    Uint(usize),
    /// `bytesN`.
    Fixed(usize),
}

impl Packed {
    fn width(self) -> usize {
        match self {
            Self::Address => 20,
            Self::Uint(n) | Self::Fixed(n) => n,
        }
    }

    fn parse(ty: &str) -> Result<Self, LayoutError> {
        let unsupported = || LayoutError::Type(ty.to_owned());
        if ty == "address" {
            return Ok(Self::Address);
        }
        let (prefix, bits_or_bytes, scale) = if let Some(n) = ty.strip_prefix("uint") {
            ("uint", n, 8)
        } else if let Some(n) = ty.strip_prefix("bytes") {
            ("bytes", n, 1)
        } else {
            return Err(unsupported());
        };
        let n: usize = bits_or_bytes.parse().map_err(|_| unsupported())?;
        if n == 0 || !n.is_multiple_of(scale) || n / scale > 32 {
            return Err(unsupported());
        }
        Ok(if prefix == "uint" {
            Self::Uint(n / 8)
        } else {
            Self::Fixed(n)
        })
    }
}

/// A packed key: `0x01 (address key,uint64 until)` is the tag byte `0x01`, then a 20-byte address
/// and an 8-byte integer, with nothing between them and nothing after.
#[derive(Debug, Clone)]
pub struct PackedLayout {
    tag: Vec<u8>,
    fields: Vec<(String, Packed)>,
}

impl PackedLayout {
    pub fn parse(key: &str) -> Result<Self, LayoutError> {
        let bad = || LayoutError::Fragment(key.to_owned());
        let (tag, rest) = key.split_once(' ').ok_or_else(bad)?;
        let tag = hex::decode(tag).map_err(|_| bad())?;
        let inner = rest
            .trim()
            .strip_prefix('(')
            .and_then(|r| r.strip_suffix(')'))
            .ok_or_else(bad)?;
        let fields = if inner.is_empty() {
            Vec::new()
        } else {
            inner
                .split(',')
                .map(|p| {
                    let (ty, name) = p.trim().split_once(' ').ok_or_else(bad)?;
                    Ok((name.to_owned(), Packed::parse(ty)?))
                })
                .collect::<Result<_, LayoutError>>()?
        };
        Ok(Self { tag, fields })
    }

    #[must_use]
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// Decode `data` if it starts with the tag and is exactly as long as the fields.
    pub fn decode(&self, data: &[u8]) -> Result<Values, LayoutError> {
        let wrong = || LayoutError::Decode(format!("0x{} packed", hex::encode(&self.tag)));
        let mut rest = data.strip_prefix(self.tag.as_slice()).ok_or_else(wrong)?;
        let mut out = Vec::with_capacity(self.fields.len());
        for (name, ty) in &self.fields {
            if rest.len() < ty.width() {
                return Err(wrong());
            }
            let (bytes, tail) = rest.split_at(ty.width());
            rest = tail;
            out.push((
                name.clone(),
                match ty {
                    Packed::Address => Val::Address(Address::from_slice(bytes)),
                    Packed::Uint(_) => Val::Uint(U256::from_be_slice(bytes)),
                    Packed::Fixed(_) => Val::Bytes(bytes.to_vec()),
                },
            ));
        }
        if rest.is_empty() {
            Ok(out)
        } else {
            Err(wrong())
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;

    use super::*;

    #[test]
    fn abi_selector_and_decode() {
        let l = AbiLayout::parse("transfer(address to,uint256 value)").unwrap();
        assert_eq!(l.selector(), [0xa9, 0x05, 0x9c, 0xbb]);
        let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(address!("0x2700000000000000000000000000000000000013").as_slice());
        data.extend_from_slice(&U256::from(7).to_be_bytes::<32>());
        let v = l.decode(&data).unwrap();
        assert_eq!(v[0].0, "to");
        assert_eq!(v[1], ("value".to_owned(), Val::Uint(U256::from(7))));
        data.push(0);
        assert!(
            l.decode(&data).is_err(),
            "a trailing byte is not this function"
        );
    }

    #[test]
    fn packed_decode() {
        let l = PackedLayout::parse("0x02 (address key,uint64 until)").unwrap();
        let mut data = vec![0x02];
        data.extend_from_slice(&[0x11; 20]);
        data.extend_from_slice(&5u64.to_be_bytes());
        let v = l.decode(&data).unwrap();
        assert_eq!(v[1].1, Val::Uint(U256::from(5)));
        assert!(l.decode(&data[..data.len() - 1]).is_err());
        assert!(l.decode(&[0x03]).is_err());
    }
}
