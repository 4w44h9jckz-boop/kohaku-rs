//! One seed, and every secret the wallet holds derived from it (`exp-frames` experiment 45).
//!
//! ```text
//! mnemonic   BIP-39, 24 English words (256 bits of entropy)
//! seed       BIP-39's 64-byte seed of the mnemonic, with an empty passphrase
//! owner i    BIP-32 at BIP-44's m/44'/60'/0'/0/i                              secp256k1
//! K(label)   HKDF-SHA256(IKM = seed, salt = "kohaku-seed-v1", info = label)   32 bytes
//! ```
//!
//! Account keys stay on BIP-44's path, so any Ethereum wallet given the mnemonic finds the same
//! owner. Every other secret is `K` of a label of its own, listed in [`PATHS`]. Distinct labels
//! are distinct HKDF inputs, so no two derived secrets are related without the seed; and BIP-32's
//! tree is keyed with HMAC-SHA512 under "Bitcoin seed", apart from HKDF's extract under
//! "kohaku-seed-v1".
//!
//! A label's indices are decimal and an address is `0x` and 40 lowercase hex digits. A secp256k1
//! key is `K(label)` itself, refused in the 2^-128 case that it is zero or not below the order. A
//! BN254 field element is `K(label)` as a big-endian integer mod p. A ticket's blinding factor is
//! RFC 9380's `hash_to_field` of `K(label)` into BLS12-381's scalar field, with `expand_message_xmd`
//! (SHA-256) and the tag `kohaku-seed-v1/ticket-blinding`.

use alloy::{
    primitives::{Address, B256, U256},
    signers::local::{
        MnemonicBuilder, PrivateKeySigner,
        coins_bip39::{English, Mnemonic},
    },
};
use commonware_cryptography::bls12381::primitives::group::Scalar;
use commonware_math::algebra::Additive;
use hkdf::Hkdf;
use kohaku_frame_registry::{
    announce,
    note::{Secrets, field},
};
use kohaku_tornadocash_keychain::signature::SignatureKeychain;
use rand::CryptoRng;
use sha2::Sha256;

/// HKDF's salt: the version of this derivation.
pub const SALT: &[u8] = b"kohaku-seed-v1";
/// RFC 9380's domain separation tag for a ticket's blinding factor.
pub const BLINDING_DST: &[u8] = b"kohaku-seed-v1/ticket-blinding";

#[derive(Debug, thiserror::Error)]
pub enum DeriveError {
    #[error("not a BIP-39 English mnemonic: {0}")]
    Mnemonic(String),
    #[error("the key at {0} is not a valid secp256k1 secret")]
    Key(String),
    #[error("the blinding factor at {0} is zero")]
    Blinding(String),
}

/// What a derivation path gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A secp256k1 key on BIP-44's path.
    Bip44Secp256k1,
    /// `K(label)` as a secp256k1 key.
    Secp256k1,
    /// `K(label)` as 32 bytes.
    Bytes32,
    /// `K(label)` mod BN254's scalar field.
    Bn254Field,
    /// `hash_to_field(K(label))` in BLS12-381's scalar field.
    Bls12381Scalar,
}

/// One published path: its label (or BIP-32 path), what it gives, and what for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Path {
    pub label: &'static str,
    pub kind: Kind,
    pub purpose: &'static str,
    /// What brings back what the secret opened, after a loss.
    pub rebuilt_from: &'static str,
}

/// Every path the wallet derives, with `<i>`, `<n>`, `<j>`, `<k>`, `<v>` for indices and
/// `<vault>` for an address.
pub const PATHS: &[Path] = &[
    Path {
        label: "m/44'/60'/0'/0/<i>",
        kind: Kind::Bip44Secp256k1,
        purpose: "owner i: the account's signer, and the EOA that deposits and buys tickets",
        rebuilt_from: "the account's address, from the CREATE2 salt below; its owner slot",
    },
    Path {
        label: "account/<i>/salt",
        kind: Kind::Bytes32,
        purpose: "the CREATE2 salt of account i, deployed with owner i and an empty recovery commitment",
        rebuilt_from: "the address alone: code there means the account exists",
    },
    Path {
        label: "account/<i>/recovery-salt/<r>",
        kind: Kind::Bytes32,
        purpose: "the salt of account i's r-th recovery commitment, keccak256(salt || 1 || recovery key's address)",
        rebuilt_from: "not needed to spend; hides the recovery key until a recovery reveals it",
    },
    Path {
        label: "pool/keychain",
        kind: Kind::Secp256k1,
        purpose: "kohaku-tornadocash-keychain's key: each privacy-pool note's secret and nullifier, by pool and nonce",
        rebuilt_from: "the pool's Deposit and Withdrawal events",
    },
    Path {
        label: "pool/recipient/<n>",
        kind: Kind::Secp256k1,
        purpose: "where the n-th withdrawal pays out",
        rebuilt_from: "the address's balance",
    },
    Path {
        label: "custody/<vault>/<j>/nullifier",
        kind: Kind::Bn254Field,
        purpose: "the nullifier secret of the j-th registry note in a vault (custody per application)",
        rebuilt_from: "the registry's Inserted and Updated events, and scopeOf(vault)",
    },
    Path {
        label: "custody/<vault>/<j>/secret",
        kind: Kind::Bn254Field,
        purpose: "the secret of the same note",
        rebuilt_from: "as above",
    },
    Path {
        label: "view",
        kind: Kind::Secp256k1,
        purpose: "the viewing key: announcements sealed to it carry the openings of notes others made for the wallet",
        rebuilt_from: "the board's Posted events",
    },
    Path {
        label: "ticket/<k>/sender",
        kind: Kind::Secp256k1,
        purpose: "the fresh sender the k-th ticket pays for",
        rebuilt_from: "its nonce: 0 means the ticket is unspent",
    },
    Path {
        label: "ticket/<k>/salt",
        kind: Kind::Bytes32,
        purpose: "the k-th ticket's salt, in the message the committee signs",
        rebuilt_from: "derived",
    },
    Path {
        label: "ticket/<k>/blinding",
        kind: Kind::Bls12381Scalar,
        purpose: "the k-th ticket's blinding factor r: the request is r * H(m)",
        rebuilt_from: "the committee's blinded answer, posted on the board beside r * H(m)",
    },
    Path {
        label: "ticket/<k>/binder",
        kind: Kind::Secp256k1,
        purpose: "the k-th ticket's one-time key: it signs the one transaction a bound ticket pays for (experiment 48)",
        rebuilt_from: "derived; its address is in the bound ticket's message",
    },
    Path {
        label: "backup/<v>/key",
        kind: Kind::Bytes32,
        purpose: "the key of the v-th encrypted backup",
        rebuilt_from: "the backup itself, found by its locator",
    },
    Path {
        label: "backup/<v>/locator",
        kind: Kind::Bytes32,
        purpose: "the tag the v-th backup is posted under",
        rebuilt_from: "derived",
    },
];

/// A wallet's seed. Its `Debug` prints nothing of it.
#[derive(Clone)]
pub struct Seed {
    phrase: String,
    bytes: [u8; 64],
}

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seed(..)")
    }
}

/// What the k-th ticket needs from the seed.
#[derive(Clone)]
pub struct TicketSecrets {
    pub sender: PrivateKeySigner,
    pub salt: B256,
    pub blinding: Scalar,
}

impl std::fmt::Debug for TicketSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TicketSecrets {{ sender: {}, .. }}",
            self.sender.address()
        )
    }
}

impl Seed {
    /// The seed of a BIP-39 English mnemonic, with an empty passphrase.
    pub fn from_mnemonic(phrase: &str) -> Result<Self, DeriveError> {
        let mnemonic = Mnemonic::<English>::new_from_phrase(phrase)
            .map_err(|e| DeriveError::Mnemonic(e.to_string()))?;
        let bytes = mnemonic
            .to_seed(None)
            .map_err(|e| DeriveError::Mnemonic(e.to_string()))?;
        Ok(Self {
            phrase: phrase.to_owned(),
            bytes,
        })
    }

    /// A new 24-word mnemonic and its seed.
    pub fn generate(rng: &mut impl CryptoRng) -> Result<(String, Self), DeriveError> {
        let mut entropy = [0u8; 32];
        rng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::<English>::new_from_entropy(entropy.into());
        let phrase = mnemonic.to_phrase();
        let seed = Self::from_mnemonic(&phrase)?;
        Ok((phrase, seed))
    }

    /// `K(label)`.
    ///
    /// # Panics
    ///
    /// Never: 32 bytes is within HKDF-SHA256's output length.
    #[must_use]
    pub fn key(&self, label: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(Some(SALT), &self.bytes)
            .expand(label.as_bytes(), &mut out)
            .expect("32 bytes is a valid HKDF-SHA256 length");
        out
    }

    /// `K(label)` as a secp256k1 key.
    pub fn secp256k1(&self, label: &str) -> Result<PrivateKeySigner, DeriveError> {
        PrivateKeySigner::from_bytes(&B256::from(self.key(label)))
            .map_err(|_| DeriveError::Key(label.to_owned()))
    }

    /// Owner `i`, at m/44'/60'/0'/0/i.
    pub fn owner(&self, i: u32) -> Result<PrivateKeySigner, DeriveError> {
        MnemonicBuilder::<English>::default()
            .phrase(self.phrase.as_str())
            .index(i)
            .and_then(|b| b.build())
            .map_err(|_| DeriveError::Key(format!("m/44'/60'/0'/0/{i}")))
    }

    #[must_use]
    pub fn account_salt(&self, i: u32) -> B256 {
        B256::from(self.key(&format!("account/{i}/salt")))
    }

    #[must_use]
    pub fn recovery_salt(&self, i: u32, r: u32) -> B256 {
        B256::from(self.key(&format!("account/{i}/recovery-salt/{r}")))
    }

    /// The privacy-pool keychain.
    pub fn keychain(&self) -> Result<SignatureKeychain<PrivateKeySigner>, DeriveError> {
        Ok(SignatureKeychain::new(self.secp256k1("pool/keychain")?))
    }

    pub fn recipient(&self, n: u32) -> Result<PrivateKeySigner, DeriveError> {
        self.secp256k1(&format!("pool/recipient/{n}"))
    }

    /// The j-th registry note in `vault`.
    #[must_use]
    pub fn custody(&self, vault: Address, j: u32) -> Secrets {
        let part = |p: &str| {
            field(U256::from_be_bytes(
                self.key(&format!("custody/{}/{j}/{p}", lower(vault))),
            ))
        };
        Secrets {
            nullifier_secret: part("nullifier"),
            secret: part("secret"),
        }
    }

    /// The viewing key, as experiment 33's announcements use it.
    pub fn view(&self) -> Result<announce::Keys, DeriveError> {
        announce::Keys::from_secret(B256::from(self.key("view")))
            .map_err(|_| DeriveError::Key("view".to_owned()))
    }

    pub fn ticket(&self, k: u32) -> Result<TicketSecrets, DeriveError> {
        let label = format!("ticket/{k}/blinding");
        let blinding = Scalar::map(BLINDING_DST, &self.key(&label));
        if blinding == Scalar::zero() {
            return Err(DeriveError::Blinding(label));
        }
        Ok(TicketSecrets {
            sender: self.secp256k1(&format!("ticket/{k}/sender"))?,
            salt: B256::from(self.key(&format!("ticket/{k}/salt"))),
            blinding,
        })
    }

    /// The k-th ticket's one-time key, for a bound ticket.
    pub fn binder(&self, k: u32) -> Result<PrivateKeySigner, DeriveError> {
        self.secp256k1(&format!("ticket/{k}/binder"))
    }

    #[must_use]
    pub fn backup_key(&self, v: u32) -> [u8; 32] {
        self.key(&format!("backup/{v}/key"))
    }

    #[must_use]
    pub fn backup_locator(&self, v: u32) -> B256 {
        B256::from(self.key(&format!("backup/{v}/locator")))
    }
}

/// An address as a label writes it: `0x` and 40 lowercase hex digits.
#[must_use]
pub fn lower(a: Address) -> String {
    format!("0x{}", hex::encode(a.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn bip39_seed_is_the_standard_one() {
        // BIP-39's English test vector for 32 zero bytes of entropy, passphrase "TREZOR", is
        // checked by coins-bip39; with no passphrase the first account is the well-known one.
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        assert_eq!(
            seed.owner(0).unwrap().address(),
            "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb"
                .parse::<Address>()
                .unwrap()
        );
    }

    #[test]
    fn labels_give_unrelated_secrets() {
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        let a = seed.key("ticket/1/sender");
        let b = seed.key("ticket/1/salt");
        let c = seed.key("ticket/10/sender");
        assert_ne!(a, b);
        assert_ne!(a, c);
        let other = Seed::from_mnemonic(&PHRASE.replace("art", "zoo")).ok();
        // "zoo" breaks the checksum: a mnemonic is checked before it is used.
        assert!(other.is_none());
    }

    #[test]
    fn debug_prints_no_secret() {
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        assert_eq!(format!("{seed:?}"), "Seed(..)");
        let t = seed.ticket(0).unwrap();
        assert!(!format!("{t:?}").contains(&hex::encode(t.salt)));
    }
}
