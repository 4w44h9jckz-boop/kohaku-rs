//! The issuers: a committee that holds the ticket key in shares, made by Commonware's DKG, and
//! the count of what each buyer may still be issued.
//!
//! Every issuer is a dealer and a player of one Joint-Feldman round
//! (`dkg::feldman_desmedt`), so no one ever holds the whole key. Here the round's messages pass
//! in memory; in deployment they would travel over an authenticated channel, as Commonware's own
//! DKG example sends them over `p2p::authenticated`.
//!
//! **The count must be shared.** A blinded request carries nothing an issuer can match to
//! another request, so an issuer that counts only its own answers cannot tell a quorum it joined
//! from one it did not. With `n` issuers, a quorum of `q` and `k` tickets bought, a buyer who
//! sends each request to a different quorum collects `n * k` answers and so `n * k / q` tickets,
//! rounded down: with 4 issuers, a quorum of 3 and 3 bought, 4 tickets ([`Count::PerIssuer`]).
//! The issuers must instead agree on one list of the requests each buyer made, and answer only
//! the first `k` ([`Count::Shared`]): then any quorum's answers are to requests on that list, and
//! the buyer gets at most `k` tickets. Here the list is one
//! structure in memory; in deployment it is a log the issuers agree on.

use std::collections::BTreeMap;

use alloy::primitives::{Address, B256, keccak256};
use commonware_codec::Encode;
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg::feldman_desmedt::{Dealer, Info, Logs, Player, Reveal},
        primitives::{
            group::{G1, Share},
            sharing::{Mode, Sharing},
            variant::{MinSig, PartialSignature},
        },
    },
    ed25519,
};
use commonware_math::algebra::Random;
use commonware_parallel::Sequential;
use commonware_utils::{N3f1, TryCollect, ordered::Set};
use rand::CryptoRng;

use crate::blind;

/// The DKG's namespace.
pub const DKG_NAMESPACE: &[u8] = b"kohaku-ticket-issuers";

#[derive(Debug, thiserror::Error)]
pub enum IssuersError {
    #[error("dkg: {0}")]
    Dkg(String),
    #[error("{0} has no ticket left to be issued")]
    Exhausted(Address),
}

/// How the issuers count what a buyer has been issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Count {
    /// Each issuer counts its own answers: a buyer can collect more tickets than it bought.
    PerIssuer,
    /// The issuers share one list of each buyer's requests.
    Shared,
}

/// A request's identity: the hash of its blinded point.
#[must_use]
pub fn request_id(blinded: &G1) -> B256 {
    keccak256(blinded.encode())
}

/// What each buyer bought on chain, and the requests answered under it.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    pub bought: BTreeMap<Address, u64>,
    /// Under [`Count::Shared`], every issuer's view: each buyer's requests, in order.
    shared: BTreeMap<Address, Vec<B256>>,
    /// Under [`Count::PerIssuer`], each issuer's own: (issuer, buyer) to requests answered.
    own: BTreeMap<(usize, Address), Vec<B256>>,
}

impl Ledger {
    #[must_use]
    pub fn new(bought: BTreeMap<Address, u64>) -> Self {
        Self {
            bought,
            ..Self::default()
        }
    }

    /// Whether issuer `issuer` may answer `buyer`'s request `id`, recording it if so. A request
    /// already on the list may be answered again: any quorum's answers to it make one ticket.
    pub fn admit(
        &mut self,
        count: Count,
        issuer: usize,
        buyer: Address,
        id: B256,
    ) -> Result<(), IssuersError> {
        let limit = usize::try_from(self.bought.get(&buyer).copied().unwrap_or_default())
            .unwrap_or(usize::MAX);
        let list = match count {
            Count::Shared => self.shared.entry(buyer).or_default(),
            Count::PerIssuer => self.own.entry((issuer, buyer)).or_default(),
        };
        if list.contains(&id) {
            return Ok(());
        }
        if list.len() >= limit {
            return Err(IssuersError::Exhausted(buyer));
        }
        list.push(id);
        Ok(())
    }
}

/// One issuer: its identity and its share of the ticket key.
pub struct Issuer {
    pub identity: ed25519::PublicKey,
    share: Share,
    /// Every blinded point this issuer answered, in order: all it ever learns of a ticket.
    pub transcript: Vec<G1>,
}

impl std::fmt::Debug for Issuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issuer")
            .field("identity", &self.identity)
            .field("index", &self.share.index)
            .finish_non_exhaustive()
    }
}

impl Issuer {
    /// This issuer's index in the sharing: which partial public key its answers verify under.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.share.index.get()
    }

    /// Answer a blinded point with this issuer's share, and remember the point.
    pub fn answer(&mut self, blinded: &G1) -> PartialSignature<MinSig> {
        self.transcript.push(*blinded);
        blind::answer(&self.share, blinded)
    }
}

/// The committee: its public sharing and each issuer.
#[derive(Debug)]
pub struct Committee {
    pub sharing: Sharing<MinSig>,
    pub issuers: Vec<Issuer>,
}

impl Committee {
    /// Run one DKG round among `n` issuers, each a dealer and a player.
    ///
    /// # Panics
    ///
    /// If `n` is zero.
    pub fn dkg(rng: &mut impl CryptoRng, n: usize) -> Result<Self, IssuersError> {
        let err = |e: &dyn std::fmt::Debug| IssuersError::Dkg(format!("{e:?}"));
        let keys: Vec<ed25519::PrivateKey> = (0..n)
            .map(|_| ed25519::PrivateKey::random(&mut *rng))
            .collect();
        let set: Set<ed25519::PublicKey> = keys
            .iter()
            .map(Signer::public_key)
            .try_collect()
            .map_err(|e| err(&e))?;
        let info = Info::<MinSig, ed25519::PublicKey>::new::<N3f1>(
            DKG_NAMESPACE,
            0,
            None,
            Mode::NonZeroCounter,
            Reveal::V1,
            set.clone(),
            set,
        )
        .map_err(|e| err(&e))?;
        let mut players = keys
            .iter()
            .map(|k| {
                Player::<MinSig, ed25519::PrivateKey>::new(info.clone(), k.clone())
                    .map(|p| (k.public_key(), p))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| err(&e))?;
        let mut logs = Logs::<MinSig, ed25519::PublicKey, N3f1>::new(info.clone());
        for key in &keys {
            let (mut dealer, public, private) =
                Dealer::start::<N3f1>(&mut *rng, info.clone(), key.clone(), None)
                    .map_err(|e| err(&e))?;
            for (to, message) in private {
                let (_, player) = players
                    .iter_mut()
                    .find(|(pk, _)| *pk == to)
                    .expect("every player is in the set");
                if let Some(ack) = player
                    .dealer_message::<N3f1>(key.public_key(), public.clone(), message)
                    .map_err(|e| err(&e))?
                {
                    dealer.receive_player_ack(to, ack).map_err(|e| err(&e))?;
                }
            }
            let (dealer, log) = dealer
                .finalize::<N3f1>()
                .check(&info)
                .ok_or_else(|| IssuersError::Dkg("a dealer's log does not check".into()))?;
            logs.record(dealer, log);
        }
        let mut sharing = None;
        let mut issuers = vec![];
        for (identity, player) in players {
            let (output, share) = player
                .finalize::<N3f1, ed25519::Batch>(&mut *rng, logs.clone(), &Sequential)
                .map_err(|e| err(&e))?;
            sharing.get_or_insert_with(|| output.public().clone());
            issuers.push(Issuer {
                identity,
                share,
                transcript: vec![],
            });
        }
        Ok(Self {
            sharing: sharing.expect("at least one issuer"),
            issuers,
        })
    }

    /// How many answers make a signature.
    #[must_use]
    pub fn quorum(&self) -> usize {
        self.sharing.required() as usize
    }
}
