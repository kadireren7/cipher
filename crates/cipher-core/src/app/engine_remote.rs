//! Cross-relay contacts (docs/MULTI_RELAY_PROTOCOL.md): contact cards, remote directory/KeyPackage access through an intro capability, and the
//! identity checks that make a hostile relay unable to substitute keys.
use super::engine::{get_json, put_json, Engine, NS_CONTACT, NS_META};
use super::model::*;
use crate::contact_card::{ContactCard, MAX_CARD_LIFETIME_MS};
use crate::error::{Result, SecurityError};
use crate::events::SecurityEvent;
use crate::relay_client::RelayEndpoint;
use crate::verification::{self, IdentityPins};
use cipher_wire::{Id16, RelayDescriptor};

const DAY_MS: u64 = 24 * 3600 * 1000;

impl Engine {
    /// Tell the engine how other relays' users must name this relay (needed for onion relays, whose descriptor carries the certificate pin).
    /// Persisted in the vault, so call it once after unlocking; it is restored on every later start.
    pub fn set_own_relay(&mut self, relay: RelayDescriptor) -> Result<()> {
        self.guard()?;
        let relay = relay.validated().map_err(|_| SecurityError::Malformed("relay descriptor"))?;
        self.vault.with_store(|s| put_json(s, NS_META, "own_relay", &relay))?;
        self.own_relay = Some(relay);
        Ok(())
    }

    pub fn own_relay(&self) -> Option<&RelayDescriptor> {
        self.own_relay.as_ref()
    }

    /// Issue a signed contact card (the thing to show as a QR code or send as a link). Mints a fresh INTRO capability at our relay; the card expires
    /// with it. Only the account's root device issues cards (its identity key is the key a card pins).
    pub fn create_contact_card(&mut self, lifetime_days: u32) -> Result<String> {
        self.guard()?;
        let relay = self
            .own_relay
            .clone()
            .ok_or(SecurityError::Denied("this relay cannot be named in a card (onion relays need set_own_relay with a pin)"))?;
        let lifetime = (u64::from(lifetime_days)).saturating_mul(DAY_MS);
        if lifetime == 0 || lifetime > MAX_CARD_LIFETIME_MS {
            return Err(SecurityError::Malformed("card lifetime"));
        }
        let now = self.now_ms();
        let intro = Id16(crate::rng::array::<16>()?);
        {
            let s = self.session()?;
            if s.mls.identity_public().as_slice() != s.ident.root_identity_key.as_slice() {
                return Err(SecurityError::Denied("only the root device can issue contact cards"));
            }
        }
        self.api()?.mint_intro_cap(intro)?;
        ContactCard::issue(&self.session()?.mls, relay, intro, now, lifetime)
    }

    /// Add a contact from their card, possibly on another relay. The card's signature authenticates the relay/capability; the card pins the root
    /// identity key; the directory answer of THEIR relay must match that key or nothing is stored. `verified` = the card was scanned in person
    /// (like a QR code), otherwise the contact starts Unverified.
    pub fn add_contact_by_card(&mut self, card: &str, name: &str, verified: bool) -> Result<Contact> {
        self.guard()?;
        let card = ContactCard::parse(card, self.now_ms())?;
        let own = self.session()?.ident.account_id;
        if card.account == own {
            return Err(SecurityError::Denied("cannot add yourself"));
        }
        let same_relay = self.own_relay.as_ref().is_some_and(|o| o.url() == card.relay.url());
        let home = (!same_relay).then(|| RemoteHome { relay: card.relay.clone(), intro: card.intro });
        let existing = self.contact(&card.account)?;
        if let Some(c) = &existing {
            if c.root_identity_key != card.root_key {
                self.push_event(SecurityEvent::IdentityChanged { account_id: card.account.to_hex() });
                return Err(SecurityError::IdentityUntrusted("card identity differs from the pinned identity"));
            }
        }
        // Ask the issuer's relay for the device records and require the card's root key among them BEFORE anything is pinned.
        let ep = RelayEndpoint::from_descriptor(&card.relay)?;
        let dir = self.api_at(&ep)?.intro_directory(&card.intro)?;
        if dir.account_id != card.account
            || !dir
                .devices
                .iter()
                .any(|d| d.endorsement.is_none() && d.identity_key == card.root_key && verification::verify_binding(&card.account, d))
        {
            self.push_event(SecurityEvent::IdentityChanged { account_id: card.account.to_hex() });
            return Err(SecurityError::IdentityUntrusted("relay's records do not match the card's identity"));
        }
        let trust = self.vault.with_store(|s| IdentityPins::new(s).evaluate_directory(&card.account, &dir.devices))?;
        for e in trust.events.clone() {
            self.push_event(e);
        }
        if trust.trusted.iter().all(|r| r.identity_key != card.root_key) {
            return Err(SecurityError::IdentityUntrusted("no trusted root device"));
        }
        let mut c = existing.unwrap_or(Contact {
            account_id: card.account,
            name: super::engine::clean_name(name, &card.account),
            trust: TrustState::Unverified,
            root_identity_key: card.root_key.to_vec(),
            verified_key: None,
            blocked: false,
            home: None,
        });
        c.home = home;
        if verified && c.trust != TrustState::IdentityChanged {
            c.trust = TrustState::Verified;
            c.verified_key = Some(card.root_key.to_vec());
        }
        self.vault.with_store(|s| put_json(s, NS_CONTACT, &c.account_id.to_hex(), &c))?;
        Ok(c)
    }

    /// Where a contact lives (None = our own relay).
    pub(crate) fn home_of(&mut self, account: &Id16) -> Option<RemoteHome> {
        self.vault.with_store(|s| get_json::<Contact>(s, NS_CONTACT, &account.to_hex())).ok().flatten().and_then(|c| c.home)
    }
}
