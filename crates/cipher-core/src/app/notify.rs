//! Notification privacy policy (ported from the retired TypeScript layer; now enforced in Rust so the UI cannot get it wrong).
//!
//! Push providers only ever see the constant wake payload. Visible text is built here from the privacy mode **and the vault
//! state**: a locked vault cannot decrypt anything, so it can only ever produce the generic notification, whatever mode is set.
//!
//! Platform limits: the OS and push provider learn *that* and *when* a wake happened; Android may retain notification history;
//! while locked the app cannot even authenticate to the relay (the transport key lives in the vault), so a wake while locked
//! can only show "New message" — it cannot know how many or from whom.
use serde::{Deserialize, Serialize};

/// The entire payload that may be sent through a push provider.
pub const WAKE_PAYLOAD: &str = "{\"v\":1}";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PrivacyMode {
    /// Never show sender or content. DEFAULT.
    #[default]
    NoContent,
    /// Show the sender's local name (only while the vault is unlocked).
    SenderOnly,
    /// Show sender and message text (only while the vault is unlocked).
    ContentWhenUnlocked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub conversation_title: String,
    pub sender_name: String,
    pub preview: String,
    pub is_group: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationText {
    pub title: String,
    pub body: String,
    /// Always `true`: hide on the lock screen regardless of mode.
    pub secret_on_lock_screen: bool,
}

/// Strict wake parser: only the exact constant payload is accepted (fail closed).
pub fn is_valid_wake(payload: &str) -> bool {
    payload == WAKE_PAYLOAD
}

pub fn build(mode: PrivacyMode, vault_unlocked: bool, notices: &[Notice]) -> NotificationText {
    let generic = NotificationText { title: "Cipher".into(), body: "New message".into(), secret_on_lock_screen: true };
    if !vault_unlocked || notices.is_empty() || mode == PrivacyMode::NoContent {
        return generic;
    }
    let clip = |s: &str, n: usize| -> String { s.chars().filter(|c| !super::model::is_disguising_char(*c)).take(n).collect() };
    match (mode, notices) {
        (PrivacyMode::SenderOnly, [n]) => {
            NotificationText { title: clip(&n.sender_name, 40), body: "New message".into(), secret_on_lock_screen: true }
        }
        (PrivacyMode::SenderOnly, many) => {
            NotificationText { title: "Cipher".into(), body: format!("{} new messages", many.len()), secret_on_lock_screen: true }
        }
        (PrivacyMode::ContentWhenUnlocked, [n]) => NotificationText {
            title: if n.is_group { clip(&format!("{} · {}", n.sender_name, n.conversation_title), 60) } else { clip(&n.sender_name, 40) },
            body: clip(&n.preview, 120),
            secret_on_lock_screen: true,
        },
        (PrivacyMode::ContentWhenUnlocked, many) => {
            NotificationText { title: "Cipher".into(), body: format!("{} new messages", many.len()), secret_on_lock_screen: true }
        }
        _ => generic,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(text: &str) -> Notice {
        Notice { conversation_title: "Team".into(), sender_name: "Alice".into(), preview: text.into(), is_group: true }
    }

    #[test]
    fn default_is_no_content_and_locked_vault_is_always_generic() {
        assert_eq!(PrivacyMode::default(), PrivacyMode::NoContent);
        for mode in [PrivacyMode::NoContent, PrivacyMode::SenderOnly, PrivacyMode::ContentWhenUnlocked] {
            let t = build(mode, false, &[n("SECRET-FIXTURE")]);
            assert_eq!((t.title.as_str(), t.body.as_str()), ("Cipher", "New message"), "{mode:?}");
            assert!(t.secret_on_lock_screen);
        }
    }

    #[test]
    fn modes_expose_only_what_they_promise_when_unlocked() {
        let t = build(PrivacyMode::NoContent, true, &[n("SECRET-FIXTURE")]);
        assert!(!format!("{t:?}").contains("SECRET-FIXTURE") && !format!("{t:?}").contains("Alice") && !format!("{t:?}").contains("Team"));
        let t = build(PrivacyMode::SenderOnly, true, &[n("SECRET-FIXTURE")]);
        assert_eq!(t.title, "Alice");
        assert!(!format!("{t:?}").contains("SECRET-FIXTURE") && !format!("{t:?}").contains("Team"), "no group name, no text");
        let t = build(PrivacyMode::ContentWhenUnlocked, true, &[n("hello")]);
        assert_eq!((t.title.as_str(), t.body.as_str()), ("Alice · Team", "hello"));
        let t = build(PrivacyMode::ContentWhenUnlocked, true, &[n("a"), n("b")]);
        assert_eq!(t.body, "2 new messages", "several messages never reveal content");
        assert!(t.secret_on_lock_screen);
    }

    #[test]
    fn control_characters_and_length_are_neutralised() {
        let t = build(PrivacyMode::ContentWhenUnlocked, true, &[n(&format!("x\u{0007}\n{}", "y".repeat(500)))]);
        assert!(t.body.chars().count() <= 120 && !t.body.chars().any(char::is_control));
    }

    #[test]
    fn only_the_exact_constant_wake_payload_is_accepted() {
        assert!(is_valid_wake(WAKE_PAYLOAD));
        for bad in ["", "{}", "{\"v\":1,\"body\":\"x\"}", "{\"v\":2}", " {\"v\":1}", "{\"v\": 1}"] {
            assert!(!is_valid_wake(bad), "{bad}");
        }
    }
}
