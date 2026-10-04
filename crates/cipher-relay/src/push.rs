//! Push wake-ups carry NO message content, sender, group, count or ciphertext.
//! The provider (APNs/FCM) learns only "device token X was woken at time T".
//! On wake, the app fetches ciphertext over the authenticated channel, decrypts
//! locally and decides what (if anything) to display.
use std::sync::Mutex;

/// The entire payload ever sent to a push provider. Constant by construction.
pub const WAKE_PAYLOAD: &str = "{\"v\":1}";

pub trait PushNotifier: Send + Sync {
    fn wake(&self, token: &str);
}

#[derive(Debug, Default)]
pub struct NullPush;
impl PushNotifier for NullPush {
    fn wake(&self, _token: &str) {}
}

/// Test double that records exactly what would be handed to a push provider.
#[derive(Debug, Default)]
pub struct RecordingPush {
    pub sent: Mutex<Vec<(String, String)>>,
}
impl PushNotifier for RecordingPush {
    fn wake(&self, token: &str) {
        if let Ok(mut g) = self.sent.lock() {
            g.push((token.to_owned(), WAKE_PAYLOAD.to_owned()));
        }
    }
}
