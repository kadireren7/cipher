#![no_main]
use cipher_core::mls::MlsClient;
use cipher_core::protocol::{ExpectedPeer, GroupProtocol};
use cipher_wire::Id16;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut c = match MlsClient::generate(Id16([1; 16]), Id16([2; 16])) {
        Ok(c) => c,
        Err(_) => return,
    };
    // Welcome parsing path.
    let _ = c.join_from_welcome(data);
    // KeyPackage validation path (attacker-supplied by a malicious relay).
    if let Ok(g) = c.create_group() {
        let peer = ExpectedPeer { account_id: Id16([3; 16]), device_id: Id16([4; 16]), identity_key: [5; 32] };
        let _ = c.add_member(&g, data, &peer);
        // Ciphertext processing path on a group with only ourselves.
        struct Deny;
        impl cipher_core::protocol::CommitValidator for Deny {
            fn approve_add(&self, _: &Id16, _: &Id16, _: &[u8]) -> bool {
                false
            }
        }
        let _ = c.process(&g, data, &Deny);
    }
});
