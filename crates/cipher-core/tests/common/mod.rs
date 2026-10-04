#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
use cipher_core::mls::MlsClient;
use cipher_core::protocol::{CommitValidator, ExpectedPeer, GroupProtocol, GroupRef};
use cipher_wire::Id16;

pub fn rid() -> Id16 {
    Id16(cipher_core::rng::array::<16>().unwrap())
}

pub fn new_client() -> MlsClient {
    MlsClient::generate(rid(), rid()).unwrap()
}

pub fn expected(c: &MlsClient) -> ExpectedPeer {
    ExpectedPeer { account_id: c.account_id(), device_id: c.device_id(), identity_key: c.identity_public() }
}

pub struct AllowAll;
impl CommitValidator for AllowAll {
    fn approve_add(&self, _: &Id16, _: &Id16, _: &[u8]) -> bool {
        true
    }
}

pub struct DenyAll;
impl CommitValidator for DenyAll {
    fn approve_add(&self, _: &Id16, _: &Id16, _: &[u8]) -> bool {
        false
    }
}

/// Alice creates a group and adds `others` one by one; every existing member
/// processes each commit; joiners use the welcome. Returns the group ref.
pub fn build_group(alice: &mut MlsClient, others: &mut [&mut MlsClient]) -> GroupRef {
    let g = alice.create_group().unwrap();
    let mut joined: Vec<usize> = Vec::new();
    for i in 0..others.len() {
        let kp = others[i].generate_key_packages(1).unwrap().remove(0);
        let out = alice.add_member(&g, &kp, &expected(others[i])).unwrap();
        alice.merge_pending_commit(&g).unwrap();
        for &j in &joined {
            others[j].process(&g, &out.commit, &AllowAll).unwrap();
        }
        let gj = others[i].join_from_welcome(out.welcome.as_ref().unwrap()).unwrap();
        assert_eq!(gj, g);
        joined.push(i);
    }
    g
}
