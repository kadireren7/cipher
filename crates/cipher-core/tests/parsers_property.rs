#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Property tests over every parser that handles attacker-controlled bytes.
//! Contract: never panic, never partially succeed on garbage.
mod common;
use cipher_core::attachment::AttachmentDescriptor;
use cipher_core::mls::{identity_bytes, parse_identity, MlsClient};
use cipher_core::protocol::GroupProtocol;
use cipher_core::relay_client::RelayEndpoint;
use common::*;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn snapshot_restore_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = MlsClient::restore(&bytes);
    }

    #[test]
    fn process_never_panics_on_random_ciphertext(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let (mut a, mut b) = (new_client(), new_client());
        let g = build_group(&mut a, &mut [&mut b]);
        let epoch = b.epoch(&g).unwrap();
        prop_assert!(b.process(&g, &bytes, &AllowAll).is_err());
        prop_assert_eq!(b.epoch(&g).unwrap(), epoch);
    }

    #[test]
    fn key_package_validation_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let (mut a, b) = (new_client(), new_client());
        let g = a.create_group().unwrap();
        prop_assert!(a.add_member(&g, &bytes, &expected(&b)).is_err());
    }

    #[test]
    fn welcome_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let mut a = new_client();
        prop_assert!(a.join_from_welcome(&bytes).is_err());
    }

    #[test]
    fn descriptor_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..6000)) {
        let _ = AttachmentDescriptor::from_bytes(&bytes);
    }

    #[test]
    fn identity_codec_roundtrip(a in any::<[u8;16]>(), d in any::<[u8;16]>(), junk in proptest::collection::vec(any::<u8>(), 0..64)) {
        let (a, d) = (cipher_wire::Id16(a), cipher_wire::Id16(d));
        prop_assert_eq!(parse_identity(&identity_bytes(&a, &d)), Some((a, d)));
        if junk.len() != 32 { prop_assert!(parse_identity(&junk).is_none()); }
    }

    #[test]
    fn relay_endpoint_parser_never_panics(s in ".{0,200}") {
        let _ = RelayEndpoint::new(&s);
    }
}
