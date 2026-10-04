//! PIN -> key derivation using Argon2id (RFC 9106), via the RustCrypto `argon2` crate.
//!
//! Parameters are stored with the envelope but are *validated against a floor on
//! every load*: an attacker who edits stored parameters to something cheap cannot
//! downgrade the KDF (fail closed, `KdfParamsBelowFloor`).
//!
//! Defaults (m=64 MiB, t=3, p=1) follow RFC 9106 guidance for memory-constrained
//! settings and exceed the OWASP minimum (m=19 MiB, t=2, p=1). They have been
//! benchmarked only on the dev host (see `docs/LOCAL_STORAGE_SECURITY.md`);
//! SECURITY TODO (ST-003): benchmark on low-end Android hardware and tune to ~250-500 ms.
use crate::error::{Result, SecurityError};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const FLOOR_M_KIB: u32 = 19 * 1024;
pub const FLOOR_T: u32 = 2;
pub const MAX_M_KIB: u32 = 1024 * 1024; // 1 GiB; avoid attacker-chosen DoS on load
pub const MAX_T: u32 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

/// Whether the production KDF cost floor is enforced. Always `Enforced` unless a
/// test-only variant (compiled only with `insecure-test-support`) is chosen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KdfFloor {
    #[default]
    Enforced,
    #[cfg(any(test, feature = "insecure-test-support"))]
    DisabledForTests,
}

impl KdfFloor {
    fn enforced(self) -> bool {
        match self {
            KdfFloor::Enforced => true,
            #[cfg(any(test, feature = "insecure-test-support"))]
            KdfFloor::DisabledForTests => false,
        }
    }
}

impl KdfParams {
    pub const MOBILE_DEFAULT: KdfParams = KdfParams { m_kib: 64 * 1024, t: 3, p: 1 };

    /// Deliberately weak parameters for fast tests. Not available in production builds.
    #[cfg(any(test, feature = "insecure-test-support"))]
    pub const INSECURE_FAST_FOR_TESTS: KdfParams = KdfParams { m_kib: 8, t: 1, p: 1 };

    fn validate(&self, enforce_floor: bool) -> Result<()> {
        if enforce_floor && (self.m_kib < FLOOR_M_KIB || self.t < FLOOR_T) {
            return Err(SecurityError::KdfParamsBelowFloor);
        }
        if self.m_kib > MAX_M_KIB || self.t > MAX_T || self.p == 0 || self.p > 4 {
            return Err(SecurityError::Malformed("kdf params"));
        }
        Ok(())
    }

    /// Validate parameters read from storage (fail closed below the floor).
    pub fn validate_stored(&self, floor: KdfFloor) -> Result<()> {
        self.validate(floor.enforced())
    }
}

pub fn derive(pin: &[u8], salt: &[u8; 16], params: KdfParams, floor: KdfFloor) -> Result<Zeroizing<[u8; 32]>> {
    params.validate_stored(floor)?;
    let p = Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| SecurityError::Malformed("kdf params"))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    a2.hash_password_into(pin, salt, out.as_mut_slice()).map_err(|_| SecurityError::Malformed("kdf"))?;
    Ok(out)
}

/// Minimal PIN policy. A numeric PIN has limited entropy; the real offline bound
/// is that derivation also requires the hardware-bound keystore secret.
pub fn validate_pin(pin: &str) -> Result<()> {
    let n = pin.chars().count();
    let first = pin.chars().next();
    let all_same = pin.chars().all(|c| Some(c) == first);
    if !(6..=64).contains(&n) || all_same {
        return Err(SecurityError::WeakPin);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn production_floor_is_enforced_by_validate() {
        let weak = KdfParams { m_kib: 8, t: 1, p: 1 };
        assert!(matches!(weak.validate(true), Err(SecurityError::KdfParamsBelowFloor)));
        assert!(KdfParams::MOBILE_DEFAULT.validate(true).is_ok());
    }

    #[test]
    fn derive_refuses_weak_params_when_floor_enforced() {
        let weak = KdfParams::INSECURE_FAST_FOR_TESTS;
        assert!(matches!(derive(b"123456", &[1; 16], weak, KdfFloor::Enforced), Err(SecurityError::KdfParamsBelowFloor)));
    }

    #[test]
    fn rejects_absurd_params() {
        let huge = KdfParams { m_kib: u32::MAX, t: 3, p: 1 };
        assert!(huge.validate(false).is_err());
    }

    #[test]
    fn deterministic_and_salt_sensitive() {
        let p = KdfParams::INSECURE_FAST_FOR_TESTS;
        let a = derive(b"123456", &[1; 16], p, KdfFloor::DisabledForTests).unwrap();
        let b = derive(b"123456", &[1; 16], p, KdfFloor::DisabledForTests).unwrap();
        let c = derive(b"123456", &[2; 16], p, KdfFloor::DisabledForTests).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
    }

    #[test]
    fn pin_policy() {
        assert!(validate_pin("12345").is_err());
        assert!(validate_pin("111111").is_err());
        assert!(validate_pin("493817").is_ok());
    }
}
