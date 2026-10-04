//! The single entry point for cryptographically secure randomness in this crate
//! (SEC-012). Uses the OS CSPRNG via `getrandom`; failure is an error, never a
//! fallback to a weaker source. OpenMLS draws from its own provider RNG
//! (`RustCrypto`, which is also OS-backed).
use crate::error::{Result, SecurityError};
use zeroize::Zeroizing;

pub fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| SecurityError::Rng)
}

pub fn array<const N: usize>() -> Result<[u8; N]> {
    let mut a = [0u8; N];
    fill(&mut a)?;
    Ok(a)
}

pub fn secret32() -> Result<Zeroizing<[u8; 32]>> {
    let mut a = Zeroizing::new([0u8; 32]);
    fill(a.as_mut_slice())?;
    Ok(a)
}
