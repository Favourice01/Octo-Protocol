//! SEP-0005 hierarchical key derivation for Stellar (SLIP-0010 ed25519).
//!
//! Stellar's SEP-0005 derives account keys at the path `m/44'/148'/<index>'` (all hardened),
//! where `148` is Stellar's SLIP-0044 coin type. From one BIP39 mnemonic we can derive unlimited
//! account keypairs deterministically.
//!
//! In octo's muxed-account model we normally derive only **account 0** (the single master
//! account) and fan out to customers via muxed ids — but this module supports arbitrary indexes
//! so the "real account per customer" model remains available later.

use crate::error::WalletError;
use bip39::{Language, Mnemonic, Seed};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

/// Stellar's SLIP-0044 coin type.
const STELLAR_COIN_TYPE: u32 = 148;
/// BIP44 purpose.
const BIP44_PURPOSE: u32 = 44;
/// Hardened-derivation offset.
const HARDENED: u32 = 0x8000_0000;
/// Entropy for a 12-word BIP39 mnemonic (128 bits).
const MNEMONIC_ENTROPY_LEN: usize = 16;

/// A BIP39 seed (the 64-byte output of mnemonic + passphrase), zeroized on drop.
pub struct WalletSeed(Zeroizing<Vec<u8>>);

impl WalletSeed {
    /// Generate a fresh 12-word mnemonic and return both it and its seed.
    ///
    /// The mnemonic is the **backup secret** — it must be shown to the operator once (for
    /// out-of-band storage) and then only ever persisted in sealed form. It is returned in a
    /// [`Zeroizing`] string so the caller controls its lifetime.
    ///
    /// # Entropy source (load-bearing security property)
    ///
    /// The 128 bits of mnemonic entropy come from [`rand::rngs::OsRng`] — the operating system's
    /// CSPRNG (`getrandom(2)` on Linux) — and are passed to [`Mnemonic::from_entropy`]. We do
    /// **not** call `Mnemonic::new`: in tiny-bip39 2.0.0 that routes through
    /// `crypto::gen_random_bytes` → `rand::thread_rng()`, a userspace ChaCha12 generator that is
    /// only reachable when tiny-bip39's default `rand` feature is on and whose algorithm is a
    /// `rand` implementation detail. Pinning `OsRng` here keeps this guarantee independent of
    /// either crate's defaults across version bumps.
    ///
    /// ```
    /// use octo_wallet_core::WalletSeed;
    /// let (a, _) = WalletSeed::generate();
    /// let (b, _) = WalletSeed::generate();
    /// assert_eq!(a.split(' ').count(), 12);
    /// assert_ne!(*a, *b);
    /// ```
    pub fn generate() -> (Zeroizing<String>, WalletSeed) {
        let mnemonic = fresh_mnemonic();
        let phrase = Zeroizing::new(mnemonic.phrase().to_string());
        let seed = Seed::new(&mnemonic, "");
        let wallet_seed = WalletSeed(Zeroizing::new(seed.as_bytes().to_vec()));
        (phrase, wallet_seed)
    }

    /// Reconstruct a seed from an existing BIP39 mnemonic phrase (recovery / re-import).
    pub fn from_phrase(phrase: &str) -> Result<WalletSeed, WalletError> {
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
            .map_err(|_| WalletError::InvalidMnemonic)?;
        let seed = Seed::new(&mnemonic, "");
        Ok(WalletSeed(Zeroizing::new(seed.as_bytes().to_vec())))
    }

    /// Construct directly from raw seed bytes (e.g. after decrypting a sealed seed).
    pub fn from_bytes(bytes: Vec<u8>) -> WalletSeed {
        WalletSeed(Zeroizing::new(bytes))
    }

    /// Borrow the raw seed bytes (kept private to the crate; callers derive, they don't read).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Derive the 32-byte ed25519 secret key for Stellar account `index` (`m/44'/148'/index'`).
    ///
    /// Returned zeroized; feed it to [`crate::signer`] to build a keypair.
    pub fn derive_ed25519_secret(&self, index: u32) -> Zeroizing<[u8; 32]> {
        let path = [
            BIP44_PURPOSE | HARDENED,
            STELLAR_COIN_TYPE | HARDENED,
            index | HARDENED,
        ];
        let key = slip10_ed25519::derive_ed25519_private_key(self.as_bytes(), &path);
        Zeroizing::new(key)
    }
}

/// Draw a new 12-word mnemonic from OS entropy (see [`WalletSeed::generate`]).
fn fresh_mnemonic() -> Mnemonic {
    let mut entropy = Zeroizing::new([0u8; MNEMONIC_ENTROPY_LEN]);
    OsRng.fill_bytes(entropy.as_mut());
    // 16 bytes is a valid BIP39 entropy length, so from_entropy cannot fail here.
    match Mnemonic::from_entropy(entropy.as_ref(), Language::English) {
        Ok(m) => m,
        Err(_) => unreachable!("16-byte entropy is always a valid BIP39 length"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use stellar_strkey::ed25519::PublicKey;

    // Official SEP-0005 Test 1 vector (no passphrase).
    // https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md
    const VECTOR_MNEMONIC: &str =
        "illness spike retreat truth genius clock brain pass fit cave bargain toe";
    // m/44'/148'/0' — verified against the official SEP-0005 Test 1 vector.
    const EXPECTED_ACCOUNT_0: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

    fn account_id(seed: &WalletSeed, index: u32) -> String {
        let secret = seed.derive_ed25519_secret(index);
        let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
        let pk = PublicKey(signing.verifying_key().to_bytes());
        format!("{pk}")
    }

    #[test]
    fn sep0005_account_0_matches_official_vector() {
        let seed = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        assert_eq!(account_id(&seed, 0), EXPECTED_ACCOUNT_0);
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        let b = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        assert_eq!(account_id(&a, 0), account_id(&b, 0));
        assert_eq!(account_id(&a, 5), account_id(&b, 5));
    }

    #[test]
    fn different_indexes_give_different_accounts() {
        let seed = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        assert_ne!(account_id(&seed, 0), account_id(&seed, 1));
        assert_ne!(account_id(&seed, 1), account_id(&seed, 2));
    }

    #[test]
    fn generated_mnemonic_roundtrips() {
        let (phrase, seed) = WalletSeed::generate();
        let reimported = WalletSeed::from_phrase(&phrase).unwrap();
        assert_eq!(account_id(&seed, 0), account_id(&reimported, 0));
    }

    #[test]
    fn generated_mnemonics_never_collide_across_a_large_sample() {
        // Smoke test for a broken/constant RNG on generate()'s entropy path (skips slow PBKDF2).
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let phrase = fresh_mnemonic().phrase().to_string();
            assert!(seen.insert(phrase), "duplicate mnemonic generated");
        }
        let (a, _) = WalletSeed::generate();
        let (b, _) = WalletSeed::generate();
        assert_ne!(*a, *b);
    }

    #[test]
    fn invalid_mnemonic_rejected() {
        assert!(matches!(
            WalletSeed::from_phrase("not a real mnemonic phrase at all"),
            Err(WalletError::InvalidMnemonic)
        ));
    }

    proptest! {
        #[test]
        fn derivation_is_deterministic_for_any_index(
            entropy in any::<[u8; 16]>(),
            index in any::<u32>()
        ) {
            let mnemonic =
                bip39::Mnemonic::from_entropy(&entropy, bip39::Language::English).unwrap();
            let seed_bytes = bip39::Seed::new(&mnemonic, "").as_bytes().to_vec();
            let seed_a = WalletSeed::from_bytes(seed_bytes.clone());
            let seed_b = WalletSeed::from_bytes(seed_bytes);
            let secret_a = seed_a.derive_ed25519_secret(index);
            let secret_b = seed_b.derive_ed25519_secret(index);
            prop_assert_eq!(*secret_a, *secret_b);
        }

        #[test]
        fn distinct_indices_yield_distinct_secrets(
            entropy in any::<[u8; 16]>(),
            index_a in any::<u32>(),
            index_b in any::<u32>()
        ) {
            prop_assume!(index_a != index_b);
            let mnemonic =
                bip39::Mnemonic::from_entropy(&entropy, bip39::Language::English).unwrap();
            let seed =
                WalletSeed::from_bytes(bip39::Seed::new(&mnemonic, "").as_bytes().to_vec());
            let secret_a = seed.derive_ed25519_secret(index_a);
            let secret_b = seed.derive_ed25519_secret(index_b);
            prop_assert_ne!(*secret_a, *secret_b);
        }
    }

    #[test]
    fn boundary_indices_derive_without_panic() {
        let seed = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        // Exercises the hardened-offset OR-mask at the extreme ends of u32:
        // 0, 1 (lowest valid indices), HARDENED-1 (highest non-hardened u32 value),
        // and u32::MAX (wraps the OR-mask into the already-set upper bit).
        for &index in &[0u32, 1, super::HARDENED - 1, u32::MAX] {
            let secret = seed.derive_ed25519_secret(index);
            let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
            let pk = PublicKey(signing.verifying_key().to_bytes());
            let encoded = format!("{pk}");
            let decoded = PublicKey::from_string(&encoded).unwrap();
            assert_eq!(decoded.0, signing.verifying_key().to_bytes());
        }
    }
}
