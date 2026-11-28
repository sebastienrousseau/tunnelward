// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ML-KEM-768 from aws-lc-rs, which every tunnelward handshake and
//! gateway-blind call uses, checked against kyberlib, an independent
//! implementation (test only). One key is shared: kyberlib derives it
//! from a random seed and aws-lc-rs imports its expanded form.
//!
//! - kyberlib encapsulates to keys aws-lc-rs generates, which open.
//! - 2,000 encapsulations each way: one side encapsulates, the other
//!   decapsulates to the same shared secret.
//! - 500 tampered ciphertexts: both reject implicitly (FIPS 203) to the
//!   same secret, which is not the real one.

use aws_lc_rs::kem::{AlgorithmId, Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use kyberlib::{CryptoRng, KemCore, MlKem768, MlKem768Ciphertext, MlKem768EncapKey, RngCore};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

const ROUND_TRIPS: usize = 2_000;
const TAMPERED: usize = 500;

/// kyberlib's RNG trait over the system's randomness, from aws-lc-rs.
/// `fill_bytes` cannot fail, so a failure is noted in `failed`, which
/// every test checks at its end.
struct System(SystemRandom, bool);

impl System {
    fn new() -> Self {
        Self(SystemRandom::new(), false)
    }

    fn held(&self) -> Res<()> {
        if self.1 {
            return Err("the system's randomness failed".into());
        }
        Ok(())
    }
}

impl RngCore for System {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.0.fill(dest).is_err() {
            self.1 = true;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0
            .fill(dest)
            .map_err(|_| rand_core::Error::from(core::num::NonZeroU32::MIN))
    }
}

impl CryptoRng for System {}

/// A key pair both libraries hold: kyberlib's, from a random seed.
struct Shared {
    kyber_secret: kyberlib::MlKem768DecapKey,
    kyber_public: MlKem768EncapKey,
    aws_secret: DecapsulationKey<AlgorithmId>,
}

fn debug(e: impl core::fmt::Debug) -> String {
    format!("{e:?}")
}

fn shared(rng: &mut System) -> Res<Shared> {
    let (mut d, mut z) = ([0; 32], [0; 32]);
    rng.0.fill(&mut d).map_err(debug)?;
    rng.0.fill(&mut z).map_err(debug)?;
    let (kyber_secret, kyber_public) = MlKem768::generate_from_seed(&d, &z).map_err(debug)?;
    let aws_secret = DecapsulationKey::new(&ML_KEM_768, kyber_secret.as_bytes()).map_err(debug)?;
    Ok(Shared {
        kyber_secret,
        kyber_public,
        aws_secret,
    })
}

/// kyberlib encapsulates to `ek`: (ciphertext, shared secret).
fn kyber_encapsulate(ek: &MlKem768EncapKey, rng: &mut System) -> Res<(Vec<u8>, Vec<u8>)> {
    let (ct, ss) = ek.encapsulate(rng).map_err(debug)?;
    Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
}

fn kyber_decapsulate(dk: &kyberlib::MlKem768DecapKey, ct: &[u8]) -> Res<Vec<u8>> {
    let ct = MlKem768Ciphertext::try_from_slice(ct).map_err(debug)?;
    Ok(dk.decapsulate(&ct).as_bytes().to_vec())
}

fn aws_encapsulate(ek: &EncapsulationKey<AlgorithmId>) -> Res<(Vec<u8>, Vec<u8>)> {
    let (ct, ss) = ek.encapsulate().map_err(debug)?;
    Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
}

fn aws_decapsulate(dk: &DecapsulationKey<AlgorithmId>, ct: &[u8]) -> Res<Vec<u8>> {
    let ss = dk.decapsulate(Ciphertext::from(ct)).map_err(debug)?;
    Ok(ss.as_ref().to_vec())
}

/// aws-lc-rs cannot derive the encapsulation key of a key it imported,
/// so its own keys are checked this way: kyberlib encapsulates to the
/// encapsulation key aws-lc-rs generated, and aws-lc-rs opens it.
#[test]
fn kyberlib_encapsulates_to_keys_aws_lc_rs_generates() -> Res<()> {
    let mut rng = System::new();
    for _ in 0..64 {
        let dk = DecapsulationKey::generate(&ML_KEM_768).map_err(debug)?;
        let ek = dk
            .encapsulation_key()
            .and_then(|ek| ek.key_bytes())
            .map_err(debug)?;
        let ek = MlKem768EncapKey::try_from_slice(ek.as_ref()).map_err(debug)?;
        let (ct, ss) = kyber_encapsulate(&ek, &mut rng)?;
        assert_eq!(aws_decapsulate(&dk, &ct)?, ss);
    }
    rng.held()
}

#[test]
fn each_decapsulates_what_the_other_encapsulates() -> Res<()> {
    let mut rng = System::new();
    let key = shared(&mut rng)?;
    let aws_ek = EncapsulationKey::new(&ML_KEM_768, key.kyber_public.as_bytes()).map_err(debug)?;
    for _ in 0..ROUND_TRIPS {
        let (ct, ss) = aws_encapsulate(&aws_ek)?;
        assert_eq!(kyber_decapsulate(&key.kyber_secret, &ct)?, ss);
        let (ct, ss) = kyber_encapsulate(&key.kyber_public, &mut rng)?;
        assert_eq!(aws_decapsulate(&key.aws_secret, &ct)?, ss);
    }
    rng.held()
}

#[test]
fn both_reject_a_tampered_ciphertext_to_the_same_secret() -> Res<()> {
    let mut rng = System::new();
    let key = shared(&mut rng)?;
    for i in 0..TAMPERED {
        let (mut ct, ss) = kyber_encapsulate(&key.kyber_public, &mut rng)?;
        let at = (rng.next_u32() as usize) % ct.len();
        ct[at] ^= 1 << (i % 8);
        let aws = aws_decapsulate(&key.aws_secret, &ct)?;
        assert_eq!(aws, kyber_decapsulate(&key.kyber_secret, &ct)?, "byte {at}");
        assert_ne!(aws, ss, "byte {at}: not rejected");
    }
    rng.held()
}
