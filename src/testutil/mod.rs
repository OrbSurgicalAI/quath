use std::{fmt::Debug, time::Duration};

use arbitrary::Arbitrary;
use uuid::Uuid;

use crate::core::crypto::{DsaSystem, PrivateKey, PublicKey};
pub const ARBTEST_DURATION: Duration = Duration::from_secs(2);


pub struct BasicSetupDetails<S>
where 
    S: DsaSystem
{
    pub client_id: Uuid,
    pub admin_id: Uuid,
    pub admin_pk: S::Public,
    pub admin_sk: S::Private,
    pub server_pk: S::Public,
    pub server_sk: S::Private
}

impl<S: DsaSystem> BasicSetupDetails<S> {
    pub fn new() -> Self {
        let client_id = Uuid::new_v4();
        let admin_id = Uuid::new_v4();

        let (admin_pk, admin_sk) = S::generate().map_err(|_| "failed").unwrap();
        let (server_pk, server_sk) = S::generate().map_err(|_| "failed").unwrap();

        Self {
            client_id,
            admin_id,
            admin_pk,
            admin_sk,
            server_pk,
            server_sk
        }
    }
}


pub fn run_arbtest_harness_simple<S>()
where 
    S: DsaSystem,
    S::GenError: Debug,
    <<S as DsaSystem>::Private as crate::core::crypto::PrivateKey>::Error: Debug
{
    arbtest::arbtest(|u| {
        let wow = Vec::arbitrary(u)?;
        test_signing_harness::<S>(&wow);

        Ok(())
    }).budget(ARBTEST_DURATION);
    
}

pub fn test_signing_harness<S>(message: &[u8])
where 
    S: DsaSystem,

    S::GenError: Debug,
    <<S as DsaSystem>::Private as crate::core::crypto::PrivateKey>::Error: Debug
{
    let (public, private) = S::generate().unwrap();
    let signature = private.sign_bytes(message).unwrap();
    // let signature = S::sign_bytes(message, &private).unwrap();
    assert!(public.verify(message, &signature));

    let (public2, private2) = S::generate().unwrap();
    let sig2 = private2.sign_bytes(message).unwrap();
    // let sig2 = S::sign_bytes(message, &private2).unwrap();

    assert!(!public.verify(message, &sig2));
    assert!(!public2.verify(message, &signature));


   

}



#[cfg(test)]
mod tests {
    use crate::core::crypto::{specials::{FauxChain, FauxKem}, DsaSystem, KemAlgorithm, PrivateKey, PublicKey};

  


    #[test]
    pub fn test_faux_dsa() {
        let (f_pk, f_sk) = FauxChain::generate().unwrap();
        let (f_pk2, _) = FauxChain::generate().unwrap();
        let sign = f_sk.sign_bytes(&[1, 2, 3]).unwrap();
        assert!(f_pk.verify(&[1, 2, 3], &sign));
        assert!(!f_pk.verify(&[1, 2], &sign));
        assert!(!f_pk2.verify(&[1, 2, 3], &sign));

    }

    #[test]
    pub fn test_faux_kem() {
        let (dk, ek) = FauxKem::generate().unwrap();
        let (ct, ss) = FauxKem::encapsulate(&ek).unwrap();
        let c_ss = FauxKem::decapsulate(&dk, &ct).unwrap();
        assert_eq!(c_ss.0, ss.0);
    }
}