use std::{fmt::Debug, time::Duration};

use arbitrary::Arbitrary;

use crate::core::crypto::{DsaSystem, PrivateKey, PublicKey};

pub const ARBTEST_DURATION: Duration = Duration::from_secs(2);

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