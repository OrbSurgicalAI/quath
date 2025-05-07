use std::fmt::Debug;

use crate::core::crypto::SigningAlgorithm;


pub fn test_signing_harness<S>(message: &[u8])
where 
    S: SigningAlgorithm,

    S::Error: Debug
{
    let (public, private) = S::generate().unwrap();
    let signature = S::sign_bytes(message, &private).unwrap();
    assert!(S::verify_bytes(message, &signature, &public));

    let (public2, private2) = S::generate().unwrap();
    let sig2 = S::sign_bytes(message, &private2).unwrap();

    assert!(!S::verify_bytes(message, &sig2, &public));
    assert!(!S::verify_bytes(message, &signature, &public2));
   

}