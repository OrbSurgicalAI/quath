
use fips203::ml_kem_512; // Could also be ml_kem_768 or ml_kem_1024. 
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};



pub fn main() {
    // Use the desired target parameter set.
    
    // Alice runs `try_keygen()` and then serializes the encaps key `ek` for Bob (to bytes).
    let (alice_ek, alice_dk) = ml_kem_512::KG::try_keygen().unwrap();
    let alice_ek_bytes = alice_ek.into_bytes();

    // Alice sends the encaps key `ek_bytes` to Bob.
    let bob_ek_bytes = alice_ek_bytes;

    // Bob deserializes the encaps `ek_bytes` and then runs `encaps() to get the shared 
    // secret `ssk` and ciphertext `ct`. He serializes the ciphertext `ct` for Alice (to bytes).
    let bob_ek = ml_kem_512::EncapsKey::try_from_bytes(bob_ek_bytes).unwrap();
    let (bob_ssk_bytes, bob_ct) = bob_ek.try_encaps().unwrap();
    let bob_ct_bytes = bob_ct.into_bytes();

    // Bob sends the ciphertext `ct_bytes` to Alice
    let alice_ct_bytes = bob_ct_bytes;

    // Alice deserializes the ciphertext `ct` and runs `decaps()` with her decaps key
    let alice_ct = ml_kem_512::CipherText::try_from_bytes(alice_ct_bytes).unwrap();
    let alice_ssk_bytes = alice_dk.try_decaps(&alice_ct).unwrap();


    println!("Bob SK: {:?}, Alice: {:?}", bob_ssk_bytes, alice_ssk_bytes);

    // Alice and Bob will now have the same secret key
    assert_eq!(bob_ssk_bytes, alice_ssk_bytes);

}