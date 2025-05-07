
// use fips203::ml_kem_512; // Could also be ml_kem_768 or ml_kem_1024. 
// use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
// use k256::ecdsa::VerifyingKey;
// use quath::algos::ecdsa::K256ECDSA;
// use quath::algos::fips204::{MlDsa44, MlDsa87};
// use quath::core::crypto::protocol::{ClientRegisterError, MlClassicLight, MlDSA44, MlStandardLight, OpCode, ProtocolKit};
// use quath::core::crypto::token::MsSinceEpoch;
// use quath::core::crypto::{DsaSystem, Identifier, SigningAlgorithm, ToBytes};
// use uuid::Uuid;



pub fn main() {
    

    // let admin_id = Uuid::new_v4();
    // let (admin_pub, admin_priv) = MlDsa44::generate().unwrap();
    // let (server_pub, server_priv) = MlDsa44::generate().unwrap();


    // let (
    //     packet,
    //     client_priv
    // ) = MlStandardLight::client_register_init(admin_id, &admin_priv).map_err(|e| "yo").unwrap();


    // println!("FLAG A");
    // MlStandardLight::server_register(&packet, &admin_pub, &server_priv).unwrap();
    
    // println!("SERVER REGISTER");

    // let (token, dk) = MlStandardLight::client_token_init(MsSinceEpoch(0), &client_priv, packet.body.identifier, &()).unwrap();

    // println!("INIT");
    // let pending_tok = token.body.token.clone();
    
    // let (packet, server_tok) = MlStandardLight::server_token(token, &packet.body.public_key, &(), &server_priv).unwrap();

    // let client_token = MlStandardLight::client_token_finish(&pending_tok, &dk, packet, &server_pub, &()).unwrap();

    // println!("SERVER TOKEN: {:?}", server_tok);
    // println!("CLIENT TOK: {:?}", client_token);

    // // let admin_id = Uuid::new_v4();
    // // let (admin_pub, admin_priv) = K256ECDSA::generate().unwrap();


    // // let (server_pub, server_priv) = K256ECDSA::generate().unwrap();


    // // let (
    // //     packet,
    // //     client_priv
    // // ) = MlClassicLight::client_register_init(admin_id, &admin_priv).map_err(|_| "d").unwrap();



    // // println!("KEY SIZE: {:?}", size_of_val(&server_pub.to_encoded_point(false)));
    
    // // let client_id = packet.body.1;


    // // let server_register = MlClassicLight::server_register(&packet, &admin_pub, &server_priv).unwrap();

    
    // // let (tok, dk) = MlClassicLight::client_token_init(MsSinceEpoch(0), &client_priv, client_id, &()).map_err(|_| "").unwrap();


    // // let client_token = tok.token().clone();

    // // let (server_packet, token) = MlClassicLight::server_token(tok, &packet.body.2, &(), &server_priv).map_err(|_| "").unwrap();






    // // let c = MlClassicLight::client_token_finish(&client_token, &dk, server_packet, &server_pub, &()).map_err(|_| "").unwrap();

    // // println!("Server Token: {:?}", token);
    // // println!("Client Token: {:?}", c);

}