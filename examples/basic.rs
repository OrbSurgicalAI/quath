// use fips203::ml_kem_512; // Could also be ml_kem_768 or ml_kem_1024.
// use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
// use k256::ecdsa::VerifyingKey;
// use quath::algos::ecdsa::K256ECDSA;
// use quath::algos::fips204::{MlDsa44, MlDsa87};
// use quath::core::crypto::protocol::{ClientRegisterError, MlClassicLight, MlDSA44, MlStandardLight, OpCode, ProtocolKit};
// use quath::core::crypto::token::MsSinceEpoch;
// use quath::core::crypto::{DsaSystem, Identifier, SigningAlgorithm, ToBytes};
// use uuid::Uuid;

use std::time::Duration;

use base64::{Engine, prelude::BASE64_STANDARD};
use chrono::Utc;
use quath::{DsaSystem, ProtocolTime, Sec1Kit, algos::{fips203::MlKem512, fips204::MlDsa44}, protocol::ProtocolKit};
use sha2::Sha256;
use sha3::Sha3_256;
use uuid::Uuid;

type StandardPk = ProtocolKit<MlDsa44, MlKem512, Sha256, 32>;


pub fn main() -> anyhow::Result<()> {

    let client_id = Uuid::new_v4();
    let admin_id = Uuid::new_v4();

    let (admin_public, admin_private) = MlDsa44::generate().unwrap();
    let (server_public, server_private) = MlDsa44::generate().unwrap();



    // Start the client registration.
    let (packet, client_priv_key) = Sec1Kit::client_register_init(client_id, admin_id, &admin_private)?;

    let client_public = packet.body.public_key.0.clone();

    // Do the server registration portion.
    let server_registry_resp = Sec1Kit::server_register(&packet, &admin_public, &server_private)?;

    // Finish registering the client.
    Sec1Kit::client_register_finish(&server_registry_resp, client_id, &server_public)?;

    

    // Now do a cycle.
    let (cycle_req, new_private) = Sec1Kit::client_cycle_init(client_id, &client_priv_key)?;
    let proposed_public = cycle_req.body.new_public_key.0.clone();
    let server_cycle_resp = Sec1Kit::server_cycle(&cycle_req, &client_public, &server_private)?;
    Sec1Kit::client_cycle_finish(&server_cycle_resp, client_id, &proposed_public, &server_public)?;


    // Now we will make a token.
    let (token_req, dk) = Sec1Kit::client_token_init(0, 0, ProtocolTime(0), &client_priv_key, client_id, |_| {})?;

    let client_wip_token = token_req.body.token.0.clone();

    let (server_response, server_token) = Sec1Kit::server_token(&token_req, &client_public, &server_private, ProtocolTime(0), Duration::from_hours(1))?;

    let c = Sec1Kit::client_token_finish(&server_response, &client_wip_token, &dk, &server_public)?;


    
    println!("Client Secret Portion:\t{}", BASE64_STANDARD.encode(&c.body));
    println!("Server Secret Portion:\t{}", BASE64_STANDARD.encode(&server_token.body));




    Ok(())

    // let client_id = Uuid::new_v4();
    // let admin_id = Uuid::new_v4();
    // let (admin_pub, admin_priv) = MlDsa44::generate().unwrap();
    // let (server_pub, server_priv) = MlDsa44::generate().unwrap();

    // let a = ProtocolKit::<MlDsa44, MlKem512, Sha256, 32>::client_register_init(client_id, admin_id, admin_priv);


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

    // let admin_id = Uuid::new_v4();
    // let (admin_pub, admin_priv) = K256ECDSA::generate().unwrap();

    // let (server_pub, server_priv) = K256ECDSA::generate().unwrap();

    // let (
    //     packet,
    //     client_priv
    // ) = MlClassicLight::client_register_init(admin_id, &admin_priv).map_err(|_| "d").unwrap();

    // println!("KEY SIZE: {:?}", size_of_val(&server_pub.to_encoded_point(false)));

    // let client_id = packet.body.1;

    // let server_register = MlClassicLight::server_register(&packet, &admin_pub, &server_priv).unwrap();

    // let (tok, dk) = MlClassicLight::client_token_init(MsSinceEpoch(0), &client_priv, client_id, &()).map_err(|_| "").unwrap();

    // let client_token = tok.token().clone();

    // let (server_packet, token) = MlClassicLight::server_token(tok, &packet.body.2, &(), &server_priv).map_err(|_| "").unwrap();

    // let c = MlClassicLight::client_token_finish(&client_token, &dk, server_packet, &server_pub, &()).map_err(|_| "").unwrap();

    // println!("Server Token: {:?}", token);
    // println!("Client Token: {:?}", c);
}
