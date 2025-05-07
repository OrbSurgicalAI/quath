
use fips203::ml_kem_512; // Could also be ml_kem_768 or ml_kem_1024. 
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use quath::core::crypto::protocol::{MlDSA44, MlStandardLight, ProtocolKit};
use quath::core::crypto::token::MsSinceEpoch;
use quath::core::crypto::SigningAlgorithm;
use uuid::Uuid;



pub fn main() {
    

    let admin_id = Uuid::new_v4();
    let (admin_pub, admin_priv) = MlDSA44::generate().unwrap();


    let (server_pub, server_priv) = MlDSA44::generate().unwrap();


    let (
        packet,
        client_priv
    ) = MlStandardLight::client_register_init(admin_id, &admin_priv).map_err(|_| "d").unwrap();


    
    let client_id = packet.body.1;


    let server_register = MlStandardLight::server_register(&packet, &admin_pub, &server_priv).unwrap();

    
    let (tok, dk) = MlStandardLight::client_token_init(MsSinceEpoch(0), &client_priv, client_id, &()).map_err(|_| "").unwrap();


    let client_token = tok.token().clone();

    let (server_packet, token) = MlStandardLight::server_token(tok, &packet.body.2, &(), &server_priv).map_err(|_| "").unwrap();






    let c = MlStandardLight::client_token_finish(&client_token, &dk, server_packet, &server_pub, &()).map_err(|_| "").unwrap();

    println!("Server Token: {:?}", token);
    println!("Client Token: {:?}", c);

}