//! This is not a full implementation and leaves
//! some details out.

use std::{collections::HashMap, env, time::{Duration, Instant}};

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use fips204::ml_dsa_44::PrivateKey;
use quath::{
    DsaSystem, HashingAlgorithm, ProtocolTime, Sec1Kit, ViewBytes, algos::fips204::{MlDsa44, MlDsa44Public}, token::{Final, Token}
};
use sha3::Sha3_256;
use uuid::Uuid;

pub struct AdminContext {
    admin_id: Uuid,
    admin_public: MlDsa44Public,
    admin_private: PrivateKey,
}

pub struct ClientContext {
    client_id: Uuid,
    client_public: MlDsa44Public,
    client_private: PrivateKey,
}

pub struct ServerContext {
    server_public: MlDsa44Public,
    server_private: PrivateKey,
    registry: HashMap<Uuid, MlDsa44Public>,
    token_db: HashMap<[u8; 32], DateTime<Utc>>
}

impl ServerContext {
    pub fn register(&mut self, client_id: Uuid, admin: &AdminContext, timer: &mut TimingData) -> Result<ClientContext> {
        // Start the client registration.
        let start_1 = Instant::now();
        let (packet, client_private) =
            Sec1Kit::client_register_init(client_id, admin.admin_id, &admin.admin_private)?;

        let client_public: MlDsa44Public = packet.public_key().clone();
        let end_1 = Instant::now();

        let start_2  = Instant::now();
        // Do the server registration portion.
        let server_registry_resp =
            Sec1Kit::server_register(&packet, &admin.admin_public, &self.server_private)?;
         // Insert into the registry.
        self.registry.insert(client_id, client_public.clone());

        let end_2 = Instant::now();


        let start_3 = Instant::now();

        // Finish registering the client.
        Sec1Kit::client_register_finish(&server_registry_resp, client_id, &self.server_public)?;


        let end_3 = Instant::now();


        if !timer.is_client {

            
            timer.total_time = end_2 - start_2;

            
        } else {
            timer.total_time = (end_1 - start_1) + (end_3 - start_3);
        }


       
        Ok(ClientContext {
            client_id,
            client_private,
            client_public,
        })
    }
}

impl ClientContext {
    pub fn cycle(&mut self, server_ctx: &mut ServerContext,

            timer: &mut TimingData

    ) -> anyhow::Result<()> {

        let start_1 = Instant::now();

        // Propose a cycle with the details we have.
        let (cycle_req, new_private) =
            Sec1Kit::client_cycle_init(self.client_id, &self.client_private)?;
        let proposed_public = cycle_req.body.new_public_key.0.clone();

        let end_1 = Instant::now();

        let start_2 = Instant::now();

        // Get the server's reply.
        let server_cycle_resp = {
            // SERVER SIDE.

            // We need to read from our database!
            let client_public = server_ctx
                .registry
                .get(&self.client_id)
                .ok_or_else(|| anyhow!("Could not read entry for client ID on server side."))?
                .clone();

            let server_cycle_resp =
                Sec1Kit::server_cycle(&cycle_req, &client_public, &server_ctx.server_private)?;

            *server_ctx
                .registry
                .get_mut(&self.client_id)
                .ok_or_else(|| anyhow::anyhow!("Client missing from server!"))? =
                proposed_public.clone();

            server_cycle_resp
        };

        let end_2 = Instant::now();

        let start_3 = Instant::now();

        Sec1Kit::client_cycle_finish(
            &server_cycle_resp,
            self.client_id,
            &proposed_public,
            &server_ctx.server_public,
        )?;

        // Swap in the new variables.
        self.client_private = new_private;
        self.client_public = proposed_public;

        let end_3 = Instant::now();

        // Make sure the key material is the same.
        assert_eq!(
            self.client_public.view(),
            server_ctx
                .registry
                .get(&self.client_id)
                .clone()
                .unwrap()
                .view()
        );

        if !timer.is_client {

            
            timer.total_time = end_2 - start_2;

            
        } else {
            timer.total_time = (end_1 - start_1) + (end_3 - start_3);
        }

        Ok(())
    }

    pub fn get_token(&mut self, server_ctx: &mut ServerContext, timing: &mut TimingData) -> anyhow::Result<Token<Final>> {
        //

        let start_1 = Instant::now();

        let (token_req, dk) = Sec1Kit::client_token_init(
            0,
            0,
            ProtocolTime(0),
            &self.client_private,
            self.client_id,
            |_| {},
        )?;
        let client_wip_token = token_req.body.token.0.clone();


        let end_1 = Instant::now();

        let start_2 = Instant::now();

        let server_response = {
            // SERVER SIDE.

            // We need to read from our database!
            let client_public = server_ctx
                .registry
                .get(&self.client_id)
                .ok_or_else(|| anyhow!("Could not read entry for client ID on server side."))?
                .clone();

            let (server_response, server_token) = Sec1Kit::server_token(
                &token_req,
                &client_public,
                &server_ctx.server_private,
                ProtocolTime(0),
                Duration::from_hours(1),
            )?;

            let hash = Sha3_256::hash(&server_token.view());
            
            server_ctx.token_db.insert(hash, Utc::now() + Duration::from_hours(1));

            server_response
        };

        let end_2 = Instant::now();

        let start_3 = Instant::now();

        let c =
            Sec1Kit::client_token_finish(&server_response, &client_wip_token, &dk, &server_ctx.server_public)?;
        
        let end_3  = Instant::now();

        if timing.is_client {
            timing.total_time = (end_1 - start_1) + (end_3 - start_3);
        } else {
            timing.total_time = end_2 - start_2;
        }


        
        Ok(c)
    }

    pub fn verify_token(&self, token: &Token<Final>, server_ctx: &mut ServerContext, timer: &mut TimingData) -> anyhow::Result<()> {
        let start = Instant::now();
        let hash = Sha3_256::hash(&token.view());
        let time = server_ctx.token_db.get(&hash).ok_or_else(|| anyhow!("Failed to lookup hash."))?;


        assert!(!timer.is_client, "Cannot time client verification.");



        let result = if *time > Utc::now() {
            Ok(())
        } else {
            server_ctx.token_db.remove(&hash);
            Err(anyhow!("Token expired."))
        };

        let end = Instant::now();

        timer.total_time = end - start;

        result

    }
}



#[derive(Clone)]
pub struct TimingData {
    is_client: bool,
    total_time: Duration    
}

impl TimingData {
    pub fn time_client() -> Self {
        Self {
            is_client: true,
            total_time: Duration::ZERO
        }
    }
    pub fn time_server() -> Self {
        Self {
            is_client: false,
            total_time: Duration::ZERO
        }
    }
}

#[derive(Debug, Clone)]
pub enum Test {
    None,
    Cycle,
    Register,
    Verify,
    Stamp
}

pub fn main() -> anyhow::Result<()> {

    let mut is_client = false;
    let mut test = Test::None;

    let arguments = env::args().collect::<Vec<String>>();
    if arguments.len() != 4 {
        println!("You must specify three args!\n\tUsage: benchmark <client/server> <stamp/verify/cycle> <rounds>");
        return Ok(());
    }

    if arguments[1].eq_ignore_ascii_case("client") {
        is_client = true;
    } else if arguments[1].eq_ignore_ascii_case("server") {
        is_client = false;
    } else {
        println!("You must specify <client/server> for the first argument.");
        return Ok(());
    }


    if arguments[2].eq_ignore_ascii_case("cycle") {
        test = Test::Cycle;
    } else if arguments[2].eq_ignore_ascii_case("stamp") {
        test = Test::Stamp;  
    } else if arguments[2].eq_ignore_ascii_case("register") {
        test = Test::Register;
    } else if arguments[2].eq_ignore_ascii_case("verify") {
        test = Test::Verify;
    } else {
        println!("Not a valid test.");
        return Ok(());
    }

    let rounds = str::parse::<usize>(arguments[3].as_str())?;


    


    let client_id = Uuid::new_v4();
    let admin_id = Uuid::new_v4();

    
    let (admin_public, admin_private) = MlDsa44::generate().unwrap();
    let (server_public, server_private) = MlDsa44::generate().unwrap();

    // Make an admin context struct.
    let admin_ctx = AdminContext {
        admin_id,
        admin_private,
        admin_public,
    };

    // Make a server context struct.
    let mut server_ctx = ServerContext {
        server_private,
        server_public,
        registry: HashMap::default(),
        token_db: HashMap::default()
    };

    let mut client = server_ctx.register(client_id, &admin_ctx, &mut TimingData::time_client())?;
    let mut timings = vec![];
    
    let mut token = None;
    for _ in 0..rounds {
        let mut timing = if is_client {
            TimingData::time_client()
        } else {
            TimingData::time_server()
        };
        match test {
            Test::Register => {
                server_ctx.registry.clear();
                client = server_ctx.register(client_id, &admin_ctx, &mut timing)?;
            },
            Test::Stamp => {
                client.get_token(&mut server_ctx, &mut timing)?;
            }
            Test::Verify => {
                if token.is_none() {
                    token = Some(client.get_token(&mut server_ctx, &mut TimingData::time_client())?);
                }

                client.verify_token(token.as_ref().unwrap(), &mut server_ctx, &mut timing)?;


            }
            Test::Cycle => client.cycle(&mut server_ctx, &mut timing)?,
            Test::None => panic!("Invalid test.")
        }
        
        timings.push(timing);
    }

    let length = timings.len();
    
    let average = timings.clone().into_iter().map(|f| f.total_time).fold(Duration::ZERO, std::ops::Add::add).as_secs_f64() / length as f64;
    
    let time_min = timings.iter().map(|f| f.total_time).min().unwrap();
    let time_max = timings.iter().map(|f| f.total_time).max().unwrap();


    timings.sort_by_key(|f| f.total_time);

    let median = timings[timings.len() / 2].total_time;
    

    print!("Mode:\t\t\t");
    if is_client {
        println!("CLIENT");
    } else {
        println!("SERVER");
    }

    let f_list = timings.iter().map(|f| f.total_time.as_secs_f64()).collect::<Vec<_>>();
    let median = statistical::median(&f_list);
    let stdev = statistical::standard_deviation(&f_list, None);


    println!("Test:\t\t\t{:?}", test);
    println!("Total Runs:\t\t{length}");
    println!("Average Time (ms):\t{:.4}ms", average * 1000.);
    println!("Min Time (ms):\t\t{:.4}ms", time_min.as_secs_f64() * 1000.);
    println!("Max Time (ms):\t\t{:.4}ms", time_max.as_secs_f64() * 1000.);
    println!("Std. Dev. (ms):\t\t{:.4}ms", stdev * 1000.);
    println!("Median (ms):\t\t{:.4}ms", median * 1000.);
    // println!()
    // println!("Timing: {:.2}ms", average * 1000.);

    // let token = client.get_token(&mut server_ctx)?;
    // client.verify_token(&token, &mut server_ctx)?;

  
    Ok(())
}
