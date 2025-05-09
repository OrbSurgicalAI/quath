mod client;
mod register;
mod server_register;
mod server_cycle;

use std::task::Poll;

pub use client::*;
pub use register::*;
pub use server_register::*;
pub use server_cycle::*;

use crate::ServerProtocolError;

pub type ServerPollResult<T> = Poll<Result<T, ServerProtocolError>>;

#[cfg(test)]
mod tests {
    use std::{task::Poll, time::Duration};

    use sha3::Sha3_256;
    use uuid::Uuid;

    use crate::{
        specials::{FauxChain, FauxKem},
        testutil::BasicSetupDetails, MsSinceEpoch,
    };

    use super::{ClientDriver, RegistryDriver, RegistryOutput, ServerRegistryDriver, ServerRegistryOutput};

    #[test]
    pub fn registry_tandem_happy() {
        // Generate a setup.
        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut reg_client_driver = RegistryDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            setup.admin_id,
            setup.admin_sk.clone(),
            setup.client_id,
            setup.server_pk.clone(),
        );

        let mut reg_server_driver = ServerRegistryDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(setup.server_sk.clone());


        reg_client_driver.recv(None).unwrap();

        #[allow(irrefutable_let_patterns)]
        let RegistryOutput::RegisterRequest(inner) = reg_client_driver.poll_transmit().unwrap() else {
            panic!("Incorrect request from the client.");
        };

        reg_server_driver.recv(MsSinceEpoch(0), Some(super::ServerRegistryInput::ClientRequest(inner)));
        
        let ServerRegistryOutput::VerifyRequestIntegrity { requested_id, admin_id, public_key } = reg_server_driver.poll_transmit().unwrap() else {
            panic!("server did not try to verify the request integrity.");
        };

        reg_server_driver.recv(MsSinceEpoch(0),  Some(super::ServerRegistryInput::VerificationResponse(super::VerifyRequestIntegrityResponse::Success { admin_public: setup.admin_pk.clone() })));

        let ServerRegistryOutput::StoreRegistry { client_id, public_key, time } = reg_server_driver.poll_transmit().unwrap() else {
            panic!("server did not try to store.");
        };


        reg_server_driver.recv(MsSinceEpoch(0), Some(super::ServerRegistryInput::StoreSucess));


        let Poll::Ready(Ok(inner)) = reg_server_driver.poll_result() else {
            panic!("server did not response.");
        };

        reg_client_driver.recv(Some(super::RegistryInput::Response(inner))).unwrap();

        

        let Poll::Ready(inner) = reg_client_driver.poll_completion() else {
            panic!("clien did not complete registry.");
        };


       
        // let mut client = ClientDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(setup.admin_id, setup.);
    }
}
