use std::{cmp::Ordering, marker::PhantomData};

use uuid::Uuid;

use crate::token::{self, signature::{KeyChain, PrivateKey, PublicKey, Signature}, token::{AliveToken, FluidToken, GenericToken}};

use super::{config::Configuration, error::FluidError};


/// Manages the context of the protocol.
pub trait ProtocolCtx<D>
{
    /// Compares the current time against another time.
    fn current_time(&self) -> D;
    fn config(&self) -> &Configuration;
}

pub trait TimeObj {
    fn cmp_within(&self, other: &Self, bound: u64) -> Ordering {
        (self.seconds() + bound).cmp(&(other.seconds()))
    }
    fn from_seconds(seconds: u64) -> Self;
    fn seconds(&self) -> u64;
}


pub trait FixedByteRepr<const N: usize> {
    fn to_fixed_repr(&self) -> [u8; N];
    fn from_fixed_repr(val: [u8; N]) -> Self;
}



pub trait SyncProtocolExtrServer<PUB, S, D, CTX, M>
where 
    D: TimeObj,
    CTX: ProtocolCtx<D>,
    PUB: PublicKey<S>
{
    type Error;
    fn ctx(&self) -> &CTX;
    fn register(&self, id: Uuid, pb: PUB, last_key_cycle: D, metadata: Option<M>) -> Result<(), Self::Error>;
    fn deregister(&self, id: Uuid) -> Result<Uuid, Self::Error>;
    fn patch(&self, id: Uuid, metadata: Option<M>) -> Result<(), Self::Error>;
    fn stamp<T, P>(&self, token: FluidToken<D, T, P>) -> Result<FluidToken<D, T, P>, Self::Error>;
    fn revoke<T, P>(&self, token: &FluidToken<D, T, P>) -> Result<FluidToken<D, T, P>, Self::Error>;
    fn revoke_all(&self, id: Uuid) -> Result<(), Self::Error>;
}

// pub trait BaseProtocol {
//     fn generate<D, T, P, C: ProtocolCtx<D>>(ctx: &C, token_type: &T, protocol: &P) -> FluidToken<D, T, P>;
// }



pub trait SyncClient<D, C, KC, T, P>
where
    C: ProtocolCtx<D>,
    KC: KeyChain,
    D: FixedByteRepr<8> + TimeObj,
    T: FixedByteRepr<1> + Clone,
    P: FixedByteRepr<1> + Clone,
    KC::Error: Into<Self::Err>,
    
{
    type Err: From<FluidError> + From<KC::Error>;


    fn ctx(&self) -> &C;
    fn get_id(&self) -> Result<Option<Uuid>, Self::Err>;
    fn set_id(&mut self, id: Option<Uuid>) -> Result<Option<Uuid>, Self::Err>;
    fn private_key(&self) -> Result<&Option<KC::Private>, Self::Err>;
    fn set_private_key(&mut self, privkey: Option<KC::Private>) -> Result<(), Self::Err>;
    fn get_current_token(&self) -> Result<&Option<AliveToken<D>>, Self::Err>;
    fn set_current_token(&mut self, token: Option<AliveToken<D>>) -> Result<(), Self::Err>;
    fn stamp_request(&self, id: Uuid, token: &GenericToken<D>, signature: &KC::Signature) -> Result<Response<D>, Self::Err>;
    fn cycle_request(&self, id: Uuid, public: &KC::Public, new_sig: &KC::Signature, old_sig: &KC::Signature) -> Result<bool, Self::Err>;
    fn register_request(&self, id: Uuid, public: &KC::Public) -> Result<Uuid, Self::Err>;
    fn generate(&self, token_type: T, protocol: P) -> Result<FluidToken<D, T, P>, Self::Err> {
        Ok(FluidToken::generate(self.ctx(), self.get_id()?.ok_or(FluidError::ClientNotRegistered)?, token_type, protocol))
    }

    fn sign(&self, token: FluidToken<D, T, P>) -> Result<(GenericToken<D>, KC::Signature), Self::Err>
    where 
        T: FixedByteRepr<1>,
        P: FixedByteRepr<1>
    {
        let sign = self.private_key()?.as_ref().ok_or(FluidError::ClientNoPrivateKey)?.sign(&token.to_bytes())?;
        Ok((token.generic(), sign))
    }
   
    fn refresh_token(&mut self, token_type: T, token_protocol: P) -> Result<&GenericToken<D>, Self::Err>
    where 
        T: FixedByteRepr<1>,
        P: FixedByteRepr<1>
    {

        let (new_tok, new_sig) = self.sign(self.generate(token_type.clone(), token_protocol.clone())?)?;

        let response = self.stamp_request(self.get_id()?.ok_or(FluidError::ClientNotRegistered)?, &new_tok, &new_sig)?;
        match response {
            Response::Return { token, life } => {
                self.set_current_token(Some(AliveToken::from_raw(token, life)))?;
                Ok(self.get_current_token()?.as_ref().unwrap().token())
            },
            Response::Invalid => {
                return Err(FluidError::ServerRejectedToken)?;
            },
            Response::CycleRequired => {
                let (public, private) = KC::generate();

                let sig_new = private.sign(public.as_bytes())?;
                let sig_old = self.private_key()?.as_ref().ok_or(FluidError::ClientNoPrivateKey)?.sign(public.as_bytes())?;


                let cycle = self.cycle_request(self.get_id()?.ok_or(FluidError::ClientNotRegistered)?, &public, &sig_new, &sig_old)?;
                if cycle {
                    // Success! Let's store it and rerun.
                    self.set_private_key(Some(private))?;
                    return self.refresh_token(token_type, token_protocol);
                    
                } else {
                    return Err(FluidError::ServerRejectedCycle)?;
                }

            }
        }


    }
    fn is_registered(&self) -> Result<bool, Self::Err> {
        Ok(self.get_id()?.is_some() && self.private_key()?.is_some())
    }
    fn is_current_valid(&self) -> Result<bool, Self::Err> {
        if let Some(token) = self.get_current_token()? {
            Ok(token.is_alive(self.ctx()))
        } else {
            Ok(false)
        }
    }
    fn register(&mut self) -> Result<(), Self::Err> {
        let (public, private) = KC::generate();
        let id = Uuid::new_v4();

        self.register_request(id, &public)?;

        self.set_private_key(Some(private))?;
        self.set_id(Some(id))?;
        Ok(())


    }
    fn execute(&mut self, token_type: T, token_protocol: P) -> Result<&GenericToken<D>, Self::Err>
    where 
        T: FixedByteRepr<1>,
        P: FixedByteRepr<1>
    {
        if !self.is_registered()? {
            // We are not registered.
            self.register()?;
        }
        if self.is_current_valid()? {
            return Ok(self.get_current_token()?.as_ref().unwrap().token());
        }
        
        self.refresh_token(token_type, token_protocol)
    }
    fn get_token(&mut self, token_type: T, token_protocol: P) -> Result<&GenericToken<D>, Self::Err> {
        self.execute(token_type, token_protocol)
    }
    

}






pub trait AsyncClient<D, C, KC, T, P>
where
    C: ProtocolCtx<D>,
    KC: KeyChain,
    D: FixedByteRepr<8> + TimeObj + 'static,
    T: FixedByteRepr<1> + Clone,
    P: FixedByteRepr<1> + Clone,
    KC::Error: Into<Self::Err>,
    
{
    type Err: From<FluidError> + From<KC::Error>;


    fn ctx<'a>(&'a self) -> impl Future<Output = &'a C> where C: 'a;
    async fn get_id<'a>(&self) -> Result<Option<Uuid>, Self::Err> where C: 'a;
    async fn set_id(&mut self, id: Option<Uuid>) -> Result<Option<Uuid>, Self::Err>;
    async fn private_key<'a>(&'a self) -> Result<&'a Option<KC::Private>, Self::Err> where KC::Private: 'a;
    async fn set_private_key(&mut self, privkey: Option<KC::Private>) -> Result<(), Self::Err>;
    async fn get_current_token<'a>(&'a self) -> Result<&'a Option<AliveToken<D>>, Self::Err> where D: 'a;
    async fn set_current_token(&mut self, token: Option<AliveToken<D>>) -> Result<(), Self::Err>;
    async fn stamp_request(&self, id: Uuid, token: &GenericToken<D>, signature: &KC::Signature) -> Result<Response<D>, Self::Err>;
    async fn cycle_request(&self, id: Uuid, public: &KC::Public, new_sig: &KC::Signature, old_sig: &KC::Signature) -> Result<bool, Self::Err>;
    async fn register_request(&self, id: Uuid, public: &KC::Public) -> Result<Uuid, Self::Err>;
    async fn generate(&self, token_type: T, protocol: P) -> Result<FluidToken<D, T, P>, Self::Err> {
        Ok(FluidToken::generate(self.ctx().await, self.get_id().await?.ok_or(FluidError::ClientNotRegistered)?, token_type, protocol))
    }

    async fn sign(&self, token: FluidToken<D, T, P>) -> Result<(GenericToken<D>, KC::Signature), Self::Err>
    where 
        T: FixedByteRepr<1>,
        P: FixedByteRepr<1>
    {
        let sign = self.private_key().await?.as_ref().ok_or(FluidError::ClientNoPrivateKey)?.sign(&token.to_bytes())?;
        Ok((token.generic(), sign))
    }
   
    async fn refresh_token<'a>(&'a mut self, token_type: T, token_protocol: P) -> Result<&'a GenericToken<D>, Self::Err>
    where 
        T: FixedByteRepr<1>,
        P: FixedByteRepr<1>,
        D: 'a
    {

        let (new_tok, new_sig) = self.sign(self.generate(token_type.clone(), token_protocol.clone()).await?).await?;
        let response = self.stamp_request(self.get_id().await?.ok_or(FluidError::ClientNotRegistered)?, &new_tok, &new_sig).await?;
        match response {
            Response::Return { token, life } => {
                self.set_current_token(Some(AliveToken::from_raw(token, life))).await?;
                Ok(self.get_current_token().await?.as_ref().unwrap().token())
            },
            Response::Invalid => {
                return Err(FluidError::ServerRejectedToken)?;
            },
            Response::CycleRequired => {
                let (public, private) = KC::generate();

                let sig_new = private.sign(public.as_bytes())?;
                let sig_old = self.private_key().await?.as_ref().ok_or(FluidError::ClientNoPrivateKey)?.sign(public.as_bytes())?;


                let cycle = self.cycle_request(self.get_id().await?.ok_or(FluidError::ClientNotRegistered)?, &public, &sig_new, &sig_old).await?;
                if cycle {
                    // Success! Let's store it and rerun.
                    self.set_private_key(Some(private)).await?;

                    // Try again
                    let (new_tok, new_sig) = self.sign(self.generate(token_type.clone(), token_protocol.clone()).await?).await?;
                    if let Response::Return { token, life } = self.stamp_request(self.get_id().await?.ok_or(FluidError::ClientNotRegistered)?, &new_tok, &new_sig).await? {
                        self.set_current_token(Some(AliveToken::from_raw(token, life))).await?;
                        Ok(self.get_current_token().await?.as_ref().unwrap().token())
                    } else {
                        Err(FluidError::ServerRejectedCycle)?
                    }
                } else {
                    return Err(FluidError::ServerRejectedCycle)?;
                }

            }
        }
    

    }
    async fn is_registered(&self) -> Result<bool, Self::Err> {
        Ok(self.get_id().await?.is_some() && self.private_key().await?.is_some())
    }
    async fn is_current_valid(&self) -> Result<bool, Self::Err> {
        if let Some(token) = self.get_current_token().await? {
            Ok(token.is_alive(self.ctx().await))
        } else {
            Ok(false)
        }
    }
    async fn register(&mut self) -> Result<(), Self::Err> {
        let (public, private) = KC::generate();
        let id = Uuid::new_v4();

        self.register_request(id, &public).await?;

        self.set_private_key(Some(private)).await?;
        self.set_id(Some(id)).await?;
        Ok(())


    }
    async fn execute(&mut self, token_type: T, token_protocol: P) -> Result<&GenericToken<D>, Self::Err>
    where 
        T: FixedByteRepr<1>,
        P: FixedByteRepr<1>
    {
        if !self.is_registered().await? {
            // We are not registered.
            self.register().await?;
        }
        if self.is_current_valid().await? {
            return Ok(self.get_current_token().await?.as_ref().unwrap().token());
        }
        
        self.refresh_token(token_type, token_protocol).await
    }
    async fn get_token(&mut self, token_type: T, token_protocol: P) -> Result<&GenericToken<D>, Self::Err> {
        self.execute(token_type, token_protocol).await
    }
}




pub enum Response<D> {
    Return {
        token: GenericToken<D>,
        life: D
    },
    CycleRequired,
    Invalid
}

