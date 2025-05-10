use std::{borrow::Cow, marker::PhantomData, ops::Range};

use bitvec::{array::BitArray, order::Lsb0};
use rand::Rng;
use uuid::Uuid;

use super::{FixedByteRepr, KemAlgorithm, MsSinceEpoch, Parse, ViewBytes};


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending;

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq)]
pub struct Final;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Token<K> {
    pub protocol: u8,
    pub sub_protocol: u8,
    pub id: Uuid,
    // The permission bitfield.
    pub permissions: BitArray<[u8; 16], Lsb0>,
    pub timestamp: MsSinceEpoch,
    pub body: [u8; 32],
    pub _state: PhantomData<K>

}

const ID_FIELD: Range<usize> = 2..18;
const PERMISSION_FIELD: Range<usize> = 18..34;
const TIMESTAMP_FIELD: Range<usize> = 34..42;
const BODY_FIELD: Range<usize> = 42..74;





impl<K> Token<K> {
    pub fn permissions(&self) -> &BitArray<[u8; 16], Lsb0> {
        &self.permissions
    }
    pub fn to_fixed_bytes(&self) -> [u8; 74] {
        let mut buffer = [0u8; 74];
        buffer[0] = self.protocol;
        buffer[1] = self.sub_protocol;
        buffer[ID_FIELD].copy_from_slice(&self.id.to_bytes_le());
        buffer[PERMISSION_FIELD].copy_from_slice(&self.permissions.data);
        buffer[TIMESTAMP_FIELD].copy_from_slice(&self.timestamp.0.to_le_bytes());
        buffer[BODY_FIELD].copy_from_slice(&self.body);
        buffer
    }

}

impl<K> ViewBytes for Token<K> {
    fn view(&self) -> std::borrow::Cow<'_, [u8]> {
        Cow::Owned(self.to_fixed_bytes().to_vec())
    }
}

impl<'a, K> Parse<'a> for Token<K> {
    type Error = &'static str;
    fn parse_bytes(value: &'a [u8]) -> Result<Self, Self::Error> {
        let protocol = value[0];
        let sub_protocol = value[1];
        let id = Uuid::from_bytes_le(value[ID_FIELD].try_into().unwrap());

        let perms: [u8; 16] = value[PERMISSION_FIELD].try_into().unwrap();

        let permissions = BitArray::from(perms);
        let timestamp = MsSinceEpoch(i64::from_le_bytes(value[TIMESTAMP_FIELD].try_into().unwrap()));
        let body = value[BODY_FIELD].try_into().unwrap();

        Ok(Self {
            protocol,
            sub_protocol,
            id,
            permissions,
            timestamp,
            body,
            _state: PhantomData
        })
    }

}


impl Token<Pending> {

    pub fn new(protocol: u8, sub_protocol: u8, id: Uuid, time: MsSinceEpoch) -> Self {
        Self {
            protocol,
            sub_protocol,
            permissions: BitArray::new([0u8; 16]),
            body: rand::rng().random(),
            id,
            timestamp: time,
            _state: PhantomData
        }

    }
    pub fn permissions_mut(&mut self) -> &mut BitArray<[u8; 16], Lsb0> {
        &mut self.permissions
    }

    #[cfg(test)]
    pub fn finalize(self) -> Token<Final> {
        Token {
            id: self.id,
            protocol: self.protocol,
            sub_protocol: self.sub_protocol,
            body: self.body.clone(),
            permissions: self.permissions,
            _state: PhantomData,
            timestamp: self.timestamp
        }
    }

    pub fn update_with_shared_secret<K>(&self, ss: K::SharedSecret) -> Token<Final>
    where 
        K: KemAlgorithm,
        K::SharedSecret: FixedByteRepr<32>
    {

     


        Token {
            id: self.id,
            protocol: self.protocol,
            sub_protocol: self.sub_protocol,
            body: ss.to_fixed_repr(),
            permissions: self.permissions,
            _state: PhantomData,
            timestamp: self.timestamp
        }
        

        

    }
}






#[cfg(test)]
mod tests {
    use std::{marker::PhantomData, time::Duration};

    use arbitrary::Arbitrary;
    use bitvec::array::BitArray;
    use uuid::Uuid;

    use crate::core::crypto::{MsSinceEpoch, Parse, ViewBytes};

    use super::{Pending, Token};


    impl<'a> Arbitrary<'a> for Token<Pending> {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                id: Uuid::from_u128(u.arbitrary()?),
                permissions: BitArray::from(<[u8; 16]>::arbitrary(u)?),
                body: <[u8; 32]>::arbitrary(u)?,
                timestamp: MsSinceEpoch(i64::arbitrary(u)?),
                sub_protocol: u.arbitrary()?,
                protocol: u.arbitrary()?,
                _state: PhantomData
            })
        }
    }

    #[test]
    pub fn token_modify_permission_bitfield() {
        let mut token = Token::new(1, 1, Uuid::new_v4(), MsSinceEpoch(3939));

        token.permissions_mut().set(0, true);
        assert!(token.permissions().get(0).unwrap());

        let token: Token<Pending> = Token::parse_bytes(&*token.view()).unwrap();
        assert!(token.permissions().get(0).unwrap());

    }

    #[test]
    pub fn token_serde() {
        
        arbtest::arbtest(|u| {
            
            let manufactured = Token::arbitrary(u)?;

            let field = manufactured.view();
            let manufactured_again = Token::parse_bytes(&field as &[u8]).unwrap();
            assert_eq!(manufactured, manufactured_again);
        
            
            Ok(())
        }).budget(Duration::from_secs(2));
    }
}