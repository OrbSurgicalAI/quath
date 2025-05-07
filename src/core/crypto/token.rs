use super::{FixedByteRepr, KEMAlgorithm, ToBytes};



#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Token {
    pub protocol: u8,
    pub sub_protocol: u8,
    pub id: u128,
    pub permissions: u16,
    pub timestamp: MsSinceEpoch,
    pub body: [u8; 32]
}

impl Token {
    pub fn update_with_shared_secret<K>(&self, ss: K::SharedSecret) -> Token
    where 
        K: KEMAlgorithm,
        K::SharedSecret: FixedByteRepr<32>
    {

        let mut tok = self.clone();
        let ss = ss.to_fixed_repr();
        tok.body.copy_from_slice(&ss);

        tok

        

    }
}

impl ToBytes for Token {
    fn to_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Debug, Eq, Ord)]
pub struct MsSinceEpoch(pub i64);