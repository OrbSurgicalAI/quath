use std::{borrow::Cow, fmt::{Debug, Display}, marker::PhantomData, ops::Deref};

use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::DateTime;
use serde::{de::Visitor, Deserialize, Serialize};
use uuid::Uuid;

use crate::core::crypto::{mem::B64, opcode::OpCode, token::MsSinceEpoch, Parse, Signature, ViewBytes};


// #[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
// #[repr(transparent)]
// struct Cv<V: ToBytes>()


#[derive(PartialEq, Eq, Debug)]
#[repr(transparent)]
struct InternalB64SerContainer<'a>(Cow<'a, [u8]>);

struct B64Visitor;






impl<'de> Visitor<'de> for B64Visitor {
    type Value = InternalB64SerContainer<'de>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("expecting valid b64")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {

        let data = BASE64_STANDARD.decode(v).map_err(|e| E::custom(e))?;
        Ok(InternalB64SerContainer(Cow::Owned(data)))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
            let data = BASE64_STANDARD.decode(v).map_err(|e| E::custom(e))?;
            Ok(InternalB64SerContainer(Cow::Owned(data)))
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        let data = BASE64_STANDARD.decode(v).map_err(|e| E::custom(e))?;
        Ok(InternalB64SerContainer(Cow::Owned(data)))
    }

 
}

impl<'a> Serialize for InternalB64SerContainer<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        if serializer.is_human_readable() {
            BASE64_STANDARD.encode(&self.0).serialize(serializer)
        } else {
            serializer.collect_seq(self.0.into_iter())
        }
    }
}

impl<'de> Deserialize<'de> for InternalB64SerContainer<'de> {
    
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>
        {

        if deserializer.is_human_readable() {
            let inner = deserializer.deserialize_string(B64Visitor)?;
            Ok(inner)
                
        } else {
            Ok(InternalB64SerContainer(Cow::Owned(Vec::deserialize(deserializer)?)))
        }
    }
}

/* B64 Wrapper */


impl<T: ViewBytes> Serialize for B64<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        InternalB64SerContainer(self.0.view()).serialize(serializer)
    }
}



impl<'de, T> Deserialize<'de> for B64<T>
where 
    T: ViewBytes,
    for<'a> T: Parse<'a>,
    for<'a> <T as Parse<'a>>::Error: Display,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de> {
        let InternalB64SerContainer(inner) = InternalB64SerContainer::deserialize(deserializer)?;
        let wow = T::parse_bytes(&*inner).map_err(serde::de::Error::custom)?;

        Ok(B64(wow))

    }
}






/* OPCODE SERDE IMPLEMENTATIONS */
impl Serialize for OpCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_static_str())
        } else {
            serializer.serialize_u8(self.to_code())
        }
    }
}

struct OpCodeVisitor;


impl<'v> Visitor<'v> for OpCodeVisitor {
    type Value = OpCode;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("expecting qualified opcode")
    }
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        OpCode::try_from(v).map_err(E::custom)
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        OpCode::try_from(&*v).map_err(E::custom)
    }
    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        OpCode::try_from(v).map_err(E::custom)
    }
    fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        self.visit_u8(u8::try_from(v).map_err(|_| E::custom("opcodes must fit in 8 bits"))?)
    }
    fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        self.visit_u8(u8::try_from(v).map_err(|_| E::custom("opcodes must fit in 8 bits"))?)
    }
    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
                self.visit_u8(u8::try_from(v).map_err(|_| E::custom("opcodes must fit in 8 bits"))?)
    }
    fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
                self.visit_u8(u8::try_from(v).map_err(|_| E::custom("opcodes must fit in 8 bits"))?)
    }
    fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
                self.visit_u8(u8::try_from(v).map_err(|_| E::custom("opcodes must fit in 8 bits"))?)
    }
    fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
                self.visit_u8(u8::try_from(v).map_err(|_| E::custom("opcodes must fit in 8 bits"))?)
    }
    fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
                self.visit_u8(u8::try_from(v).map_err(|_| E::custom("opcodes must fit in 8 bits"))?)
    }
    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
                self.visit_u8(u8::try_from(v).map_err(|_| E::custom("opcodes must fit in 8 bits"))?)
    }
    fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
                self.visit_u8(u8::try_from(v).map_err(|_| E::custom("opcodes must fit in 8 bits"))?)
    }
    
}

impl<'de> Deserialize<'de> for OpCode {
    
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>
        {

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(OpCodeVisitor)
        } else {
            deserializer.deserialize_u8(OpCodeVisitor)
        }
    }
}


/* Identifier Serde */

/* Milliseconds Since Epoch */
impl Serialize for MsSinceEpoch {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        if serializer.is_human_readable() {
            DateTime::from_timestamp_millis(self.0).unwrap().serialize(serializer)
        } else {
            serializer.serialize_i64(self.0)
        }
        
    }
}

struct MsSinceEpochVisitor;

impl<'v> Visitor<'v> for MsSinceEpochVisitor {
    type Value = MsSinceEpoch;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("milliseconds since epoch")
    }
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        let value = DateTime::parse_from_rfc3339(&v).map_err(E::custom)?;
        Ok(MsSinceEpoch(value.timestamp_millis()))
    }
}

impl<'de> Deserialize<'de> for MsSinceEpoch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de> {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(MsSinceEpochVisitor)
        } else {
            Ok(MsSinceEpoch(i64::deserialize(deserializer)?))
        }
    }
}


// impl<'v, I: Identifier> Visitor<'v, I> for IdVisitor<'v, I> {
    

// }


#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use serde::{Deserialize, Serialize, Serializer};
    use serde_test::{assert_ser_tokens, assert_tokens, Configure, Token};
    use uuid::{uuid, Uuid};

    use crate::core::crypto::{mem::B64, opcode::OpCode, token::MsSinceEpoch, ServerCycleBody, Signature, ViewBytes};

    use super::InternalB64SerContainer;


    


    #[derive(serde::Serialize, Deserialize)]
    pub struct Stub {
        field: B64<[u8; 3]>
    }

    #[test]
    pub fn test_string_like() {
        // This test serves as a sanity check that the signatures can
        // actually be encoded as B64 strings.
        

        
        let result = serde_json::to_string(&Stub {
            field: B64([1, 2, 3])
        }).unwrap();

        assert_eq!(result, "{\"field\":\"AQID\"}");

        let result: Stub = serde_json::from_str(&"{\"field\":\"AQID\"}").unwrap();
        assert_eq!(*result.field, [1, 2, 3]);
    }

  
    #[test]
    pub fn test_serde_internal_b64_container() {
        assert_tokens(&InternalB64SerContainer(Cow::Borrowed(&[1, 2, 3])).compact(), &[
            Token::Seq { len: Some(3) },
            Token::U8(1),
            Token::U8(2),
            Token::U8(3),
            Token::SeqEnd
        ]);
        assert_tokens(&InternalB64SerContainer(Cow::Borrowed(&[])).compact(), &[
            Token::Seq { len: Some(0) },
            Token::SeqEnd
        ]);
        assert_tokens(&InternalB64SerContainer(Cow::Borrowed(&[1, 2, 3])).readable(), &[
            Token::Str("AQID")
        ]);
    }
    
    #[test]
    pub fn test_serde_basic() {

        let sig = B64([1, 2, 3]);

    
        assert_tokens(&B64([1, 2, 3]).compact(), &[
            Token::Seq { len: Some(3) },
            Token::U8(1),
            Token::U8(2),
            Token::U8(3),
            Token::SeqEnd
        ]);

        assert_ser_tokens(&sig.readable(), &[
            Token::Str("AQID")
        ]);
    }

    #[test]
    pub fn test_serde_empty() {

        let sig = B64([]);

    
        assert_tokens(&sig.clone().compact(), &[
            Token::Tuple { len: 0 },
            Token::TupleEnd
        ]);

        assert_ser_tokens(&sig.readable(), &[
            Token::Str("")
        ]);
    }

    #[test]
    pub fn test_serde_opcode() {
        use OpCode::*;

        let cases = [
            (Register, 0u8, "Register"),
            (RegSuccess, 1, "RegSuccess"),
            (Cycle, 2, "Cycle"),
            (CycleOk, 3, "CycleOk"),
            (Stamp, 4, "Stamp"),
            (Stamped, 5, "Stamped"),
        ];

        for (variant, code, name) in cases {
            assert_tokens(&variant.compact(), &[Token::U8(code)]);
            assert_tokens(&variant.readable(), &[Token::Str(name)]);
        }
    }

    #[test]
    pub fn test_serde_hash() {
        assert_tokens(&B64([1, 2, 3]).compact(), &[
            Token::Seq { len: Some(3) },
            Token::U8(1),
            Token::U8(2),
            Token::U8(3),
            Token::SeqEnd
        ]);
        assert_tokens(&B64([]).compact(), &[
            Token::Seq { len: Some(0) },
            Token::SeqEnd
        ]);
        assert_tokens(&B64([1, 2, 3]).readable(), &[
            Token::Str("AQID")
        ]);
    }

    #[test]
    pub fn test_serde_server_cycle_body() {

      

        assert_tokens(&ServerCycleBody {
            code: OpCode::Register,
            hash: B64([1, 2, 3])
        }.readable(), &[
            Token::Struct { name: "ServerCycleBody", len: 2},
            Token::Str("code"),
            Token::Str("Register"),
            Token::Str("hash"),
            Token::Str("AQID"),
            Token::StructEnd
        ]);

        assert_tokens(&ServerCycleBody {
            code: OpCode::Register,
            hash: B64([1, 2, 3])
        }.compact(), &[
            Token::Struct { name: "ServerCycleBody", len: 2},
            Token::Str("code"),
            Token::U8(0),
            Token::Str("hash"),
            Token::Seq { len: Some(3) },
            Token::U8(1),
            Token::U8(2),
            Token::U8(3),
            Token::SeqEnd,
            Token::StructEnd
        ]);
    }






  


    #[test]
    pub fn test_serde_ms_since_epoch() {
        assert_tokens(&MsSinceEpoch(12).readable(), &[
            Token::Str("1970-01-01T00:00:00.012Z")
        ]);
        assert_tokens(&MsSinceEpoch(12).compact(), &[
            Token::I64(12)
        ]);
    }
}