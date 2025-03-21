use std::marker::PhantomData;
use chrono::DateTime;
use serde::{de::Visitor, Deserialize, Serialize};


use super::error::ContainerError;


pub struct Rfc3339Container<D>(pub D);

impl<D> Rfc3339Container<D> {
    pub fn inner(self) -> D {
        self.0
    }
}

pub trait Rfc3339: Sized {
    type Error: core::error::Error;
    fn to_rfc3339(&self) -> Rfc3339Str;
    fn parse_from_rfc3339(candidate: &str) -> Result<Self, Self::Error>;
}

pub struct Rfc3339Str(String);



impl Rfc3339Str {
    /// The regex used here to parse the string is from the following gihub:
    /// https://gist.github.com/marcelotmelo/b67f58a08bee6c2468f8
    pub fn from_str(string: &str) -> Result<Self, ContainerError> {
        match DateTime::parse_from_rfc3339(string) {
            Ok(..) => Ok(Self(string.to_string())),
            Err(..) => Err(ContainerError::Rfc3339ParseFailure)
        }

    }
}


impl<D> Serialize for Rfc3339Container<D>
where 
    D: Rfc3339
{

    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        self.0.to_rfc3339().0.serialize(serializer)
    }

}

struct RFC3339Visitor<O> {
    _type: PhantomData<O>,
}

impl<'de, O> Visitor<'de> for RFC3339Visitor<O>
where
    O: Rfc3339,
{
    type Value = Rfc3339Container<O>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a url-safe b64 encoded value")
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        visit_str_inner(&v).map_err(|e| E::custom(e))
    }
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        visit_str_inner(v).map_err(|e| E::custom(e))
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        visit_str_inner(v).map_err(|e| E::custom(e))
    }
}


fn visit_str_inner<'a, O>(candidate: &'a str) -> Result<Rfc3339Container<O>, <O as Rfc3339>::Error>
where 
    O: Rfc3339
{
    let decoded = O::parse_from_rfc3339(candidate)?;
    Ok(Rfc3339Container(decoded))
}



impl<'de, O> Deserialize<'de> for Rfc3339Container<O>
where 
    O: Rfc3339
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de> {
        deserializer.deserialize_string(RFC3339Visitor { _type: PhantomData::<O> })
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::web::container::rfc3339::Rfc3339Str;


    #[test]
    pub fn try_parse_rfc3339() {
        let invalid = "hello world";
        assert!(Rfc3339Str::from_str(invalid).is_err());

       

        assert!(Rfc3339Str::from_str("2016-02-28 16:41:41.090Z").is_ok());
    }
}