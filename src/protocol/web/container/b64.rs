use std::marker::PhantomData;

use base64::{prelude::BASE64_URL_SAFE, DecodeError, Engine};
use serde::{de::Visitor, Deserialize, Serialize};


pub struct B64Owned<S>(pub S);

impl<S> B64Owned<S> {
    pub fn inner(self) -> S {
        self.0
    }
}

pub struct B64Ref<'a, S>(pub &'a S);

impl<T> Serialize for B64Owned<T>
where
    T: AsRef<[u8]>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        BASE64_URL_SAFE
            .encode(self.0.as_ref())
            .serialize(serializer)
    }
}

struct B64Visitor<O> {
    _type: PhantomData<O>,
}

impl<'de, O> Visitor<'de> for B64Visitor<O>
where
    O: From<Vec<u8>>,
{
    type Value = B64Owned<O>;

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


fn visit_str_inner<O>(candidate: &str) -> Result<B64Owned<O>, DecodeError>
where 
    O: From<Vec<u8>>
{
    let decoded = BASE64_URL_SAFE.decode(candidate)?;
    Ok(B64Owned(O::from(decoded)))
}


impl<'de, T> Deserialize<'de> for B64Owned<T>
where
    T: From<Vec<u8>>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_string(B64Visitor { _type: PhantomData::<T> })
    }
}

impl<'a, T> Serialize for B64Ref<'a, T>
where
    T: AsRef<[u8]>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        BASE64_URL_SAFE
            .encode(&self.0)
            .serialize(serializer)
    }
}