#[cfg(feature = "fips203")]
pub mod fips203;

#[cfg(feature = "sha3")]
pub mod sha3;

#[cfg(feature = "fips204")]
pub mod fips204;

#[cfg(feature = "ecdh")]
pub mod ecdh;

#[cfg(feature = "ecdsa")]
pub mod ecdsa;

#[cfg(feature = "fips205")]
pub mod fips205;

pub(crate) fn parse_into_fixed_length<const N: usize>(arr: &[u8]) -> Result<[u8; N], &'static str> {
    arr.try_into()
        .map_err(|_| "failed to convert into properly sized array")
}
