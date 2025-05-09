use fips203::traits::{SerDes, KeyGen, Encaps, Decaps};
use crate::core::crypto::*;

use super::parse_into_fixed_length;


impl FixedByteRepr<32> for fips203::SharedSecretKey {
    fn to_fixed_repr(&self) -> [u8; 32] {
        self.clone().into_bytes()
    }
}

macro_rules! gen_fips203_kem_variant {
    ($primary:ident, $module_name:ident) => {

        /// Represents the KEM algorithm for this variant of FIPS203.
        /// 
        /// Implementation is provided by the NCC group.
        pub struct $primary;

        impl ViewBytes for fips203::$module_name::EncapsKey {
            fn view(&self) -> std::borrow::Cow<'_, [u8]> {
                std::borrow::Cow::Owned(self.clone().into_bytes().to_vec())
            }
        }

        impl ViewBytes for fips203::$module_name::DecapsKey {
            fn view(&self) -> std::borrow::Cow<'_, [u8]> {
                std::borrow::Cow::Owned(self.clone().into_bytes().to_vec())
            }
        }


        impl ViewBytes for fips203::$module_name::CipherText {
            fn view(&self) -> std::borrow::Cow<'_, [u8]> {
                std::borrow::Cow::Owned(self.clone().into_bytes().to_vec())
            }
        }

        impl<'a> Parse<'a> for fips203::$module_name::EncapsKey {
            type Error = &'static str;
            fn parse_bytes(value: &'a [u8]) -> Result<Self, Self::Error> {
                Self::try_from_bytes(parse_into_fixed_length(value)?)
            }
        }
        

        impl<'a> Parse<'a> for fips203::$module_name::CipherText {
            type Error = &'static str;
            fn parse_bytes(value: &'a [u8]) -> Result<Self, Self::Error> {
                Self::try_from_bytes(parse_into_fixed_length(value)?)
            }
        }

        
        
        

        impl KEMAlgorithm for $primary {
            type EncapsulationKey = fips203::$module_name::EncapsKey;
            type DecapsulationKey = fips203::$module_name::DecapsKey;
            type CipherText = fips203::$module_name::CipherText;
            type SharedSecret = fips203::SharedSecretKey;
            type Context = ();
            type Error = &'static str;
        
            fn generate(_: &Self::Context) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error> {
                let (encap, decap) = fips203::$module_name::KG::try_keygen()?;
        
                Ok((decap, encap))
            }
        
            fn encapsulate(encap_key: &Self::EncapsulationKey, _: &Self::Context) -> Result<(Self::CipherText, Self::SharedSecret), Self::Error> {
                let (ss, ct) = encap_key.try_encaps()?;
                Ok((ct, ss))
            }
        
            fn decapsulate(decap_key: &Self::DecapsulationKey, cipher: &Self::CipherText, _: &Self::Context) -> Result<Self::SharedSecret, Self::Error> {
               let ss =  decap_key.try_decaps(cipher)?;
               
               Ok(ss)
            }
        }
    }
}

impl<'a> Parse<'a> for fips203::SharedSecretKey {
    type Error = &'static str;
    fn parse_bytes(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(parse_into_fixed_length(value)?)
    }
}

impl ViewBytes for fips203::SharedSecretKey {
    fn view(&self) -> std::borrow::Cow<'_, [u8]> {
        self.clone().into_bytes().to_vec().into()
    }
}

gen_fips203_kem_variant!(MlKem512, ml_kem_512);
gen_fips203_kem_variant!(MlKem769, ml_kem_768);
gen_fips203_kem_variant!(MlKem1024, ml_kem_1024);





#[cfg(test)]
mod tests {


    use crate::{algos::fips203::MlKem512, core::crypto::KEMAlgorithm};



    #[test]
    pub fn test_fips203_kem() {
        
        let (dk, ek) = MlKem512::generate(&()).unwrap();
        let (ct, server_ss) = MlKem512::encapsulate(&ek, &()).unwrap();
        let client_ss = MlKem512::decapsulate(&dk, &ct, &()).unwrap();
        assert_eq!(server_ss, client_ss);

    }
}