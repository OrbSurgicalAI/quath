
use fips204::{traits::{SerDes, Signer, Verifier}, ml_dsa_44::{self}, ml_dsa_65, ml_dsa_87};

use crate::algos::parse_into_fixed_length;





macro_rules! new_pk_cont_ncc_group {
    (
        $name:ident, $len:expr,
        $target_type:ty
    ) => {
        /// The key container type. This allows us
        /// to more efficiently interact with the underlying bytes
        /// of the public key.
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[repr(transparent)]
        pub struct $name(pub [u8; $len]);

        impl From<$target_type> for $name {
            fn from(value: $target_type) -> Self {
                Self(value.into_bytes())
            }
        }

        impl $name {
            /// Converts the key container into the actual key. This
            /// is usually called in the verification methods.
            pub fn as_key(&self) -> $target_type {
                <$target_type>::try_from_bytes(self.0).expect("Guaranteed decoding failed.")
            }
        }
    };
}





macro_rules! new_fips204_spec {
    (
        $primary:ident,
        $pk_name:ident,
        $mod_name:ident
        // $name:ident,
        // $len:expr,
        // $target_type:ty
    ) => {

        /// A utility struct representing the digital signature scheme.
        /// 
        /// Contains a single method `generate` which generates a keypair.
        /// ```
        /// use crate::quath::core::crypto::*;
        /// use crate::quath::algos::fips204::MlDsa44;
        /// 
        /// let (pubk, privk) = MlDsa44::generate().unwrap();
        /// ```
        pub struct $primary;


        new_pk_cont_ncc_group!($pk_name, { $mod_name::PK_LEN }, $mod_name::PublicKey);


        impl crate::core::crypto::DsaSystem for $primary {
            type Public = $pk_name;
            type Private = $mod_name::PrivateKey;
            type Signature = [u8; { $mod_name::SIG_LEN }];
            type GenError = &'static str;

            fn generate() -> Result<(Self::Public, Self::Private), &'static str> {
                let (pubk, privk) = $mod_name::try_keygen()?;
                Ok((<$pk_name>::from(pubk), privk))
            }
        }

        impl crate::core::crypto::PrivateKey for $mod_name::PrivateKey {
            type Signature = [u8; { $mod_name::SIG_LEN }];
            type Error = &'static str;
            fn sign_bytes(&self, sequence: &[u8]) -> Result<Self::Signature, Self::Error> {
                self.try_sign(sequence, &[])
            }
        }

        impl crate::core::crypto::ViewBytes for $pk_name {
            fn view(&self) -> std::borrow::Cow<'_, [u8]> {
                std::borrow::Cow::Borrowed(&self.0)
            }
        }

        impl<'a> crate::core::crypto::Parse<'a> for $pk_name {
            type Error = &'static str;
            fn parse_bytes(value: &'a [u8]) -> Result<Self, Self::Error> {
                let array = parse_into_fixed_length(value)?;
                let key = $mod_name::PublicKey::try_from_bytes(array)?;
                Ok($pk_name(key.into_bytes()))
            }
        }
        
        

        impl crate::core::crypto::PublicKey for $pk_name {
            type Signature =  [u8; { $mod_name::SIG_LEN }];
        
        
        
            fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
                $mod_name::PublicKey::try_from_bytes(self.0).unwrap().verify(message, signature, &[])
            }
        }

        paste::paste! {
            #[cfg(test)]
            #[allow(non_snake_case)]
            mod [<tests_$primary>] {
                #[test]
                #[allow(non_snake_case)]
                pub fn [<test_ $primary>]() {
                    crate::testutil::test_signing_harness::<crate::algos::fips204::$primary>(&[1,2,3]);
                }

                #[test]
                #[allow(non_snake_case)]
                pub fn [<arbtest_simple_ $primary>]() {
                    crate::testutil::run_arbtest_harness_simple::<crate::algos::fips204::$primary>();
                }
            }

            
            
        }

       

    };
}









new_fips204_spec! {
    MlDsa44,
    MlDsa44Public,
    ml_dsa_44
}

new_fips204_spec! {
    MlDsa65,
    MlDsa65Public,
    ml_dsa_65
}


new_fips204_spec! {
    MlDsa87,
    MlDsa87Public,
    ml_dsa_87
}







