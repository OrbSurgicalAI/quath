use fips203::ml_kem_1024;
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87, traits::{KeyGen, SerDes, Signer, Verifier}};
use fips205::{slh_dsa_sha2_128f, slh_dsa_sha2_128s};
use rand::seq;






macro_rules! new_pk_cont_ncc_group {
    (
        $name:ident, $len:expr,
        $target_type:ty
    ) => {
        /// The key container type. This allows us
        /// to more efficiently interact with the underlying bytes
        /// of the public key.
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

        impl crate::core::crypto::PublicKey for $pk_name {
            type Signature =  [u8; { $mod_name::SIG_LEN }];
        
        
        
            fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
                $mod_name::PublicKey::try_from_bytes(self.0).unwrap().verify(message, signature, &[])
            }
            fn view(&self) -> &[u8] {
                &self.0
            }
        }


        impl crate::core::crypto::Signature for [u8; { $mod_name::SIG_LEN }] {
            fn view(&self) -> &[u8] {
                self
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





