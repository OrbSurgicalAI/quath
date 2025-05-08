use fips205::traits::{KeyGen, SerDes, Signer, Verifier};

use fips205::*;

use crate::algos::parse_into_fixed_length;





// impl crate::core::crypto::PrivateKey for fips205::slh_dsa_shake_256f::PrivateKey {
//     type Signature = [u8; 49856];
//     type Error = &'static str;
//     fn sign_bytes(&self, sequence: &[u8]) -> Result<Self::Signature, Self::Error> {
//         self.try_sign(sequence, &[], false)
//     }
// }

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
                <$target_type>::try_from_bytes(&self.0).expect("Guaranteed decoding failed.")
            }
        }
    };
}



macro_rules! new_fips205_individual_impl {
    ( $primary:ident, $pk_name:ident, $mod_name:ident ) => {

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


        new_pk_cont_ncc_group!($pk_name, { fips205::$mod_name::PK_LEN }, fips205::$mod_name::PublicKey);


        impl crate::core::crypto::DsaSystem for $primary {
            type Public = $pk_name;
            type Private = fips205::$mod_name::PrivateKey;
            type Signature = [u8; { fips205::$mod_name::SIG_LEN }];
            type GenError = &'static str;

            fn generate() -> Result<(Self::Public, Self::Private), &'static str> {
                let (pubk, privk) = $mod_name::try_keygen()?;
                Ok((<$pk_name>::from(pubk), privk))
            }
        }

        impl crate::core::crypto::PrivateKey for fips205::$mod_name::PrivateKey {
            type Signature = [u8; { fips205::$mod_name::SIG_LEN }];
            type Error = &'static str;
            fn sign_bytes(&self, sequence: &[u8]) -> Result<Self::Signature, Self::Error> {
                self.try_sign(sequence, &[], false)
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
                let key = $mod_name::PublicKey::try_from_bytes(&array)?;
                Ok($pk_name(key.into_bytes()))
            }
        }

        impl crate::core::crypto::PublicKey for $pk_name {
            type Signature =  [u8; { fips205::$mod_name::SIG_LEN }];
        
        
        
            fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
                $mod_name::PublicKey::try_from_bytes(&self.0).unwrap().verify(message, signature, &[])
            }
        }

        // paste::paste! {
        //     #[cfg(test)]
        //     #[allow(non_snake_case)]
        //     mod [<tests_$primary>] {
        //         #[test]
        //         #[allow(non_snake_case)]
        //         pub fn [<test_ $primary>]() {
        //             crate::testutil::test_signing_harness::<crate::algos::fips205::$primary>(&[1,2,3]);
        //         }

                
        //     }

            
            
        // }

    }
}


macro_rules! new_fips205_spec {
    (
        $algo:ident, $f_mod_name:ident, $s_mod_name:ident
    ) => {

        
   
        paste::paste! {
            new_fips205_individual_impl!([<Slh $algo f>], [<Slh $algo f Public>], $f_mod_name);
            new_fips205_individual_impl!([<Slh $algo s>], [<Slh $algo s Public>], $s_mod_name);
        }

        

        
        
    }
}



new_fips205_spec! {
    Sha2_128,
    slh_dsa_sha2_128f,
    slh_dsa_sha2_128s
}

new_fips205_spec! {
    Sha2_192,
    slh_dsa_sha2_192f,
    slh_dsa_sha2_192s
}

new_fips205_spec! {
    Sha2_256,
    slh_dsa_sha2_256f,
    slh_dsa_sha2_256s
}

new_fips205_spec! {
    Shake128,
    slh_dsa_shake_128f,
    slh_dsa_shake_128s
}

new_fips205_spec! {
    Shake192,
    slh_dsa_shake_192f,
    slh_dsa_shake_192s
}

new_fips205_spec! {
    Shake256,
    slh_dsa_shake_256f,
    slh_dsa_shake_256s
}



// #[cfg(test)]
// mod tests {
//     use crate::core::crypto::SigningAlgorithm;


//     #[test]
//     pub fn test_slh_dsa_sha2_256f() {
//         use fips205::slh_dsa_sha2_256f::KG;
//         let (pub_k, priv_k) = KG::generate().unwrap();
//         let signature = KG::sign(b"hello", &priv_k).unwrap();
//         assert!(KG::verify(b"hello", &signature, &pub_k));
//     }

//     #[test]
//     pub fn test_slh_dsa_sha2_128f() {
//         use fips205::slh_dsa_sha2_128f::KG;
//         let (pub_k, priv_k) = KG::generate().unwrap();
//         let signature = KG::sign(b"hello", &priv_k).unwrap();
//         assert!(KG::verify(b"hello", &signature, &pub_k));
//     }

// }