


pub trait Signature {
    fn get_sig_bytes(&self) -> &[u8];
}

pub trait KeyChain {
    type Private: PrivateKey<Self::Signature, Self::Error>;
    type Public: PublicKey<Self::Signature>;
    type Signature: Signature;
    type Error;

    fn generate() -> (Self::Public, Self::Private);
}






pub trait PrivateKey<S, E> {
    fn sign(&self, bytes: &[u8]) -> Result<S, E>;
}

pub trait PublicKey<S> {
    fn verify(&self, bytes: &[u8], signature: &S) -> bool;
    fn as_bytes(&self) -> &[u8];
}
