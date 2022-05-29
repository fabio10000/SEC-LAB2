use rand::rngs::EntropyRng;
use rand::RngCore;
use std::error::Error;
use std::fmt;

use ring::signature::{UnparsedPublicKey, self};

#[derive(Debug)]
struct InvalidPublicKey(String);

impl fmt::Display for InvalidPublicKey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
      write!(f, "There is an error: {}", self.0)
  }
}

impl Error for InvalidPublicKey {}

pub fn random_bytes(result: &mut [u8]) -> Result<(), Box<dyn Error>> {
    let mut rng = EntropyRng::new();
    rng.fill_bytes(result);

    Ok(())
}

pub fn verify_signature(pk: &Vec<u8>, message: &Vec<u8>, signature: &Vec<u8>) -> Result<(), Box<dyn Error>> {
    let key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &pk);
    match key.verify(message, signature) {
        Ok(_) => Ok(()),
        Err(_) => Err("Verification Error".into())
    }
}