use rand::rngs::EntropyRng;
use rand::RngCore;
use std::error::Error;
use std::fmt;
use p256::{
    ecdsa::{
        VerifyingKey, 
        Signature, 
        signature::Verifier
    },
    EncodedPoint
};

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

// todo: not working
pub fn verify_signature(pk: &Vec<u8>, message: &Vec<u8>, signature: &Vec<u8>) -> Result<(), Box<dyn Error>> {
    let encoded_point = match EncodedPoint::from_bytes(pk) {
        Ok(enc) => enc,
        Err(_) => return Err(Box::new(InvalidPublicKey("Invalid publickey".into())))
    };
    println!("encode OK");
    let verifier = VerifyingKey::from_encoded_point(&encoded_point)?;
    println!("verifier OK");
    Ok(verifier.verify(message, &Signature::from_der(signature)?)?)
}