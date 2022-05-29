use std::io;
use std::io::Read;
use yubikey::*;
use x509::SubjectPublicKeyInfo;
use read_input::prelude::*;
use ring::digest;

pub struct Yubi;

impl Yubi {
    fn auto_yk() -> Result<YubiKey> {
        loop {
            for reader in Context::open()?.iter()? {
                if let Ok(yk) = reader.open() {
                    return Ok(yk);
                }
            }

            println!("No Yubikey detected: Please enter one and press [Enter] to continue...");
            let _ = io::stdin().read(&mut [0u8]).unwrap();
        }
    }

    pub fn get_public_key() -> Result<Vec<u8>> {
        let mut yubikey = Yubi::auto_yk().unwrap();
        yubikey.authenticate(MgmKey::default()).unwrap();
        Ok(piv::generate(&mut yubikey, piv::SlotId::Authentication, piv::AlgorithmId::EccP256, PinPolicy::Always, TouchPolicy::Never)?.public_key())
    }

    pub fn sign_message(msg: &Vec<u8>) -> Result<Buffer> {
        let mut yubikey = Yubi::auto_yk().unwrap();
        loop {
            let pin = input::<String>().repeat_msg("- PIN: ").get();
            if yubikey.verify_pin(pin.as_bytes()).is_ok() {
                println!("- PIN: [OK]");
                break;
            }
            println!("Wrong PIN {} retries remaining!", yubikey.get_pin_retries().unwrap());
        }
        
        Ok(piv::sign_data(&mut yubikey, &digest::digest(&digest::SHA256, &msg).as_ref(), piv::AlgorithmId::EccP256, piv::SlotId::Authentication)?)
    }
}