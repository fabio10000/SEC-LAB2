use serde::{Serialize, Deserialize};
use crate::connection::Connection;
use crate::database::Database;
use std::error::Error;
use crate::crypto::{random_bytes, verify_signature};
use shared_stuff::{validations, communication_types::*, crypto::get_mac};
use hex;
use crate::mailer::send_mail;

/// `Authenticate` enum is used to perform:
/// -   Authentication
/// -   Registration
/// -   Password Reset
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum Authenticate {
    Authenticate,
    Register,
    Reset,
    Exit
}

impl Authenticate {
    pub fn perform(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        match connection.receive()? {
            Authenticate::Authenticate => Authenticate::authenticate(connection),
            Authenticate::Register => Authenticate::register(connection),
            Authenticate::Reset => Authenticate::reset_password(connection),
            Authenticate::Exit => Err("Client disconnected")?
        }
    }

    fn register(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        loop {
            let mut is_error = false;

            let data:RegisterForm = connection.receive()?;

            if !validations::is_valid_email(&data.email) {
                is_error = true;
            }

            if Database::get(&data.email)?.is_some() {
                is_error = true;
            }

            if !is_error {
                let user = User {
                    email: data.email,
                    salt: data.salt,
                    pwd_hash: data.pwd_hash,
                    yubikey: data.yubikey,
                    is_2fa: true,
                };
                
                Database::insert(&user)?;
                connection.send(&Response::Ok)?;
                return Ok(Some(user));
            }
            connection.send(&Response::Error)?;
        }
        
        
    }

    fn reset_password(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        let email: String = connection.receive()?;
        let user = Database::get(&email)?;
        if user.is_none() {
            // act like the user exists to avoid leaking info about existing users
            let _ = connection.receive()?;
            connection.send(&Response::Error)?;
            return Ok(None)
        }
        let mut user = user.unwrap();

        let mut s_token: [u8; 4] = [0; 4];
        random_bytes(&mut s_token)?;

        let s_token = hex::encode_upper(&s_token);
        send_mail(
            &format!("{} <{}>", user.email, user.email), 
            format!("Reset your password!"), 
            format!("Your reset token is: {}", s_token)
        )?;

        let c_token: String = connection.receive()?;
        if s_token.eq(&c_token) {
            connection.send(&Response::Ok)?;
            if user.is_2fa {
                connection.send(&true)?;
                let signed_token: Vec<u8> = connection.receive()?;
                if verify_signature(&user.yubikey, &c_token.as_bytes().to_vec(), &signed_token).is_err() {
                    connection.send(&Response::Error)?;
                    return Ok(None)
                }

                connection.send(&Response::Ok)?;
            } else {
                connection.send(&false)?;
            }

            let new_password: ResetForm = connection.receive()?;
            user.salt = new_password.salt;
            user.pwd_hash = new_password.pwd_hash;
            match Database::insert(&user){
                Ok(_) => connection.send(&Response::Ok)?,
                Err(_) => connection.send(&Response::Error)?
            };
            return Ok(Some(user))
        }

        connection.send(&Response::Error)?;
        Ok(None)
    }

    fn authenticate(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        let email: String = connection.receive()?;

        // compute salt before checking if user exists to avoid timing attacks
        let mut rand_salt: [u8; 16] = [0; 16];
        random_bytes(&mut rand_salt)?;

        let user = match Database::get(&email)? {
            Some(u) => u,
            // if user does not exist send random salt to avoid leaking info about existing users
            None => User { 
                email,
                salt: rand_salt.to_vec(),
                pwd_hash: vec![],
                yubikey: vec![],
                is_2fa: false
            }
        };

        let mut challenge: [u8; 16] = [0; 16];
        random_bytes(&mut challenge)?;
        let challenge = challenge.to_vec();
        connection.send(&Challenge {
            salt: user.salt.clone(),
            chal: challenge.clone()
        })?;

        let s_mac = get_mac(&user.pwd_hash, &challenge);
        let c_mac: Vec<u8> = connection.receive()?;

        if !s_mac.eq(&c_mac) {
            connection.send(&Response::Error)?;
            return Ok(None)
        }
        connection.send(&Response::Ok)?;
        if !user.is_2fa {
            connection.send(&false)?;
            return Ok(Some(user))
        }

        connection.send(&true)?;
        let signed_2fa: Vec<u8> = connection.receive()?;
        if verify_signature(&user.yubikey, &challenge, &signed_2fa).is_err() {
            connection.send(&Response::Error)?;
            return Ok(None)
        }

        connection.send(&Response::Ok)?;
        Ok(Some(user))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub email: String,
    pub salt: Vec<u8>,
    pub pwd_hash: Vec<u8>,
    pub yubikey: Vec<u8>,
    pub is_2fa: bool
}