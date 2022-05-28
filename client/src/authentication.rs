use serde::{Serialize, Deserialize};
use crate::connection::Connection;
use std::error::Error;

use strum::IntoEnumIterator;
use strum_macros::{EnumString, EnumIter};
use read_input::prelude::*;
use crate::yubi::Yubi;
use shared_stuff::{validations, communication_types::*, crypto::get_mac};
use crate::crypto::{hash_pwd, hash_pwd_with_salt};

/// `Authenticate` enum is used to perform:
/// -   User
/// -   Registration
/// -   Password Reset
#[derive(Serialize, Deserialize, Debug, EnumString, EnumIter)]
pub enum Authenticate {
    #[strum(serialize = "Authenticate", serialize = "1")]
    Authenticate,
    #[strum(serialize = "Register", serialize = "2")]
    Register,
    #[strum(serialize = "Reset password", serialize = "3")]
    Reset,
    #[strum(serialize = "Exit", serialize = "4")]
    Exit
}

impl Authenticate {
    pub fn display() {
        let mut actions = Authenticate::iter();
        for i in 1..=actions.len() { println!("{}.\t{:?}", i, actions.next().unwrap()); }
    }

    pub fn perform(&self, connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        connection.send(self)?;

        match self {
            Authenticate::Authenticate => Authenticate::authenticate(connection),
            Authenticate::Register => Authenticate::register(connection),
            Authenticate::Reset => Authenticate::reset_password(connection),
            Authenticate::Exit => {
                println!("Exiting..."); std::process::exit(0);
            }
        }
    }

    fn register(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        loop {
            println!("<< Please register yourself >>");
            let email = input::<String>().repeat_msg("- Email: ")
            .add_err_test(|input| validations::is_valid_email(input), "Invalid Email")
            .get();
            let password = input::<String>().repeat_msg("- Password: ")
                .add_err_test(|input| validations::is_valid_password(input), "Invalid password")
                .get();
            
            let (pwd_hash, salt, _) = hash_pwd(password).into_parts();
            
            let yubikey = match Yubi::get_public_key() {
                Ok(key) => key,
                Err(e) => return Err(Box::new(e))
            };

            println!("- Yubikey: [OK]");
            connection.send(&RegisterForm {
                email, 
                salt, 
                pwd_hash, 
                yubikey
            })?;
            match connection.receive()? {
                Response::Ok => break,
                Response::Error => println!("Invalid input please try again!")
            };
        }
        println!("Successfully registered!");
        
        Ok(())
    }

    fn authenticate(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        println!("<< Please authenticate yourself >>");
        let email = input::<String>().repeat_msg("- Email: ")
            .add_err_test(|input| validations::is_valid_email(input), "Invalid Email")
            .get();
        let password = input::<String>().repeat_msg("- Password: ")
            .get();

        connection.send(&email)?;

        let challenge: Challenge = connection.receive()?;
        let (pwd_hash, _, _) = hash_pwd_with_salt(password, challenge.salt).into_parts();
        
        let mac = get_mac(&pwd_hash, &challenge.chal);
        connection.send(&mac)?;

        match connection.receive()? {
            Response::Ok => {
                match connection.receive()? {
                    false => Ok(()),
                    true => {
                        println!("< 2FA >");
                        let signed_chal = Yubi::sign_message(&challenge.chal)?.to_vec();
                        connection.send(&signed_chal)?;
                        match connection.receive()? {
                            Response::Ok => Ok(()),
                            Response::Error => Err("Wrong yubikey".into())
                        }
                    }
                }
            },
            Response::Error => Err("Wrong credentials!".into()),
        }
    }

    fn reset_password(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        println!("<< Password Reset >>");
        let email = input::<String>().repeat_msg("- Email: ")
            .add_err_test(|input| validations::is_valid_email(input), "Invalid Email")
            .get();
        connection.send(&email)?;
        println!("An email as been sent to your email, if an account exists.");
        let token = input::<String>().repeat_msg("- Email token: ").get();
        connection.send(&token)?;
        match connection.receive()? {
            Response::Ok => {
                if connection.receive()? {
                    let signed_chal = Yubi::sign_message(&token.as_bytes().to_vec())?.to_vec();
                    connection.send(&signed_chal)?;

                    match connection.receive()? {
                        Response::Error => return Err("Wrong yubikey".into()),
                        Response::Ok => {}
                    };
                }
                let new_password = input::<String>().repeat_msg("- New password: ")
                    .add_err_test(|input| validations::is_valid_password(input), "Invalid password")
                    .get();
                let (pwd_hash, salt, _) = hash_pwd(new_password).into_parts();
                
                connection.send(&ResetForm {
                    salt,
                    pwd_hash
                })?;

                match connection.receive()? {
                    Response::Ok => Ok(()),
                    Response::Error => Err("Server error, please try again later.".into())
                }
                
            },
            Response::Error => Err("Wrong token!".into())
        }
    }
}