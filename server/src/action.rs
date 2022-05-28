use serde::{Serialize, Deserialize};
use crate::connection::Connection;
use std::error::Error;
use crate::database::Database;

use crate::authentication::User;

/// `Action` enum is used to perform logged operations:
/// -   Enable/Disable 2fa authentication
#[derive(Serialize, Deserialize, Debug)]
pub enum Action {
    Switch2FA,
    Logout
}

impl Action {
    pub fn perform(user: &mut User, connection: &mut Connection) -> Result<bool, Box<dyn Error>> {
        match connection.receive()? {
            Action::Switch2FA => Action::switch_2fa(user, connection),
            Action::Logout => Ok(false)
        }
    }

    fn switch_2fa(user: &mut User, connection: &mut Connection) -> Result<bool, Box<dyn Error>> {
        user.is_2fa = !user.is_2fa;
        Database::insert(&user);
        connection.send(&user.is_2fa)?;
        Ok(true)
    }
}