use serde::{Serialize, Deserialize};
use crate::connection::Connection;
use std::error::Error;

use strum::IntoEnumIterator;
use strum_macros::{EnumString, EnumIter};

/// `Action` enum is used to perform logged operations:
/// -   Enable/Disable 2fa authentication
#[derive(Serialize, Deserialize, Debug, EnumString, EnumIter)]
pub enum Action {
    #[strum(serialize = "Enable/Disable 2FA", serialize = "1")]
    Switch2FA,
    #[strum(serialize = "Exit", serialize = "2")]
    Logout
}

impl Action {
    pub fn display() {
        let mut actions = Action::iter();
        for i in 1..=actions.len() { println!("{}.\t{:?}", i, actions.next().unwrap()); }
    }

    pub fn perform(&self, connection: &mut Connection) -> Result<bool, Box<dyn Error>> {
        connection.send(self)?;

        match self {
            Action::Switch2FA => Action::switch_2fa(connection),
            Action::Logout => Ok(false)
        }
    }

    fn switch_2fa(connection: &mut Connection) -> Result<bool, Box<dyn Error>> {
        let is_2fa = connection.receive()?;
        if is_2fa {
            println!("2FA is now enabled");
        } else {
            println!("2FA is now disabled");
        }
        Ok(true)
    }
}