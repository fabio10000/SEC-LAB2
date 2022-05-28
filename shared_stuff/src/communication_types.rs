use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisterForm {
    pub email: String,
    pub salt: Vec<u8>,
    pub pwd_hash: Vec<u8>,
    pub yubikey: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Challenge {
    pub salt: Vec<u8>,
    pub chal: Vec<u8>
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResetForm {
    pub salt: Vec<u8>,
    pub pwd_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub enum Response {
    Ok,
    Error
}