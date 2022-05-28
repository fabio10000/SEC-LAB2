use dryoc::pwhash::*;

pub fn hash_pwd(password: String) -> VecPwHash {
    PwHash::hash_interactive(&password.as_bytes()).expect("unable to hash password")
}

pub fn hash_pwd_with_salt(password: String, salt: Vec<u8>) -> VecPwHash {
    PwHash::hash_with_salt(&password.as_bytes(), salt, Config::interactive()).expect("unable to hash password")
}