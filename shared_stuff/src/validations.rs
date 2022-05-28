//Dummy validators in a real case should be more complex

pub fn is_valid_email(val:&String) -> bool {
    val.find("@").is_some()
}

pub fn is_valid_password(val:&String) -> bool {
    val.len() >= 8
}