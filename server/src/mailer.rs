use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use dotenv::dotenv;
use std::env;

fn init() -> SmtpTransport {
    dotenv().ok().expect("unable to load .env file");
    let username = env::var("MAIL_USERNAME").expect("unsetted MAIL_USERNAME");
    let password = env::var("MAIL_PASSWORD").expect("unsetted MAIL_PASSWORD");
    let host = env::var("MAIL_HOST").expect("unsetted MAIL_HOST");
    let port = env::var("MAIL_PORT").expect("unsetted MAIL_PORT");
    
    let creds = Credentials::new(username, password);

    SmtpTransport::starttls_relay(&host)
        .unwrap()
        .credentials(creds)
        .port(port.parse().unwrap())
        .build()
}

pub fn send_mail(to: &String, subject: String, message: String) -> Result<(), Box<dyn std::error::Error>> {
    let mailer = init();
    let sender_address = env::var("MAIL_SEND_ADRESS").expect("unsetted MAIL_SEND_ADRESS");
    
    let email = Message::builder()
        .from(sender_address.parse().unwrap())
        .to(to.parse().unwrap())
        .subject(subject)
        .body(message)
        .unwrap();

    match mailer.send(&email) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into())
    }
}