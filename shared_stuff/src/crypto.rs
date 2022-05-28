use sha2::Sha256;
use hmac::{Hmac, Mac};
// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

pub fn get_mac(key: &Vec<u8>, message: &Vec<u8>) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message);
    let result = mac.finalize();
    result.into_bytes().to_vec()
}