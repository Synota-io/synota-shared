pub use aes_gcm::{
    self,
    aead::{generic_array::GenericArray, Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use rand::RngCore;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sharks::{self, Share, Sharks};

use base64::{self};

use anyhow::Result as Anysult;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub fn create_nonce() -> [u8; 12] {
    let mut data: [u8; 12] = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut data);

    data
}

pub fn get_shamir_shards_from_data(data: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let sharks = Sharks(2);
    let dealer = sharks.dealer(data.as_slice());

    let shards: Vec<Share> = dealer.take(2).collect();

    let first_shard: Vec<u8> = (&shards[0]).into();
    let second_shard: Vec<u8> = (&shards[1]).into();

    println!("1: {:?}", first_shard);
    println!("2: {:?}", second_shard);

    (first_shard, second_shard)
}

pub fn get_intermediate_key_from_shamir_shards_of_intermediate_key(
    first_shard: Vec<u8>,
    second_shard: Vec<u8>,
) -> [u8; 32] {
    let shares = vec![
        Share::try_from(first_shard.as_slice()).unwrap(),
        Share::try_from(second_shard.as_slice()).unwrap(),
    ];

    let sharks = Sharks(2);

    sharks
        .recover(shares.as_slice())
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap()
}

pub fn hash_256(data: Vec<u8>) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(data);

    hasher.finalize().to_vec().as_slice().try_into().unwrap()
}

// from https://github.com/DaGenix/rust-crypto/blob/master/examples/symmetriccipher.rs
pub fn aes_encrypt(
    data: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = GenericArray::from_slice(key);
    let nonce = GenericArray::from_slice(nonce);
    let payload = Payload {
        msg: data,
        aad: &hash_256(hash_256(nonce.to_vec()).to_vec()),
    };

    let cipher = Aes256Gcm::new(key);
    cipher.encrypt(nonce, payload)
}

pub fn aes_decrypt(
    encrypted_data: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = GenericArray::from_slice(key);
    let nonce = GenericArray::from_slice(nonce);
    let ciphertext = Vec::from(encrypted_data);

    let payload = Payload {
        msg: &ciphertext,
        aad: &hash_256(hash_256(nonce.to_vec()).to_vec()),
    };

    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(nonce, payload)
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn sharding() {
        let secret: [u8; 32] = hash_256("08b603abcdef".as_bytes().to_vec());

        let (first_shard, second_shard) = get_shamir_shards_from_data(&secret);

        assert_eq!(
            get_intermediate_key_from_shamir_shards_of_intermediate_key(first_shard, second_shard),
            secret.as_slice()
        );
    }

    #[test]
    fn aes_encrypts_and_decrypts() {
        let msg = "this must getttt encrypted";

        // NOTE: THIS MUST BE EXACTLY 16 BYTES
        //
        let nonce_saved_with_msg_in_db: &[u8; 12] = &create_nonce();

        // NOTE: THIS MUST BE EXACTLY 32 BYTES
        // hence, I sha256 it to 32 bytes
        //
        let aes_key: &[u8; 32] = b"s9ivahroiwajfe90wajfeodswjafiods";

        let encrypted_msg =
            aes_encrypt(msg.as_bytes(), aes_key, nonce_saved_with_msg_in_db).unwrap();

        // This will fail for now, bc aes en/decryption is not occuring
        assert_ne!(encrypted_msg, msg.as_bytes());

        let original_msg = aes_decrypt(
            encrypted_msg.as_slice(),
            aes_key,
            nonce_saved_with_msg_in_db,
        )
        .unwrap();

        assert_eq!(original_msg, msg.as_bytes());
        assert_eq!(std::str::from_utf8(&original_msg).unwrap(), msg)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SynotaLoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SynotaLoginResponse {
    pub email: String,
    pub jwt: String,
    pub error: bool,
    pub error_msg: String,
}

pub fn base64encode(data: &[u8]) -> String {
    base64::encode_config(data, base64::STANDARD)
}

pub fn base64decode(base64_string: String) -> Anysult<Vec<u8>> {
    Ok(base64::decode_config::<String>(
        base64_string,
        base64::STANDARD,
    )?)
}
