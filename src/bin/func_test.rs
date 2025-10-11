use aes_gcm::{aead::Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rmp_serde::to_vec;
use rsa::{pkcs8::der::zeroize::Zeroizing, rand_core::RngCore};

fn generate_key_pair() -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 12]>) {
    let mut rng = rsa::rand_core::OsRng;

    let mut key = Zeroizing::new([0u8; 32]);
    let mut nonce = Zeroizing::new([0u8; 12]);

    rng.fill_bytes(&mut *key);
    rng.fill_bytes(&mut *nonce);

    (key, nonce)
}

fn encrypt(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, Result<(), aes_gcm::Error>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), data)
        .map_err(|e| Err(e))
}

fn main() {
    let data: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    let (key, nonce) = generate_key_pair();
    println!("{:?}\n\n{:?}", key, nonce);
    let serialized = to_vec(data).expect("Error");

    let d1 = encrypt(&serialized, &key, &nonce).expect("Error");
    println!("{:?}", d1)
}