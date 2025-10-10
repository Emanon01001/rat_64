use anyhow::Result;
use rsa::{
    pkcs8::{der::zeroize::Zeroizing, EncodePrivateKey, EncodePublicKey, LineEnding},
    RsaPrivateKey, RsaPublicKey,
};

fn main() -> Result<()> {
    // OSのCSPRNG（内部でgetrandom相当）。自前RNGの代わりにこれでOK。
    let mut rng = rsa::rand_core::OsRng;

    // 2048bitでも可。将来性を少し見るなら3072bitも選択肢。
    let privkey = RsaPrivateKey::new(&mut rng, 3072)?;
    let pubkey = RsaPublicKey::from(&privkey);

    // 秘密鍵PEMはゼロ化可能なバッファで保持
    let pem_priv = Zeroizing::new(privkey.to_pkcs8_pem(LineEnding::LF)?.to_string());
    let pem_pub = pubkey.to_public_key_pem(LineEnding::LF)?;

    // パーミッションを締めて書き出し（Unix 600）
    std::fs::write("private_key.pem", pem_priv.as_bytes())?;
    std::fs::write("public_key.pem", pem_pub.as_bytes())?;

    Ok(())
}
