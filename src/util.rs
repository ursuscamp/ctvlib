use bitcoin::XOnlyPublicKey;
use sha2::Digest;

/// Given arbitrary data, hash it until it return a valid secp256k1 public key.
/// Useful for calculating a NUMS point.
pub fn hash2curve(data: &[u8]) -> XOnlyPublicKey {
    let mut hashed = sha2::Sha256::digest(data);
    let mut pk = XOnlyPublicKey::from_slice(hashed.as_slice()).ok();

    while pk.is_none() {
        hashed = sha2::Sha256::digest(hashed.as_slice());
        pk = XOnlyPublicKey::from_slice(hashed.as_slice()).ok();
    }
    pk.unwrap()
}
