

from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1
import hashlib

def derive_keys_and_fingerprint(mnemonic: str, passphrase: str = ""):
    # 1. Generate seed bytes from mnemonic + passphrase (BIP39)
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)

    # 2. Create BIP32 master key from seed (using secp256k1 curve)
    bip32_master_key = Bip32Slip10Secp256k1.FromSeed(seed_bytes)

    # 3. Get private key bytes (32 bytes)
    priv_key_bytes = bip32_master_key.PrivateKey().Raw().ToBytes()
    priv_key_hex = priv_key_bytes.hex()

    # 4. Get compressed public key bytes
    pub_key_bytes = bip32_master_key.PublicKey().RawCompressed().ToBytes()
    pub_key_hex = pub_key_bytes.hex()

    # 5. Compute fingerprint: first 4 bytes of RIPEMD160(SHA256(pubkey))
    sha256_pubkey = hashlib.sha256(pub_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pubkey)
    fingerprint = ripemd160.digest()[:4].hex()

    return priv_key_hex, pub_key_hex, fingerprint

if __name__ == "__main__":
    # Example mnemonic (DO NOT use this mnemonic for real funds)
    # mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    mnemonic = "swamp arena lake auto agent nasty harvest train tone degree myself include"
    passphrase = ""  # Optional passphrase

    priv_key, pub_key, fingerprint = derive_keys_and_fingerprint(mnemonic, passphrase)

    print(f"Master Private Key (hex): {priv_key}")
    print(f"Master Public Key (compressed hex): {pub_key}")
    print(f"Fingerprint: {fingerprint}")



