#!/usr/bin/env python3

# mnem2.py
"""
My mnemonic
main() is the entry point for the project.
This code is based around the *bip_utils* library
"""
import logging
import argparse
import hashlib
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, Bip39Languages, Bip39MnemonicValidator, Bip32Slip10Secp256k1

# initialise logging - INFO, WARNING, ERROR, CRITICAL
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s -%(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

language_map = {
    "en": Bip39Languages.ENGLISH,
    "es": Bip39Languages.SPANISH,
    "fr": Bip39Languages.FRENCH,
    # "jp": Bip39Languages.JAPANESE,
    "kr": Bip39Languages.KOREAN,
    "cn": Bip39Languages.CHINESE_SIMPLIFIED,
    "zh": Bip39Languages.CHINESE_TRADITIONAL,
    "it": Bip39Languages.ITALIAN,
    "cz": Bip39Languages.CZECH,
    "pt": Bip39Languages.PORTUGUESE,
    # "ru": Bip39Languages.RUSSIAN
}

def check_list(selection, item_list):
    ''' 
    Returns the item in item_list that matches selection.
    Returns None if not found 
    '''
    for item, language in item_list :
        if (selection == item): 
            return language
        else :
            None

def get_seed_info(mnemonic: str, passphrase: str = ""):
    ''' 
    Returns the fingerprint (string) of the seed phrase.bip32_master_key
    Fingerprint MK PvtK PubK
    Compatible with SeedSigner and Krux devices. 
    '''
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

def display_results(mnemonic, pvtKey, pubKey, fingerprint):
    '''
    Prints the provided key information.
    '''
    print(f"Seed phrase : \n\t{mnemonic}")
    # print(f"Master Key :  {MasterKey} .")
    print(f"Private Key : {pvtKey} .")
    print(f"Public Key :  {pubKey} .")
    print(f"\tFingerprint : {fingerprint} \n")

def main():
    """
        This is the main function and entry-point of the program.
        This program creates a mnemonic object with the specified language and attempts to
        find a 24 word double 12 word pass phrase.
        Returns : none
    """
    parser = argparse.ArgumentParser(description="Create a Bitcoin pass phrase.")
    parser.add_argument('language', help='Language to be used [cn|cz|en|es|fr|it|jp|kr|pr|ru|zh].', type=str)
    # parser.add_argument('--passphrase', help='Optional passphrase that will act as extra mnemonic word.', type=str, default="")
    parser.add_argument('passphrase', nargs='?', help='Passphrase - optional extra mnemonic word.', type=str, default="")
    args = parser.parse_args()

    language = language_map.get(args.language.lower())
    if language is None:
        logging.error(f"Invalid language code: {args.language}")
        return

    obj_mnem1 = Bip39MnemonicGenerator(language).FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
    str_mnem1 = obj_mnem1.ToStr()
    '''
    Repeat guesses until a valid 12 word seed that matches the first (str_mnem1) is found.
    '''
    attempts = 0
    max_attempts = 10_000
    validator = Bip39MnemonicValidator()
    valid = False
    while ( not valid and attempts < max_attempts ):
        attempts = attempts + 1
        obj_mnem2 = Bip39MnemonicGenerator(language).FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
        str_mnem2 = obj_mnem2.ToStr()
        str_dbl = str_mnem1 + " " + str_mnem2
        valid = validator.IsValid(str_dbl)

    # Calculate the fingerprint; private and public keys of each mnemonic.
    pvtK1, pubK1, fp1 = get_seed_info(str_mnem1)
    pvtK2, pubK2, fp2 = get_seed_info(str_mnem2)
    pvtKd, pubKd, fpd = get_seed_info(str_dbl)

    # Display the results for each mnemonic
    print(" ")
    display_results(str_mnem1, pvtK1, pubK1, fp1)
    display_results(str_mnem2, pvtK2, pubK2, fp2)
    display_results(str_dbl, pvtKd, pubKd, fpd)

    print(f"\t\t\t{attempts} attempt(s) were made.\n")
    logging.info("Program terminated successfully.")

if __name__ == "__main__":
    main()
