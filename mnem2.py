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
import hmac
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, Bip39Languages, Bip39MnemonicValidator

# initialise logging - INFO, WARNING, ERROR, CRITICAL
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s -%(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# language_list = [("en", "english"), ("es", "spanish"), ("fr", "french"), ("jp", "japanese"),
#                  ("kr", "korean"), ("cn", "chinese_simplified"), ("zh", "chinese_traditional"), 
#                  ("it", "italian"), ("cz", "czech"), ("pt", "portuguese"), ("ru", "russian")]
language_list = [("en", "ENGLISH"), ("es", "SPANISH"), ("fr", "FRENCH"), ("jp", "JAPANESE"),
                 ("kr", "KOREAN"), ("cn", "CHINESE_SIMPLIFIED"), ("zh", "CHINESE_TRADITIONAL"), 
                 ("it", "ITALIAN"), ("cz", "CZECH"), ("pt", "PORTUGESE"), ("ru", "RUSSIAN")]

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

def calc_fingerprint(sp, pp=""):
    '''
    Calculate the fingerprint of a mnemonic given the seed phrase
    and the passphrase. Returns the fingerprint in hex (4 bytes).
    '''
    data = sp + "\n" + pp       # Concatenate seed phrase + passphrase with separator
    key = ("mnemonic" + pp).encode('utf-8')   # Create the key
    sha256_hash = hashlib.sha256(data.encode('utf-8')).digest()     # SHA256 hash of data
    hmac_hash = hmac.new(key, sha256_hash, hashlib.sha512).digest() # hash of data and key
    fingerprint = hmac_hash[:4] # Extract the first 4 bytes as the fingerprint
    return fingerprint.hex()

def main():
    """
        This is the main function and entry-point of the program.
        This program creates a mnemonic object with the specified language and attempts to
        find a 24 word double 12 word pass phrase.
        Returns : none
    """
    parser = argparse.ArgumentParser(description="Create a Bitcoin pass phrase.")
    parser.add_argument('language', help='Language to be used [cn|cz|en|es|fr|it|jp|kr|pr|ru|zh].', type=str)
    args = parser.parse_args()

    language = language_map.get(args.language.lower())
    if language is None:
        logging.error(f"Invalid language code: {args.language}")
        return

    obj_mnem1 = Bip39MnemonicGenerator(language).FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
    str_mnem1 = obj_mnem1.ToStr()

    attempts = 0
    validator = Bip39MnemonicValidator()

    '''
    Keep cycling through attempts until a valid 12 word seed that matches the first (str_mnem1) is found.
    '''
    valid = False
    while ( not valid ):
        attempts = attempts + 1
        obj_mnem2 = Bip39MnemonicGenerator(language).FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
        str_mnem2 = obj_mnem2.ToStr()
        str_dbl = str_mnem1 + " " + str_mnem2
        valid = validator.IsValid(str_dbl)

    # fp1 = calc_fingerprint(obj_mnem1)
    # fp2 = calc_fingerprint(obj_mnem2)
    # fpd = calc_fingerprint(phrase_dbl)

    print(f"Seed phrase 1 = {str_mnem1}")
    # print(f"Seed: {seed_one.hex()} .")
    # print(f"\tFingerprint: {fp1} \n")

    print(f"Seed phrase 2 = {str_mnem2}")
    # print(f"Seed: {seed_two.hex()} .")
    # print(f"\tFingerprint: {fp2} \n")

    print(f"Double seed phrase = \n\t{str_mnem1}\n\t{str_mnem2}")
    # print(f"Seed: {seed_dbl.hex()} .")
    # print(f"\tFingerprint: {fpd} \n")

    print(f"\t\t\t{attempts} attempt(s) were made.\n")
    logging.info("Program terminated successfully.")

if __name__ == "__main__":
    main()

