#!/usr/bin/env python3

# my-mnem.py
"""
My mnemonic
main() is the entry point for the project.
This code is based around the *bip_utils* library
"""
import logging
import argparse
from mnemonic import Mnemonic
import hashlib
import hmac
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, Bip39Languages, Bip39MnemonicValidator

'''
# Generate mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)

# Convert to seed
seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase="")

'''


# initialise logging - INFO, WARNING, ERROR, CRITICAL
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s -%(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

language_list = [("en", "english"), ("es", "spanish"), ("fr", "french"), ("jp", "japanese"),
                 ("kr", "korean"), ("cn", "chinese_simplified"), ("zh", "chinese_traditional"), 
                 ("it", "italian"), ("cz", "czech"), ("pt", "portuguese"), ("ru", "russian")]


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
   
    ''' 
    TODO
        Segregate fingerprint calculator into it's own module.
        Correct README.md to represent current status! <== **important**.
        Remove second argument. It must always have a seed word length 12 for a 24 word double mnemonic!
        Change the description of the command-line arguments.
        Possibly improve algorythim to look for the last word of the last seed rather than brute force 
        the whole 12 words (or retain because it improves randomness!).
    '''

    language = check_list(args.language, language_list)
    logging.info(f"The checked and parsed language requested is ==> {language} <==\n")
    entropy = 128                  # 128 bit represents 12 seed words
    mnem = Mnemonic(language)      # Assumes all generated seed phrases are valid.

    obj_mnem1 = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
    logging.info(f"The bip_utils generated mnemonic 1 is : Type - {type(obj_mnem1)}\n\t{obj_mnem1}")
    str_mnem1 = obj_mnem1.ToStr()
    logging.info(f"The bip_utils generated mnemonic 1 is : Type - {type(str_mnem1)}")


    attempts = 0
    validator = Bip39MnemonicValidator()
    valid = False
    while ( not valid ):
        attempts = attempts + 1
        TEST_STRING = "Hello, world TEST."
        print(f"TEST STRING IS OF TYPE {type(TEST_STRING)}")
        # obj_mnem1 = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
        obj_mnem2 = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
        str_mnem2 = obj_mnem2.ToStr()
        logging.info(f"The bip_utils generated mnemonic 2 is : Type - {type(str_mnem2)}")
        print(f"\t\t The loop variable 'valid' is ==>{valid}<==")
        str_dbl = str_mnem1 + " " + str_mnem2
        logging.info(f"The double phrase at attempt number {attempts} is \n{str_dbl}")
        logging.info(f"The expected string is of type {type(str_dbl)}")
        valid = validator.IsValid(str_dbl)
        print(f"\t\t The loop variable 'valid' is ==>{valid}<==")


    # seed_one = mnem.to_seed(obj_mnem1, passphrase="")
    # seed_two = mnem.to_seed(obj_mnem2, passphrase="")
    # seed_dbl = mnem.to_seed(phrase_dbl, passphrase="")

    # fp1 = calc_fingerprint(obj_mnem1)
    # fp2 = calc_fingerprint(obj_mnem2)
    # fpd = calc_fingerprint(phrase_dbl)

    print(f"Seed phrase 1 = {obj_mnem1}")
    # print(f"Seed: {seed_one.hex()} .")
    # print(f"\tFingerprint: {fp1} \n")

    print(f"Seed phrase 2 = {obj_mnem2}")
    # print(f"Seed: {seed_two.hex()} .")
    # print(f"\tFingerprint: {fp2} \n")

    print(f"Double seed phrase = \n\t{obj_mnem1}\n\t{obj_mnem2}")
    # print(f"Seed: {seed_dbl.hex()} .")
    # print(f"\tFingerprint: {fpd} \n")

    print(f"\t\t\t{attempts} attempt(s) were made.\n")

    logging.info("Program terminated successfully.")

if __name__ == "__main__":
    main()

