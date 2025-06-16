#!/usr/bin/env python3

# my-mnem.py
"""
My mnemonic
main() is the entry point for the project.
"""
import logging
import argparse
from mnemonic import Mnemonic
import hashlib
import hmac

# initialise logging - INFO, WARNING, ERROR, CRITICAL
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s -%(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

language_list = [("en", "english"), ("es", "spanish"), ("fr", "french"), ("jp", "japanese"),
                 ("kr", "korean"), ("cn", "chinese_simplified"), ("zh", "chinese_traditional"), 
                 ("it", "italian"), ("cz", "czech"), ("pt", "portuguese"), ("ru", "russian")]

sp_length_list = [12, 24]

sp_length = 12

def check_list(selection, item_list):
    ''' 
    Returns the item in item_list that matches selection.
    Returns None if not found 
    '''
    for item, language in item_list :
        if (selection == item): 
            logging.info(f"ISO code : {item}")
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

    fingerprint = hmac_hash[:4]         # Extract the first 4 bytes as the fingerprint

    return fingerprint.hex()

def main():
    """
    This is the main function and entry-point of the program.
    This program creates a mnemonic object with the specified language and attempts to
    find a 24 word double 12 word pass phrase.
    Returns : none
    """

    parser = argparse.ArgumentParser(description="Create a Bitcoin pass phrase.")
    parser.add_argument('language', help='Word list language file to be used.', type=str)
    parser.add_argument('sp_length', help='Number of words in seed phrase 12|24', type=int)
    args = parser.parse_args()
   
    logging.info(f"main() entered with arguments...\n '{args}',\n language '{args.language}' and..\n seed phrase length '{args.sp_length}'.\n")

    ''' 
    TODO
        Segregate Argument Parser into it's own module.
        Segregate fingerprint calculator into it's own module.
        Correctly impliment the passing of the command line arguments to main()
        Remove second argument. It must always have a seed word length 12 for a 24 word double mnemonic!
        Change the description of the command-line arguments.
        Possibly improve algorythim to look for the last word of the last seed rather than brute force 
        the whole 12 words (or retain because it improves randomness!).
    '''

    language = check_list(args.language, language_list)
    logging.info(f"The checked and parsed language is ==> {language} <==")

    mnem = Mnemonic(language)      # Assumes all generated seed phrases are valid.

    phrase1 = mnem.generate(strength=128)
    attempts = 0
    valid = False
    while ( not valid ):
           attempts = attempts + 1
           phrase2 = mnem.generate(strength=128)
           phrase_dbl = phrase1 + " " + phrase2
           valid = mnem.check(phrase_dbl)

    seed_one = mnem.to_seed(phrase1, passphrase="")
    seed_two = mnem.to_seed(phrase2, passphrase="")
    seed_dbl = mnem.to_seed(phrase_dbl, passphrase="")

    fp1 = calc_fingerprint(phrase1)
    fp2 = calc_fingerprint(phrase2)
    fpd = calc_fingerprint(phrase_dbl)

    print(f"Seed phrase 1 = {phrase1}")
    print(f"Seed: {seed_one.hex()} .")
    print(f"Fingerprint: {fp1} \n")

    print(f"Seed phrase 2 = {phrase2}")
    print(f"Seed: {seed_two.hex()} .")
    print(f"Fingerprint: {fp2} \n")

    print(f"Double seed phrase = {phrase_dbl}")
    print(f"Seed: {seed_dbl.hex()} .")
    print(f"Fingerprint: {fpd} \n")

    print(f"{attempts} attempt(s) were made.\n")

    logging.info("Program terminated successfully.")

if __name__ == "__main__":
    main()

