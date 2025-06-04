#!/usr/bin/env python3

# my-mnem.py
"""
My mnemonic
Test of the python 'mnemonic' library
main() is the entry point for the project.
"""

import logging
import argparse
from mnemonic import Mnemonic

# from modules.module1 import get_word_list
# # from modules.module2 import class_from_module2
# from modules.module1 import get_random
# import requests     # TESTING ONLY
# import json         # TESTING ONLY

# initialise logging - INFO, WARNING, ERROR, CRITICAL
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s -%(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def main():
    """
    This is the main function of the program.
    This program loads the word list and creates the pass phrase.
    Returns : none
    """
    logging.info("Program started.\n")

    parser = argparse.ArgumentParser(description="Create a Bitcoin pass phrase.")
    parser.add_argument('language', help='Word list languagr file to be used.', type=str)
    parser.add_argument('sp_length', help='Number of words in seed phrase 12|24', type=int)
    args = parser.parse_args()
    logging.info(f"main() entered with arguments...\n '{args}',\n language '{args.language}' and..\n seed phrase length '{args.sp_length}'.")

    ''' 
    TODO
        Segregate Argument Parser into it's own module.
        Test arguments for valid and differen languages.
    '''
    mnem = Mnemonic("english")
    mnemonic_phrase = mnem.generate(strength=128)
    print("Mnemonic Phrase:", mnemonic_phrase)

    is_valid = mnem.check(mnemonic_phrase)
    print("Is valid:", is_valid)

    seed = mnem.to_seed(mnemonic_phrase, passphrase="")
    print("Seed:", seed.hex())

    phrase1 = mnemonic_phrase
    phrase2 = mnem.generate(128)

    print(f"Phrase2 = {phrase2}")

    print(f"The double phrase = {phrase1 + " " + phrase2}")

    double_phrase = phrase1 + " " + phrase2
    is_valid = mnem.check(double_phrase)
    print("Is the double phrase valid?:", is_valid)


    # valid = False
    # while (!valid):
    #        seed2 = mnem.generate(strength=128)
    #        double = mnemonic_phrase + 
           

    logging.info("Program terminated successfully.")

if __name__ == "__main__":
    main()

