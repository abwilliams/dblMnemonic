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

# initialise logging - INFO, WARNING, ERROR, CRITICAL
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s -%(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def main():
    """
    This is the main function and entry-point of the program.
    This program creates a mnemonic object with the specified language and attempts to
    find a 24 word double 12 word pass phrase.
    Returns : none
    """
    logging.info("Program started.\n")

    parser = argparse.ArgumentParser(description="Create a Bitcoin pass phrase.")
    parser.add_argument('language', help='Word list language file to be used.', type=str)
    parser.add_argument('sp_length', help='Number of words in seed phrase 12|24', type=int)
    args = parser.parse_args()
    logging.info(f"main() entered with arguments...\n '{args}',\n language '{args.language}' and..\n seed phrase length '{args.sp_length}'.\n")

    ''' 
    TODO
        Segregate Argument Parser into it's own module.
        Correctly impliment the passing of the command line arguments to main()
        Test arguments for valid and different languages.
        Change the description of the command-line arguments.
        Display the fingerprint of each seed phrase.
    '''
    
    mnem = Mnemonic("english")
    # Assumes all Mnemonic() generated seed phrases are valid
    # Change the algo to look for the last word of the last seed rather than the whole 12 words.

    phrase1 = mnem.generate(strength=128)
    attempts = 0
    valid = False
    while ( not valid ):
           attempts = attempts + 1
           phrase2 = mnem.generate(strength=128)
           double_phrase = phrase1 + " " + phrase2
           valid = mnem.check(double_phrase)

    seed_one = mnem.to_seed(double_phrase, passphrase="")
    seed_two = mnem.to_seed(double_phrase, passphrase="")
    seed_dbl = mnem.to_seed(double_phrase, passphrase="")

    print(f"Seed phrase 1 = {phrase1}")
    print(f"Seed: {seed_one.hex()} .")
    print(f"Fingerprint: XXXX \n")

    print(f"Seed phrase 2 = {phrase2}")
    print(f"Seed: {seed_two.hex()} .")
    print(f"Fingerprint: XXXX \n")

    print(f"Double seed phrase = {double_phrase}")
    print(f"Seed: {seed_dbl.hex()} .")
    print(f"Fingerprint: XXXX \n")

    is_valid = mnem.check(double_phrase)
    print(f"The double phrase is valid. : {is_valid} ")
    print(f"{attempts} attempt(s) were made.\n")

    logging.info("Program terminated successfully.")

if __name__ == "__main__":
    main()

