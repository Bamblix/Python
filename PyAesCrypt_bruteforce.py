# Install "pip3 pyAesCrypt -user" before running this script
import pyAesCrypt
import sys
import os

input_file = "xxx" # Change this for the name of the file
output_file = "decrypted_backup.zip"
buffer_size = 64 * 1024
wordlist_path = "/usr/share/wordlists/rockyou.txt"  # Change this if you have a different wordlist

def try_password(password):
    try:
        pyAesCrypt.decryptFile(input_file, output_file, password.strip(), buffer_size)
        print(f"\n Success! Password: {password.strip()}")
        return True
    except Exception as e:
        # Suppress decryption errors
        return False

if not os.path.exists(wordlist_path):
    print(f" Wordlist not found: {wordlist_path}")
    sys.exit(1)

with open(wordlist_path, "r", encoding="latin-1", errors="ignore") as f:
    for line in f:
        if try_password(line):
            break
