#!/usr/bin/env python3
import hashlib

name = input("Please enter the name: ")
passphrase = input("Please enter the passphrase: ")
storedHash = input("Please enter the stored hash: ")

def hash_passphrase(passphrase):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(passphrase.encode('utf-8'))
    return sha256_hash.hexdigest()

if hash_passphrase(passphrase) == storedHash:
    print(f"{name}'s passphrase is valid!")
else:
    print(f"{name}'s passphrase is invalid!")
