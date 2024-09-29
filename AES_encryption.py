import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import argparse

# Configure logging
logging.basicConfig(filename='encryption_app.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def derive_key(key):
    # Log the start of key derivation
    logging.debug("Starting key derivation.")

    # Derive a 32-byte (256-bit) key using PBKDF2
    salt = b'salt1234'  # You should use a unique salt for each application
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Adjust the number of iterations as needed for your security requirements
        backend=default_backend()
    )
    
    # Log the completion of key derivation
    logging.debug("Key derivation completed.")
    return kdf.derive(key)

def encrypt(plaintext, key):
    # Log encryption process start
    logging.info("Starting encryption process.")
    
    key = derive_key(key.encode('utf-8'))
    cipher = Cipher(algorithms.AES(key), modes.CFB8(key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Log successful encryption
    logging.info("Encryption successful.")
    
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt(ciphertext, key):
    # Log decryption process start
    logging.info("Starting decryption process.")
    
    key = derive_key(key.encode('utf-8'))
    cipher = Cipher(algorithms.AES(key), modes.CFB8(key[:16]), backend=default_backend())
    decryptor = cipher.decryptor()
    
    ciphertext_bytes = base64.b64decode(ciphertext)
    plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()
    
    # Log successful decryption
    logging.info("Decryption successful.")
    
    return plaintext.decode('utf-8')

def main():
    # Log application start
    logging.info("Application started.")

    parser = argparse.ArgumentParser(description="Simple AES Encryption and Decryption")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help='Select "encrypt" or "decrypt" mode')
    parser.add_argument('-p', '--plaintext', help='Text to be encrypted or decrypted')
    parser.add_argument('-k', '--key', help='Encryption/Decryption key')

    args = parser.parse_args()

    # Log mode selection
    logging.debug(f"Selected mode: {args.mode}")
    
    if args.mode == 'encrypt':
        if not args.plaintext or not args.key:
            logging.error("Error: Both plaintext and key are required for encryption.")
            print("Error: Both plaintext and key are required for encryption.")
            return
        
        encrypted_text = encrypt(args.plaintext.encode('utf-8'), args.key)
        logging.info("Encrypted Text: %s", encrypted_text)  # Log encrypted text for debugging purposes
        print(f"Encrypted Text: {encrypted_text}")

    elif args.mode == 'decrypt':
        if not args.plaintext or not args.key:
            logging.error("Error: Both ciphertext and key are required for decryption.")
            print("Error: Both ciphertext and key are required for decryption.")
            return
        
        decrypted_text = decrypt(args.plaintext, args.key)
        logging.info("Decrypted Text: %s", decrypted_text)  # Log decrypted text for debugging purposes
        print(f"Decrypted Text: {decrypted_text}")

    # Log application end
    logging.info("Application finished.")

if __name__ == "__main__":
    main()
