This repository contains Python code for a comprehensive cryptographic toolkit, offering encryption, decryption, and password verification functionalities.


Key Features:

AES Encryption/Decryption: Utilizes AES-256 with CFB mode for robust encryption and decryption of text data.

Password-Based Key Derivation: Employs PBKDF2 with SHA-256 hash function to derive secure encryption keys from user-provided passwords.

Hashing: Implements SHA-256 hashing for password verification and storage.

Logging: Detailed logging is included for debugging and troubleshooting purposes.

User-Friendly Interface: Provides a simple command-line interface for user interaction.

Flexibility: Offers multiple cryptographic algorithms and modes for various use cases.


Files:

aes_encryption.py: Contains functions for AES encryption and decryption using the provided key derivation method.

vigenere_cipher.py: Implements the Vigenère cipher for additional encryption/decryption options.

password_hashing.py: Handles password hashing using SHA-256 for secure storage and verification.



Note:

This is a basic implementation for educational purposes. Consider security best practices and potential vulnerabilities for real-world applications.

Adjust parameters like salt values and iteration counts based on your specific security requirements.

For production use, explore more advanced cryptographic libraries and consider additional security measures.

This repository provides a valuable resource for understanding and experimenting with encryption techniques, password hashing, and security best practices.
