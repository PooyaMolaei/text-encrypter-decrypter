This repository contains Python code for a simple command-line application that encrypts and decrypts text data using AES (Advanced Encryption Standard) with a password-based key derivation function (PBKDF2).

Features:

-Encrypts and decrypts text data using AES-256 with CFB (Cipher Feedback) mode.

-Derives a secure key from a user-provided password using PBKDF2 with SHA-256 hash function.

-Supports base64 encoding/decoding for ciphertext representation.

-Includes detailed logging for debugging purposes (configurable log level).

-User-friendly command-line interface with arguments for mode selection, plaintext/ciphertext, and key.

-Records detailed logs of the encryption/decryption process for debugging and troubleshooting.


Note:

This is a basic implementation for educational purposes. Consider security best practices and potential vulnerabilities for real-world encryption scenarios.
The provided salt value ("salt1234") is for demonstration only. Use a unique and secure random salt for each application.
Adjust the number of PBKDF2 iterations (currently set to 100,000) based on your security needs and processing time considerations.
