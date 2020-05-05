# Elgamal Public Key Encryption Scheme

This Elgamal variant will use a hash function (SHA256) to compute a key for the AES-GCM encryption scheme. The 3 seperate programs performs key generation, encryption and decryption. 

## Key Generation

The program generates the public key and secret key for the user. The program has to generate a prime number from a chosen arbitrary prime number. The program can bbe run with the command:

    elg-keygen <filename to store public key> <filename to store secret key>

The programs provides decimal formated output the public key (p, g, ga) for Bob and private key (p, g, a) for Alice.

## Elgamal Encryption

Reads in the public key ( p, g, ga ) produced by elg-keygen. Generates b and computes k = SHA256(ga∥gb∥gab). Outputs ( gb,AESGCM_k(M) ) to a ciphertext file, where the latter value is encoded as a hexadecimal string. The program can bbe executed with the command:

    elg-encrypt <message text as a string with quotes> <filename of public key> <filename of ciphertext>

## Elgamal Decryption

Reads in the ciphertext produced by the previous program and a stored secret, prints the recovered message or error. The program can be executed with the command:

    elg-decrypt <filename of ciphertext> <filename to read secret key>

Implementation of Elgamal encryption and decryption was successful.