# Fragments

A small hobby project to learn about hashing and encryption properly. Fragments is a small CLI application that allows you to split files into smaller, completely obfuscated fragments which can then be hid to securely store data. This should hopefully keep your data safe for the next 10-20 years until someone builds a powerful enough Quantum Computer with the sufficient Qubits.

### Under The Hood

Firstly, The file data is read and stored as a `memoryview` object which should drastically reduce memory usage for large files as data is directly copied from that section of memory instead of creating new objects which will be very useful since we are inspecting slices of binary data which can lead to less memory usage.

Next, Fragments uses Argon2id a key-derivation function which can be used to generate AES keys from user-specified passwords. Salts are generated randomly (using cryptographically secure random values) to eliminate password cracking and rainbow tables.

Once a key has been derived, this value can be used as the secret key for encryption. Each file that you encrypt with Fragments gets a completely different key because of the randomized salting. The algorithm of choice for encryption is AES-GCM with a 256-bit key. It ensures data confidentiality as well as integrity by using the associated data tag.

Each slice of the file is assigned a unique 96-bit nonce which is used for encryption. To ensure integrity of data, the sequence number of files is stored in the associated data. Then, the sequence number, salt and the nonce are finally prepended with the ciphertext. It's safe to store them beside the file because not much can be done in regards to encryption with only these values.

It should theoretically work without issue on any OS. I configured it to use POSIX paths so there should be no issues whatsoever.