from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag, InvalidKey
from pathlib import Path
import sys, secrets, os

# File Layout:
# [4 Bytes : Magic Number] [ 1 Byte :  sequence number ] 
# [ 16 bytes : salt ] [ 12 bytes : nonce ] [ payload (AD : sequence number) ]  

# Creation:
# -c: Create Fragments
# -p: Password Field
# -s: Number of Slices

# Restoration:
# -r: Restore Fragments
# -p: Password Field

input_args = sys.argv
magic_num = 0x46524758

if len(input_args) >= 5:
    
    if input_args[1] == "-c" and input_args[3] == "-p" and input_args[5] == "-s":

        file_path = Path(input_args[2]).resolve().as_posix()

        file_name = Path(input_args[2]).stem

        with open(file_path, 'rb') as file:
            file_data = memoryview(file.read())

        # Password-Key Generation
        salt = secrets.token_bytes(16)
        kdf = Argon2id(salt=salt, length=32, iterations=1, lanes=4, memory_cost=(64*1024), ad=None, secret=None)
        password_as_bytes = input_args[4].encode("utf-8")
        secret_key = kdf.derive(password_as_bytes)

        # AES-GCM Setup``
        encryptor = AESGCM(secret_key)

        # File Division & Encryption
        batch_size = len(file_data) // (int(input_args[6]))
        sequence = 0
        for i in range(0, len(file_data), batch_size):
            nonce = secrets.token_bytes(12)
            encrypted_data = encryptor.encrypt(nonce=nonce, data=file_data[i:i+batch_size], associated_data=sequence.to_bytes(length=1, byteorder="big"))
            final_payload = b''.join([magic_num.to_bytes(length=4, byteorder="big"), sequence.to_bytes(length=1, byteorder="big"), salt, nonce, encrypted_data])

            with open(f'{file_name}_{sequence + 1}.frgx', 'wb') as file:
                file.write(final_payload)

            sequence += 1

        print("Fragmentation Complete")

    elif input_args[1] == "-r" and input_args[3] == "-p":

        contains_header = list()
        password_as_bytes = input_args[4].encode("utf-8")

        # find files
        
        for file_name in os.listdir(): 
            try:
                with open(file_name, 'rb') as file:
                    file_magic = file.read(4)
                    if file_magic == b'FRGX':
                        file_header = (file_name, file.read(1), file.read(16), file.read(12))
                        contains_header.append(file_header)
            except PermissionError:
                pass

        kdf = Argon2id(salt=contains_header[0][2], length=32, iterations=1, lanes=4, memory_cost=(64*1024), ad=None, secret=None)
        secret_key = kdf.derive(password_as_bytes)
        decryptor = AESGCM(secret_key)

        full_file = bytes()

        for header in contains_header:
            with open(header[0], 'rb') as file:
                try:
                    data = file.read()[33:]
                    plain = decryptor.decrypt(header[3], data, header[1])
                    full_file += plain
                except (InvalidKey, InvalidTag):
                    print("Incorrect Key")
                    break


        with open(input_args[2], 'wb') as file:
            file.write(full_file)
        
    else:
        print("Invalid Arguments")

