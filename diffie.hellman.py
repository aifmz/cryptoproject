from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# File paths
KEY_DIR = r'C:\crypto'
INPUT_FILE = os.path.join(KEY_DIR, "hello.txt")
ENCRYPTED_FILE = os.path.join(KEY_DIR, "encrypted_file.bin")
DECRYPTED_FILE = os.path.join(KEY_DIR, "decrypted_file.txt")

def generate_parameters():
    # Generate parameters for Diffie-Hellman key exchange
    return dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def generate_private_key(parameters):
    # Generate a private key for the given parameters
    return parameters.generate_private_key()

def save_key_to_file(key, filepath, is_private=True):
    # Save private or public key to a file
    encoding = serialization.Encoding.PEM
    if is_private:
        pem_data = key.private_bytes(
            encoding=encoding,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem_data = key.public_bytes(
            encoding=encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    with open(filepath, "wb") as f:
        f.write(pem_data)

def load_key_from_file(filepath, is_private=True):
    # Load private or public key from a file
    with open(filepath, "rb") as f:
        pem_data = f.read()

    if is_private:
        return serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
    else:
        return serialization.load_pem_public_key(pem_data, backend=default_backend())

def encrypt_file(input_file, encrypted_file, key):
    # Encrypt file using AES with the symmetric key
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, "rb") as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Save the IV and ciphertext
    with open(encrypted_file, "wb") as f:
        f.write(iv + ciphertext)

    print(f"File '{input_file}' encrypted and saved to '{encrypted_file}'.")

def decrypt_file(encrypted_file, decrypted_file, key):
    # Decrypt file using AES with the symmetric key
    with open(encrypted_file, "rb") as f:
        iv = f.read(16)  # Read the IV (first 16 bytes)
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(decrypted_file, "wb") as f:
        f.write(plaintext)

    print(f"File '{encrypted_file}' decrypted and saved to '{decrypted_file}'.")

def main():
    # Generate Diffie-Hellman parameters
    parameters = generate_parameters()

    # Generate private and public keys for Alice
    alice_private_key = generate_private_key(parameters)
    alice_public_key = alice_private_key.public_key()

    # Generate private and public keys for Bob
    bob_private_key = generate_private_key(parameters)
    bob_public_key = bob_private_key.public_key()

    # Exchange public keys and compute shared secret
    alice_shared_secret = alice_private_key.exchange(bob_public_key)
    bob_shared_secret = bob_private_key.exchange(alice_public_key)

    # Verify that both shared secrets are equal
    assert alice_shared_secret == bob_shared_secret, "Shared secrets do not match!"

    # Derive a symmetric key from the shared secret using HKDF
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'secure session',
        backend=default_backend()
    ).derive(alice_shared_secret)

    print("Shared secret established successfully!")
    print(f"Symmetric Key: {symmetric_key.hex()}")

    # Alice encrypts the file
    encrypt_file(INPUT_FILE, ENCRYPTED_FILE, symmetric_key)

    # Bob decrypts the file
    decrypt_file(ENCRYPTED_FILE, DECRYPTED_FILE, symmetric_key)

if __name__ == "__main__":
    main()
