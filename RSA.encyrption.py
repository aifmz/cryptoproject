from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os

def generate_keys():
    # Generate RSA key pair
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_file(input_file, output_file, public_key):
    # Read data from the input file
    with open(input_file, 'rb') as f:
        data = f.read()

    # Encrypt the data using RSA
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_data = rsa_cipher.encrypt(data)

    # Write the encrypted content to the output file
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

def main():
    # Directory path for saving keys
    key_dir = r'C:\crypto'

    # Ensure the directory exists
    os.makedirs(key_dir, exist_ok=True)

    # Generate RSA keys
    private_key, public_key = generate_keys()

    # Save keys to files in the specified directory
    private_key_path = os.path.join(key_dir, 'private.pem')
    public_key_path = os.path.join(key_dir, 'public.pem')

    with open(private_key_path, 'wb') as f:
        f.write(private_key)

    with open(public_key_path, 'wb') as f:
        f.write(public_key)

    # Define input and output files
    input_file = os.path.join(key_dir, 'hello.txt')
    output_file = os.path.join(key_dir, 'encrypted_data.bin')

    # Encrypt the file
    encrypt_file(input_file, output_file, public_key)

    print(f"Private key saved to: {private_key_path}")
    print(f"Public key saved to: {public_key_path}")
    print(f"Data from '{input_file}' has been encrypted and saved to '{output_file}'.")

if __name__ == "__main__":
    main()
