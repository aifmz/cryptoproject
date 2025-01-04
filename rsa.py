from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os

def generate_keys():
    # Generate RSA key pair
    key = RSA.generate(2048)
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
    # Generate RSA keys
    private_key, public_key = generate_keys()

    # Save keys to files (optional)
    with open('private.pem', 'wb') as f:
        f.write(private_key)

    with open('public.pem', 'wb') as f:
        f.write(public_key)

    # Define input and output files
    input_file = r'C:\Users\ACER\Documents\crypto sheet4\hello.txt'  
    output_file = r'C:\Users\ACER\Documents\crypto sheet4\encrypted_data.bin'

    # Encrypt the file
    encrypt_file(input_file, output_file, public_key)

    print(f"Data from '{input_file}' has been encrypted and saved to '{output_file}'.")

if __name__ == "__main__":
    main()
