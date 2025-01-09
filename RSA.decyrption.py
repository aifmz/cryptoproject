from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

def generate_keys(key_dir):
    # Generate RSA key pair
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # keys files
    private_key_path = os.path.join(key_dir, 'private.pem')
    public_key_path = os.path.join(key_dir, 'public.pem')

    with open(private_key_path, 'wb') as f:
        f.write(private_key)

    with open(public_key_path, 'wb') as f:
        f.write(public_key)

    print(f"Private key saved to: {private_key_path}")
    print(f"Public key saved to: {public_key_path}")

def load_keys(key_dir):
    # Load the private key
    private_key_path = os.path.join(key_dir, 'private.pem')
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())

    # Load the public key
    public_key_path = os.path.join(key_dir, 'public.pem')
    with open(public_key_path, 'rb') as f:
        public_key = RSA.import_key(f.read())

    return private_key, public_key

def encrypt_file(input_file, output_file, public_key):
    # Read data from the input file
    with open(input_file, 'rb') as f:
        data = f.read()

    # Encrypt the data using RSA
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = rsa_cipher.encrypt(data)

    # Write the encrypted content to the output file
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

def main():
    # Directory path for saving keys and files
    key_dir = r'C:\crypto'

    # Ensure the directory exists
    os.makedirs(key_dir, exist_ok=True)

    # Generate RSA keys if they don't already exist
    private_key_path = os.path.join(key_dir, 'private.pem')
    public_key_path = os.path.join(key_dir, 'public.pem')

    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        print("Keys not found. Generating new keys...")
        generate_keys(key_dir)
    else:
        print("Keys already exist. Loading keys...")

    # Load RSA keys from files
    private_key, public_key = load_keys(key_dir)

    # Define input and output files
    input_file = os.path.join(key_dir, 'hello.txt')
    output_file = os.path.join(key_dir, 'encrypted_data.bin')

    # Encrypt the file
    encrypt_file(input_file, output_file, public_key)

    print(f"Data from '{input_file}' has been encrypted and saved to '{output_file}'.")

if __name__ == "__main__":
    main()
