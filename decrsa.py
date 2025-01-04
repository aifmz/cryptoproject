from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def decrypt_file(input_file, output_file, private_key):
    # Read the encrypted data from the input file
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()

    # Create a cipher object using the private key
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(private_key))

    # Decrypt the data
    decrypted_data = rsa_cipher.decrypt(encrypted_data)

    # Write the decrypted content to the output file
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

def main():
    # Load the private key from a file (ensure this matches your encryption key)
    with open('private.pem', 'rb') as f:
        private_key = f.read()

    # Define input and output files
    input_file = r'C:\Users\ACER\Documents\crypto sheet4\encrypted_data.bin'
    output_file = r'C:\Users\ACER\Documents\crypto sheet4\decrypted_data.txt'

    # Decrypt the file
    decrypt_file(input_file, output_file, private_key)

    print(f"Decrypted content from '{input_file}' has been saved to '{output_file}'.")

if __name__ == "__main__":
    main()
