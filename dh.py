from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

def generate_parameters():
    # Generate parameters for Diffie-Hellman key exchange
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

def generate_private_key(parameters):
    # Generate a private key for the given parameters
    private_key = parameters.generate_private_key()
    return private_key

def generate_public_key(private_key):
    # Generate a public key from the private key
    public_key = private_key.public_key()
    return public_key

def main():
    # Generate Diffie-Hellman parameters
    parameters = generate_parameters()

    #  Alice generates her private and public keys
    alice_private_key = generate_private_key(parameters)
    alice_public_key = generate_public_key(alice_private_key)

    #  Bob generates his private and public keys
    bob_private_key = generate_private_key(parameters)
    bob_public_key = generate_public_key(bob_private_key)

    #  Exchange public keys (simulated here)
    
    # Alice computes the shared secret using Bob's public key
    alice_shared_secret = alice_private_key.exchange(bob_public_key)
    
    # Bob computes the shared secret using Alice's public key
    bob_shared_secret = bob_private_key.exchange(alice_public_key)

    # Verify that both shared secrets are equal
    assert alice_shared_secret == bob_shared_secret, "Shared secrets do not match!"

    # Optional: Derive a symmetric key from the shared secret (using HKDF)
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    # Derive a symmetric key 
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'secure session',
        backend=default_backend()
    ).derive(alice_shared_secret)

    print("Shared secret established successfully!")
    print(f"Symmetric Key: {symmetric_key.hex()}")

if __name__ == "__main__":
    main()
