from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

def generate_keys():
    key = RSA.generate(2048)  # Generate a 2048-bit RSA key pair
    private_key = key.export_key()  # Export the private key
    public_key = key.publickey().export_key()  # Export the public key
    return private_key, public_key  # Return the private and public keys

def sign_message(private_key, message):
    key = RSA.import_key(private_key)  # Import the private key for signing
    h = SHA256.new(message.encode())  # Create a SHA-256 hash of the message
    signature = pkcs1_15.new(key).sign(h)  # Sign the hash using the private key
    return signature  # Return the digital signature

def verify_signature(public_key, message, signature):
    key = RSA.import_key(public_key)  # Import the public key for verification
    h = SHA256.new(message.encode())  # Create a SHA-256 hash of the message
    try:
        pkcs1_15.new(key).verify(h, signature)  # Verify the signature using the public key
        return True  # Return True if the signature is valid
    except (ValueError, TypeError):
       
        return False  # Return False if the signature is invalid

def encrypt_file(public_key, input_file, encrypted_file):
    key = RSA.import_key(public_key)  # Import the public key for encryption
    rsa_cipher = PKCS1_OAEP.new(key)  # Create an RSA cipher object for encryption
    
    aes_key = get_random_bytes(16)  # Generate a 128-bit AES key
    iv = get_random_bytes(16)  # Generate an initialization vector (IV)
    aes_cipher = AES.new(aes_key, AES.MODE_CFB, iv)  # Create an AES cipher in CFB mode
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)  # Encrypt the AES key with RSA
    
    with open(input_file, 'rb') as f:  # Open the input file in binary read mode
        plaintext = f.read()  # Read the plaintext content of the file
    ciphertext = aes_cipher.encrypt(plaintext)  # Encrypt the file content using AES
    with open(encrypted_file, 'wb') as f:  # Open the output file in binary write mode
        f.write(encrypted_aes_key + iv + ciphertext)  # Write the encrypted AES key, IV, and ciphertext
    
    print(f"File '{input_file}' encrypted successfully to '{encrypted_file}'.")  # Print a success message

def decrypt_file(private_key, encrypted_file, decrypted_file):
    key = RSA.import_key(private_key)  # Import the private key for decryption
    rsa_cipher = PKCS1_OAEP.new(key)  # Create an RSA cipher object for decryption
    
    with open(encrypted_file, 'rb') as f:  # Open the encrypted file in binary read mode
        encrypted_aes_key = f.read(256)  # Read the first 256 bytes (RSA-encrypted AES key)
        iv = f.read(16)  # Read the next 16 bytes (IV)
        ciphertext = f.read()  # Read the remaining bytes (ciphertext)
    
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)  # Decrypt the AES key using RSA
    
    aes_cipher = AES.new(aes_key, AES.MODE_CFB, iv)  # Create an AES cipher in CFB mode with the decrypted key and IV
    plaintext = aes_cipher.decrypt(ciphertext)  # Decrypt the ciphertext to retrieve the plaintext
    
    with open(decrypted_file, 'wb') as f:  # Open the output file in binary write mode
        f.write(plaintext)  # Write the decrypted content to the file
    
    print(f"File '{encrypted_file}' decrypted successfully to '{decrypted_file}'.")  # Print a success message




# Example
if __name__ == "__main__":
    # Generate RSA keys
    private_key, public_key = generate_keys()

    # Paths to the files
    input_file = 'input.txt'  # Existing file to be encrypted
    encrypted_file = 'encrypted_file.txt'
    decrypted_file = 'decrypted_file.txt'

    # Create a sample input file
    with open(input_file, 'w') as f:
        f.write("This is a test file for hybrid encryption and decryption.")

    # Encrypt the existing file
    encrypt_file(public_key, input_file, encrypted_file)

    # Decrypt the encrypted file
    decrypt_file(private_key, encrypted_file, decrypted_file)

    # Read and display the decrypted content
    with open(decrypted_file, 'r') as f:
        print("Decrypted content:", f.read())

    # Digital signature example
    message = "This is an important message."
    signature = sign_message(private_key, message)
    print("Signature:", signature)

    # Verify the signature
    is_valid = verify_signature(public_key, message, signature)
    print("Is the signature valid?", is_valid)

    # Tampering the message
    tampered_message = "This is a tampered message."
    is_valid_tampered = verify_signature(public_key, tampered_message, signature)
    print("Is the tampered message's signature valid?", is_valid_tampered)
