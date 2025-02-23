import base64
import json
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import os
import secrets, string

class EncryptionHandler:
    # Set the path for your public and private keys
    current_path = os.path.dirname(os.path.abspath(__file__))
    PUBLIC_KEY_FILE = os.path.join(current_path, "prod_pub_key.crt")
    PRIVATE_KEY_FILE = os.path.join(current_path, "prod_priv_key.pem")
    
    # Generate a proper session key (16 bytes for AES-128) and IV (16 bytes for AES)
    SESSION_KEY = os.urandom(16)
    IV = os.urandom(16)

    def __init__(self):
        pass

    # Function to encrypt data using AES (Symmetric Encryption)
    def encrypt_data(self, data, session_key, iv):
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        padded_data = pad(data.encode('utf-8'), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return base64.b64encode(iv + encrypted_data).decode('utf-8')  # Include IV with encrypted data

    # Function to encrypt session key using RSA (Asymmetric Encryption)
    def encrypt_key(self, session_key):
        with open(self.PUBLIC_KEY_FILE, 'rb') as f:
            public_key = RSA.import_key(f.read())
        cipher_rsa = PKCS1_v1_5.new(public_key)
        encrypted_key = cipher_rsa.encrypt(session_key)
        return base64.b64encode(encrypted_key).decode('utf-8')

    # Function to decrypt data using AES (Symmetric Decryption)
    def decrypt_data(self, encrypted_data, encrypted_key):
        with open(self.PRIVATE_KEY_FILE, "rb") as key_file:
            private_key = RSA.import_key(key_file.read())

        # Decrypt session key using RSA
        encrypted_key_bytes = base64.b64decode(encrypted_key)
        cipher = PKCS1_v1_5.new(private_key)
        session_key = cipher.decrypt(encrypted_key_bytes, None)

        # Debug: Check if session_key is empty
        if not session_key:
            print("ERROR: Decrypted session key is empty.")
            return None
        print(f"Decrypted session key: {session_key.hex()}")  # Show the session key in hex format

        # Decrypt the data using AES
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        iv = encrypted_data_bytes[:16]  # First 16 bytes are the IV
        encrypted_data_bytes = encrypted_data_bytes[16:]  # Rest is the encrypted data
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(encrypted_data_bytes), AES.block_size)
        return plaintext.decode("utf-8")

    # Main function to test the encryption and decryption
    def process_data(self, text_to_encrypt):
        # Encrypting the data
        encrypted_data = self.encrypt_data(text_to_encrypt, self.SESSION_KEY, self.IV)
        encrypted_key = self.encrypt_key(self.SESSION_KEY)

        # Display encrypted data and key
        print("Encrypted Data:", encrypted_data)
        print("Encrypted Key:", encrypted_key)

        # Decrypting the data
        # encrypted_key = 'i1zpz3b19WuaHU6auPvlfv3GgMVn9ERWQd8yHpbCHGpIiBSKFUiiXjoLonhtqC5HYMdQ5s4v+OvhE2cPd6DF4ACWxoMTLDSJ/Z8JV+d+DC0LiReN1gfXfLqtKN6Y92k5Vb43qxIDqQbwuVroD2Rzy2PHeZIyqJgqncS9kW4Y+yb56IcD74X50Wf7puOiHzWmxRWiV9fewcIQVDOhulTBaSZHuvRQBwivt7rnPsh4aUbR9OOK9ZbAMY10Ed9FQDxlUHaRTLwSrYErNEo5ZcezBpFt+/048sZT64naetldud93F5LsnDmZ77TiAW9Pk0oX8YnkuZfjo4oiRmI/T8TsAG4U/C3syfFrKue0Meb5auBtlZTMw7d6z6qyTCXIe99vAptmL/e3Q8jgUO6yo1srmpWePPURDJiniI7TmREomh8qPrY1NOvi8aMlPrOQ/uUJw+tJ0maRcQ0Xn1K4etiCFJRUG2VNpb5kQV3oMsyrGisyYqCTfCgyFB+q13I7M8dvA5Dn/l1XXSCnEinY3wVX+A8DbgfCD/3DWSV+gHXadAGGX6PvCy1WlcddSFn/JSSeaybDdXydrNeHmdd+jJuS1efrWgMZmfheGoDW1bj7XyuinZmDuiognepqXqsM7By1tENC1XdOcgl2qNtnwXbx+JW73m3GQnd4Kr1ypKkoUGw='
        # encrypted_data = 'd9ZkBuxpr0vz7mVKAiJspUvgo+/gtiCGl4yfOh+mb3/fcDgVFK58g01ULBDEf5gwHhP6Jq+Tc7X50hA6lFv0FQtYOfHYiqsdBZ3VHK9bEWw='
        decrypted_data = self.decrypt_data(encrypted_data, encrypted_key)
        if decrypted_data:
            print("Decrypted Data:", decrypted_data)
        else:
            print("Decryption failed.")


if __name__ == "__main__":
    # Example text to encrypt and decrypt
    text = "Pradip sir"

    # Create an instance of the EncryptionHandler class
    handler = EncryptionHandler()
    
    # Process the data (Encrypt and then Decrypt)
    handler.process_data(text)
