import base64
import json
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad
import os

# Assuming you have the public and private keys for RSA
class EncryptDecryptResponse:

    def __init__(self):
        self.SESSION_KEY = os.urandom(16)  # Random session key for AES
        self.IV = os.urandom(16)  # Random IV for AES
        self.current_path = os.path.dirname(os.path.abspath(__file__))
        self.PUBLIC_KEY_FILE = os.path.join(self.current_path, "prod_pub_key.crt")
        self.PRIVATE_KEY_FILE = os.path.join(self.current_path, "prod_priv_key.pem")

    def encrypt_data(self, data, session_key, iv):
        """Encrypts the data using AES (CBC Mode)"""
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        padded_data = pad(data.encode('utf-8'), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted_data).decode('utf-8')

    def encrypt_key(self, session_key):
        """Encrypts the session key using RSA public key"""
        with open(self.PUBLIC_KEY_FILE, 'rb') as f:
            public_key = RSA.import_key(f.read())
        cipher_rsa = PKCS1_v1_5.new(public_key)
        encrypted_key = cipher_rsa.encrypt(session_key)
        return base64.b64encode(encrypted_key).decode('utf-8')

    def decrypt_data(self, encrypted_data, encrypted_key):
        """Decrypts the response data using RSA private key and AES"""
        with open(self.PRIVATE_KEY_FILE, "rb") as key_file:
            private_key = RSA.import_key(key_file.read())

        # Decrypt the session key
        encrypted_key_bytes = base64.b64decode(encrypted_key)
        cipher = PKCS1_v1_5.new(private_key)
        session_key = cipher.decrypt(encrypted_key_bytes, None)

        # Ensure the session key has the correct length (16 bytes for AES)
        if len(session_key) != 16:
            raise ValueError(f"Incorrect session key length: {len(session_key)} bytes")

        # Decrypt the data
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        iv = encrypted_data_bytes[:16]  # Extract IV from the encrypted data
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data_bytes[16:]), AES.block_size)
        return decrypted_data.decode("utf-8")

    def send_encrypted_request(self, payload):
        """Sends the encrypted request data to the API"""

        # Encrypt the payload data
        encrypted_data = self.encrypt_data(payload, self.SESSION_KEY, self.IV)
        encrypted_key = self.encrypt_key(self.SESSION_KEY)

        # Prepare the payload for the request
        final_json = {
            "requestId": "",
            "service": "LOP",
            "encryptedKey": encrypted_key,
            "oaepHashingAlgorithm": "NONE",
            "iv": base64.b64encode(self.IV).decode('utf-8'),
            "encryptedData": encrypted_data,
            "clientInfo": "",
            "optionalParam": ""
        }

        # Make the request (example)
        print("Encrypted Data: ", final_json)
        decrypted_data = self.decrypt_data(final_json["encryptedData"], final_json["encryptedKey"])
        print("Decrypted Response:", decrypted_data)
        return decrypted_data


# Example usage:
if __name__ == "__main__":
    encrypt_decrypt = EncryptDecryptResponse()

    # Sample data to encrypt
    sample_data = '''
      {
        "AGGR_ID": "BULK0079",
        "AGGR_NAME": "bastar",
        "CORP_ID": "596778175",
        "USER_ID": "MOHAMMAD",
        "URN": "SR263840153",
        "UNIQUEID": "some_unique_id"
    }
    '''

    # Send the encrypted request and decrypt the response
    decrypted_response = encrypt_decrypt.send_encrypted_request(sample_data)
