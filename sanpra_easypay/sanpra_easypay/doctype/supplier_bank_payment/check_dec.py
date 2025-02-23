import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import unpad
import os

# Replace with the actual path to your private key file
current_path = os.path.dirname(os.path.abspath(__file__))
PRIVATE_KEY_FILE = os.path.join(current_path, "prod_priv_key.pem")

# Fix for base64 padding issues
def fix_base64_padding(data):
    return data + '=' * (4 - len(data) % 4)

# Decrypt the RSA encrypted key using your private RSA key
def decrypt_rsa_key(encrypted_key):
    try:
        with open(PRIVATE_KEY_FILE, "rb") as key_file:
            private_key_data = key_file.read()
            private_key = RSA.import_key(private_key_data)
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None

    encrypted_key = fix_base64_padding(encrypted_key)
    try:
        encrypted_key_bytes = base64.b64decode(encrypted_key)
    except Exception as e:
        print(f"Error decoding base64 for encrypted key: {e}")
        return None

    cipher = PKCS1_v1_5.new(private_key)
    session_key = cipher.decrypt(encrypted_key_bytes, None)

    if session_key:
        print(f"Decrypted session key: {session_key.hex()}")  # Print in hex format for clarity
    else:
        print("Session key decryption failed. It is empty.")
    return session_key


# Decrypt the AES-encrypted data using the decrypted RSA session key
def decrypt_aes_data(encrypted_data, session_key):
    try:
        encrypted_data_bytes = base64.b64decode(encrypted_data)
    except Exception as e:
        print(f"Error decoding base64 for encrypted data: {e}")
        return None
    
    # Extract IV and the actual encrypted data
    iv = encrypted_data_bytes[:16]  # First 16 bytes is the IV
    encrypted_data_bytes = encrypted_data_bytes[16:]  # The rest is the encrypted data

    # Decrypt using AES
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    try:
        decrypted_data = unpad(cipher.decrypt(encrypted_data_bytes), AES.block_size)
    except Exception as e:
        print(f"Error during AES decryption: {e}")
        return None
    
    return decrypted_data.decode('utf-8')

# Main function to handle the decryption
def main():
    encrypted_key = 'i1zpz3b19WuaHU6auPvlfv3GgMVn9ERWQd8yHpbCHGpIiBSKFUiiXjoLonhtqC5HYMdQ5s4v+OvhE2cPd6DF4ACWxoMTLDSJ/Z8JV+d+DC0LiReN1gfXfLqtKN6Y92k5Vb43qxIDqQbwuVroD2Rzy2PHeZIyqJgqncS9kW4Y+yb56IcD74X50Wf7puOiHzWmxRWiV9fewcIQVDOhulTBaSZHuvRQBwivt7rnPsh4aUbR9OOK9ZbAMY10Ed9FQDxlUHaRTLwSrYErNEo5ZcezBpFt+/048sZT64naetldud93F5LsnDmZ77TiAW9Pk0oX8YnkuZfjo4oiRmI/T8TsAG4U/C3syfFrKue0Meb5auBtlZTMw7d6z6qyTCXIe99vAptmL/e3Q8jgUO6yo1srmpWePPURDJiniI7TmREomh8qPrY1NOvi8aMlPrOQ/uUJw+tJ0maRcQ0Xn1K4etiCFJRUG2VNpb5kQV3oMsyrGisyYqCTfCgyFB+q13I7M8dvA5Dn/l1XXSCnEinY3wVX+A8DbgfCD/3DWSV+gHXadAGGX6PvCy1WlcddSFn/JSSeaybDdXydrNeHmdd+jJuS1efrWgMZmfheGoDW1bj7XyuinZmDuiognepqXqsM7By1tENC1XdOcgl2qNtnwXbx+JW73m3GQnd4Kr1ypKkoUGw='
    encrypted_data = 'd9ZkBuxpr0vz7mVKAiJspUvgo+/gtiCGl4yfOh+mb3/fcDgVFK58g01ULBDEf5gwHhP6Jq+Tc7X50hA6lFv0FQtYOfHYiqsdBZ3VHK9bEWw='

    # Step 1: Decrypt the RSA encrypted session key
    session_key = decrypt_rsa_key(encrypted_key)
    if session_key is None:
        print("Error decrypting RSA key.")
        return

    # Step 2: Decrypt the AES encrypted data using the session key
    decrypted_data = decrypt_aes_data(encrypted_data, session_key)
    if decrypted_data is None:
        print("Error decrypting AES data.")
        return

    print("Decrypted Data:", decrypted_data)

if __name__ == '__main__':
    main()
