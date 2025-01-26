import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import unpad

# Helper functions for decryption

def load_private_key(priv_key_file):
    """Load the private key from a PEM file."""
    with open(priv_key_file, 'r') as f:
        priv_key_pem = f.read()
    private_key = RSA.import_key(priv_key_pem)
    return private_key

def rsa_decrypt(private_key, encrypted_data):
    """Decrypt the RSA-encrypted data using the private key."""
    rsa_cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = rsa_cipher.decrypt(encrypted_data)
    return decrypted_data

def aes_decrypt(encrypted_data, key, iv):
    """AES decryption with CBC mode and PKCS5 unpadding."""
    aes_cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(aes_cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

def base64_decode(data):
    """Decode a base64 encoded string."""
    return base64.b64decode(data)

# Function to decrypt the final payload

def decrypt_payload(final_payload, private_key):
    """Decrypt the encrypted payload."""
    # Step 1: Decode Base64-encoded encryptedKey and iv from the final payload
    encrypted_key_b64 = final_payload['encryptedKey']
    iv_b64 = final_payload['iv']
    encrypted_data_b64 = final_payload['encryptedData']
    
    # Step 2: Base64-decode the encryptedKey, iv, and encryptedData
    encrypted_key = base64_decode(encrypted_key_b64)
    iv = base64_decode(iv_b64)
    encrypted_data = base64_decode(encrypted_data_b64)
    
    # Step 3: RSA decrypt the encryptedKey to get the AES key (RANDOMNO)
    aes_key = rsa_decrypt(private_key, encrypted_key)
    
    # Step 4: AES decrypt the encryptedData using the AES key and IV
    decrypted_data = aes_decrypt(encrypted_data, aes_key, iv)
    
    # Debugging: Print the decrypted key and decrypted data
    print("Decrypted Key (RANDOMNO):", aes_key.hex())  # Hex format to see the raw key
    print("Decrypted Data:", decrypted_data.decode('utf-8'))
    
    return aes_key, decrypted_data

# Example of using the decryption process

def main():
    # Path to the private key file
    script_dir = os.path.dirname(os.path.realpath(__file__))  # Get the current script directory
    pri_key_path = os.path.join(script_dir, 'pri_key.pem')  # Join the path with pub_key.pem
     # Update with the actual path
    
    # Example payload (the final payload you receive)
    final_payload = {"requestId":"","service":"CIB","oaepHashingAlgorithm":"NONE","encryptedKey":"S9LoAcGwawRqBBHAIHKlwUSdLhZDqsCaGpYKUwjI1OkJuG5Y1Hz7dD42djRm3Hs/Xl3zz/BhCRiigFS2HJqGg1pADSNcO1JfUPv8t2AM215tG3jXb8xKuSCB9XnUyOcQWfZpk8s8qpI5rgKywBHnJLx/hIKJ6zNWwAcREiP7e1mjl7nffiCL8YVmH3HjZD7LkUazAIP7dfWsJ+xryKmd/RlXM1tE12Eww+ixUWtyd9CPw1BG8THWXDbV8C1GO4Lvg+jryFPka9ldfpAnK3UJxnzpCoccUImCdasUIKtfknPQh1mFwlYP53DkPqDfZhmwWpBGOGANextYryruircfI7iEy2d/qTG5BUBZkIjYqJZAH2AyaH/4FA1j/PgtGiqjSzrlFTJCSAuefdV8aVIU6flHPn2Wc3PUFvwGbayS1ukUtu9qvF2OPb41yuc67Ebm+sQeVL9kSaZefWWrWN0sWSxVeYq0qs9PDTkFrh9YSeJVi4Cpy577DlrCANHIn0kJKsjPfPiOb87nE0z1vXlHINBJkrDkR6DOUMN2S0gIyj5l2oygJP/hhleN+QMf9m3twr3obdWOXiDkNRFqtBVU+Q78oZc1lK4qjuqtSF4v5wsyd8kBgWyPMPYDleLAZakk5ArIsNG/KLCcdgS9yRgjepji4R8xNvFUp6vv2f4TEbA=","encryptedData":"pLu1FbvLKB7N0SKbXc1lxgVnxSvDMxBJZ61A/hr91Z7ro1u6uDf5rJeiSq96Syop2suDjEHGOCih9V8jbXdfnIQ+ydCupzcfdlnXuMCUSELp6uVCzf2L/PuvfU0+zykTmTKPGVZjsyiKzkptFdKxELVvIu8dHnFqyP4JGZUkQjwAexFRy9w/GGCXMWPWb4OOsWCEnU2mkMupZ7Aovf5KuVm9jvrWq9in1gqWF8FOYsM="}
    private_key = load_private_key(pri_key_path)
    
    # Decrypt the payload
    decrypted_key, decrypted_data = decrypt_payload(final_payload, private_key) 

if __name__ == '__main__':
    main()
    