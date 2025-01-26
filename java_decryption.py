import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.Padding import unpad

# Load the private key
def load_private_key(priv_key_file):
    with open(priv_key_file, 'r') as f:
        private_key = RSA.import_key(f.read())
    return private_key

# RSA decryption using PKCS1Padding
def rsa_decrypt(private_key, encrypted_data):
    rsa_cipher = PKCS1_v1_5.new(private_key)
    decrypted_data = rsa_cipher.decrypt(encrypted_data, None)
    return decrypted_data

# AES decryption with CBC mode and PKCS7 unpadding
def aes_decrypt(encrypted_data, key, iv):
    aes_cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(aes_cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

# Base64 decoding helper
def base64_decode(data):
    return base64.b64decode(data)

# Decrypt the payload
def decrypt_payload(final_payload, private_key):
    # Decode Base64-encoded components
    encrypted_key = base64_decode(final_payload['encryptedKey'])
    iv = base64_decode(final_payload['iv'])
    encrypted_data = base64_decode(final_payload['encryptedData'])

    # RSA decrypt the encrypted key to get the AES session key
    aes_key = rsa_decrypt(private_key, encrypted_key)

    # AES decrypt the data
    decrypted_data = aes_decrypt(encrypted_data, aes_key, iv)

    return aes_key, decrypted_data

# Main function
def main():
    # Path to the private key file
    pri_key_path = 'sanpra_easypay/pri_key.pem'  # Update to the actual private key path

    # Example payload
    final_payload = {
    "requestId": "",
    "service": "LOP",
    "encryptedKey": "yH5HpkOFZrwo0NWViiITui0QF62ITPM+lm7jzuj3e6PEniJDlUf6HBoFyW0Y1PEVQMRBweeqNTo4eZ2HsvIEVX9vLE6HgLFpqHsHc0XVtDSwtA92w6FFT8oEGwK7+NBc62OHsn3mrJGWBWP8wJOf/zTzIJMsfUq3WxQ1/o7wXv1ocFoymtiHnmxqT9n9lx4NmjVLjMF5YdLaWBkWlWXEBgWcnTORgCuXISn/mYPY79prrA3kb7+rAd4KodSt73pQV8osQsVWVX0gbQ59sbQTxGDgMkjx1SEQbqO0f58m4BvmqxfMM/0eKvC/DBE+/fweQUGJyN+7JfKKwxW1XX1YZYOm6intxsfP/LEkKmnIfY5sF3B3SoMKYNBtNFc5UY9jKE1wS8biYHt4PK/Ad+pOqexWC+hIXMWV1ti8+jjDsbdsydKMx7tk6ZnBiib3xhN2cw/+3EtxeJlu4KJMCrt2w1MIdsTxNAzVTb7wO2J/lj7KSDeQkKfFzdwP450Hd/cl8FQF77RbPHvFdHpm5xyCWdDetf6lBwZrZ38sCTCZiWQCE79/lLnRKdKZEV6mJuyXMwITPJw3eb0hxPw5uESn/zgCr9NHG4rTKl5c5EPT4U+FCfXcg//v1D2LLFM2edWUE6HV8whjRbCfXkq8WgKUQPmlZtK9ev3a8hAhpmh6iuE=",
    "oaepHashingAlgorithm": "NONE",
    "iv": "YWFhYWJiYmJjY2NjZGRkZA==",
    "encryptedData": "YWFhYWJiYmJjY2NjZGRkZGs/7t7EiBIyrJc4kWgm5zQUwga+ZjOLdEpqz7a2YW32UpaDSz8UgkTuErIDXO/GGf9J7EP6fZROLckMxtR5KTUKVW6vMibAwxsiMileL3phjJntMTvWPTouVeYSpTN7QbcgFMPOdl2XmzQPERjEjn6OgKqDApxAkJmFLncdE5J8",
    "clientInfo": "",
    "optionalParam": ""
}

    # Load the private key
    private_key = load_private_key(pri_key_path)

    # Decrypt the payload
    decrypted_key, decrypted_data = decrypt_payload(final_payload, private_key)

    print("Decrypted Key (Session Key):", decrypted_key.decode())
    print("Decrypted Data:", decrypted_data)

if __name__ == '__main__':
    main()
