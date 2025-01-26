# import os
# import base64
# import requests
# from Crypto.PublicKey import RSA
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad
# from Crypto.Cipher import PKCS1_OAEP

# # Helper functions for encryption

# def generate_random_number():
#     """Generate a random 16-byte number (RANDOMNO)."""
#     return os.urandom(16)  # 16 bytes = 128 bits

# def rsa_encrypt(public_key, data):
#     """Encrypt data using RSA with public key and PKCS1_OAEP padding."""
#     rsa_cipher = PKCS1_OAEP.new(public_key)
#     encrypted_data = rsa_cipher.encrypt(data)
#     return encrypted_data

# def aes_encrypt(data, key, iv):
#     """AES encryption with CBC mode and PKCS5 padding."""
#     aes_cipher = AES.new(key, AES.MODE_CBC, iv)
#     encrypted_data = aes_cipher.encrypt(pad(data, AES.block_size))
#     return encrypted_data

# def base64_encode(data):
#     """Encode data in Base64."""
#     return base64.b64encode(data).decode('utf-8')

# def generate_iv():
#     """Generate an initialization vector for AES encryption."""
#     return os.urandom(16)  # 16 bytes for AES

# # Function to load the RSA public key from a .pem file
# def load_public_key(pub_key_file):
#     """Load the public key from a PEM file."""
#     with open(pub_key_file, 'r') as f:
#         pub_key_pem = f.read()
#     public_key = RSA.import_key(pub_key_pem)
#     return public_key

# # Encryption Process

# def encrypt_payload(payload, public_key):
#     """Encrypt payload following the given encryption steps."""
#     # Step 1: Generate a random 16-byte number (RANDOMNO)
#     random_number = generate_random_number()
    
#     # Step 2: Encrypt the RANDOMNO using the RSA public key
#     encrypted_key = rsa_encrypt(public_key, random_number)
    
#     # Step 3: Encrypt the payload using AES (CBC mode, PKCS5 Padding)
#     iv = generate_iv()  # Initialize random IV
#     encrypted_data = aes_encrypt(payload.encode('utf-8'), random_number, iv)
    
#     # Step 4: Base64 encode the IV and the encrypted data (option a)
#     iv_base64 = base64_encode(iv)
#     encrypted_data_base64 = base64_encode(encrypted_data)
#     encrypted_key_base64 = base64_encode(encrypted_key)
    
#     # Construct the final payload with the given structure
#     final_payload = {
#         "requestId": "",  
#         "service": "LOP",  
#         "encryptedKey": encrypted_key_base64,  
#         "oaepHashingAlgorithm": "NONE", 
#         "iv": iv_base64,  
#         "encryptedData": encrypted_data_base64, 
#         "clientInfo": "", 
#         "optionalParam": "" 
#     }

#     # Debugging: Check the full payload before sending
#     print("Final Payload:", final_payload)

#     return final_payload

# # API call to send OTP (assumed endpoint for OTP generation)
# def send_otp():
#     # UAT credentials
#     payload = {
#         "AGGRID": "BULK0079",
#         "AGGRNAME": "BASTAR",
#         "CORPID": "SESPRODUCT",
#         "USERID": "HARUN",
#         "URN": "SR263840153",
#         "UNIQUEID":"hello123"
#     }
    
#     # Get the file path of the current script and load the public key
#     script_dir = os.path.dirname(os.path.realpath(__file__))  # Get the current script directory
#     pub_key_path = os.path.join(script_dir, 'pub_key.pem')  # Join the path with pub_key.pem
    
#     # Load the public key from the .pem file
#     public_key = load_public_key(pub_key_path)
    
#     # Encrypt the payload
#     encrypted_payload = encrypt_payload(str(payload), public_key)
    
#     # Send the encrypted payload to the API
#     url = "https://apibankingonesandbox.icicibank.com/api/Corporate/CIB/v1/Create"
#     headers = {
#         'Content-Type': 'application/json',
#         'accept': '*/*',
#         'APIKEY': 'SHUyF6MtXmvgtW1OnsWS6VWt1nAu4J2e'  # Replace with actual API key
#     }
    
#     # Send encrypted data as JSON
#     response = requests.post(url, json=encrypted_payload, headers=headers)
    
#     # Print the status code and response text
#     print("Status Code:", response.status_code)
#     print("Response Text:", response.text)

# if __name__ == '__main__':
#     send_otp()

# ============================ Send Api + Decrypt Api Response Cdoe ===============================

import base64
import json
import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import frappe
import os


current_path = os.path.dirname(os.path.abspath(__file__))

PUBLIC_KEY_FILE = os.path.join(current_path, "server.crt") 
PRIVATE_KEY_FILE = os.path.join(current_path, "pri_key.pem") 
OTP_API_URL = "https://apibankingonesandbox.icicibank.com/api/Corporate/CIB/v1/Create"
PAYMENT_API_URL = "https://apibankingonesandbox.icicibank.com/api/v1/cibbulkpayment/bulkPayment"
REVERSE_PAYMENT_URL = "https://apibankingonesandbox.icicibank.com/api/v1/ReverseMis"
API_KEY = "SHUyF6MtXmvgtW1OnsWS6VWt1nAu4J2e"


@frappe.whitelist()
def get_otp():
    # Payload
    session_key = "qqqqwwww11112224"
    iv = "aaaabbbbccccdddd"
    payload = json.dumps({
        "AGGRID": "BULK0079",
        "AGGRNAME": "BASTAR",
        "CORPID": "SESPRODUCT",
        "USERID": "HARUN",
        "URN": "SR263840153",
        "UNIQUEID": "5"
    })

    # Encrypt payload and session key
    encrypted_data = None
    cipher = AES.new(session_key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    padded_data = pad(payload.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    encrypted_data = base64.b64encode(encrypted_data).decode('utf-8')

    encrypted_key = None
    with open(PUBLIC_KEY_FILE, 'rb') as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_v1_5.new(public_key)
    encrypted_key = cipher_rsa.encrypt(session_key.encode('utf-8'))
    encrypted_key = base64.b64encode(encrypted_key).decode('utf-8')

    print(f"Encrypted Key: {encrypted_key}")

    # Prepare final JSON payload
    final_json = {
        "requestId": "",
        "service": "LOP",
        "encryptedKey": encrypted_key,
        "oaepHashingAlgorithm": "NONE",
        "iv": base64.b64encode(iv.encode('utf-8')).decode('utf-8'),
        "encryptedData": encrypted_data,
        "clientInfo": "",
        "optionalParam": ""
    }

    # Print the final JSON
    print("Final Payload Sent to API:")
    frappe.msgprint(json.dumps(final_json, indent=4))

    # Send API request and get the response
    response = None
    headers = {
        'Content-Type': 'application/json',
        'accept': '*/*',
        'APIKEY': API_KEY
    }
    
    response = requests.post(OTP_API_URL, headers=headers, data=json.dumps(final_json))
    response = response.json()  

    if response:
        private_key = None
        with open(PRIVATE_KEY_FILE, "rb") as key_file:
            private_key = RSA.import_key(key_file.read())
            
        session_key = None
        encrypted_key_bytes = base64.b64decode(response["encryptedKey"])
        cipher = PKCS1_v1_5.new(private_key)
        session_key = cipher.decrypt(encrypted_key_bytes, None)
        session_key = session_key
        
        iv = base64.b64decode(response["encryptedData"])[:16]
        
        decrypted_data = None
        encrypted_data_bytes = base64.b64decode(response["encryptedData"])[16:]
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(encrypted_data_bytes), AES.block_size)
        decrypted_data = plaintext.decode("utf-8")
        
        frappe.msgprint(f"Decrypted Data: {decrypted_data}")
        # frappe.throw(str(decrypted_data))
        return decrypted_data
    
@frappe.whitelist()
def make_payment(otp):
    # frappe.throw(str(otp))
    session_key = "qqqqwwww11112224"
    iv = "aaaabbbbccccdddd"
    headers = {
        'Content-Type': 'application/json',
        'accept': '*/*',
        'APIKEY': API_KEY
    }

    sample_str = "FHR|7|01/21/2025|salsts312|33|INR|000405002777|0011^MDR|000405002777|0011|Munna|33|INR|sals1t1|ICIC0000011|WIB^MCW|000451000301|0004|renu|1|INR|HARUN|ICIC0000011|WIB^MCW|041101518240|0411|renu|1|INR|BASHA|ICIC0000011|WIB^MCW|000451000301|0004|renu|1|INR|ABDULLA|ICIC0000011|WIB^MCO|000405001257|0011|RAKESH|9|INR|OTHERTEST1|NFT|DLXB0000092^MCO|000405001257|0011|RAKESH|11|INR|OTHERTEST|NFT|DLXBkkk00092^MCO|000405001257|0011|RAKESH|10|INR|OTHERTEST1|NFT|DLXB0000092^"
    encoded_str = base64.b64encode(sample_str.encode("utf-8")).decode("utf-8")
    # bank_str = "RkhSfDd8MDEvMTgvMjAyNXxzYWxzdHMzMTJ8MzN8SU5SfDAwMDQwNTAwMjc3N3wwMDExXg0KTURSfDAwMDQwNTAwMjc3N3wwMDExfE11bm5hfDMzfElOUnxzYWxzMXQxfElDSUMwMDAwMDExfFdJQl4NCk1DV3wwMDA0NTEwMDAzMDF8MDAwNHxyZW51fDF8SU5SfEhBUlVOfElDSUMwMDAwMDExfFdJQl4NCk1DV3wwNDExMDE1MTgyNDB8MDQxMXxyZW51fDF8SU5SfEJBU0hBfElDSUMwMDAwMDExfFdJQl4NCk1DV3wwMDA0NTEwMDAzMDF8MDAwNHxyZW51fDF8SU5SfEFCRFVMTEF8SUNJQzAwMDAwMTF8V0lCXg0KTUNPfDAwMDQwNTAwMTI1N3wwMDExfFJBS0VTSHw5fElOUnxPVEhFUlRFU1QxfE5GVHxETFhCMDAwMDA5Ml4NCk1DT3wwMDA0MDUwMDEyNTd8MDAxMXxSQUtFU0h8MTF8SU5SfE9USEVSVEVTVHxORlR8RExYQmtrazAwMDkyXg0KTUNPfDAwMDQwNTAwMTI1N3wwMDExfFJBS0VTSHwxMHxJTlJ8T1RIRVJURVNUMXxORlR8RExYQjAwMDAwOTJe"
    # frappe.msgprint(str(encoded_str))

    payload = json.dumps({
    "AGGR_ID": "BULK0079",
    "AGGR_NAME": "BASTAR",
    "CORP_ID": "SESPRODUCT",
    "USER_ID": "HARUN",
    "URN": "SR263840153",
    "UNIQUE_ID": "5",
    "FILE_DESCRIPTION": "TEST FILE",
    "AGOTP": otp,
    "FILE_NAME": "125.txt",
    "FILE_CONTENT": str(encoded_str)  
})
    frappe.msgprint(str(payload))
    # Encrypt payload and session key
    encrypted_data = None
    cipher = AES.new(session_key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    padded_data = pad(payload.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    encrypted_data = base64.b64encode(encrypted_data).decode('utf-8')
    # print(encrypted_data)
    encrypted_key = None
    with open(PUBLIC_KEY_FILE, 'rb') as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_v1_5.new(public_key)
    encrypted_key = cipher_rsa.encrypt(session_key.encode('utf-8'))
    encrypted_key = base64.b64encode(encrypted_key).decode('utf-8')

    # print(f"Encrypted Key: {encrypted_key}")

    payload = {
        "requestId": "",
        "service": "LOP",
        "encryptedKey": encrypted_key,
        "oaepHashingAlgorithm": "NONE",
        "iv": base64.b64encode(iv.encode('utf-8')).decode('utf-8'),
        "encryptedData": encrypted_data,
        "clientInfo": "",
        "optionalParam": ""
    }
    
    # frappe.msgprint(str(payload))
    response = requests.post(PAYMENT_API_URL, headers=headers, data=json.dumps(payload))
    response.raise_for_status()


    if response:
        response = response.json()
    
        private_key = None
        with open(PRIVATE_KEY_FILE, "rb") as key_file:
            private_key = RSA.import_key(key_file.read())
            
        session_key = None
        encrypted_key_bytes = base64.b64decode(response["encryptedKey"])
        cipher = PKCS1_v1_5.new(private_key)
        session_key = cipher.decrypt(encrypted_key_bytes, None)
        session_key = session_key
        
        iv = base64.b64decode(response["encryptedData"])[:16]
        
        decrypted_data = None
        encrypted_data_bytes = base64.b64decode(response["encryptedData"])[16:]
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(encrypted_data_bytes), AES.block_size)
        decrypted_data = plaintext.decode("utf-8")
        
        frappe.msgprint(f"Decrypted Data: {decrypted_data}")
        # check_payment_status(78781)
        
def check_payment_status(file_seq_no):
    session_key = "qqqqwwww11112224"
    iv = "aaaabbbbccccdddd"
    headers = {
        'Content-Type': 'application/json',
        'accept': '*/*',
        'APIKEY': API_KEY
    }
    payload = json.dumps({
    "AGGR_ID": "BULK0079",
    "CORP_ID": "SESPRODUCT",
    "USER_ID": "HARUN",
    "URN": "SR263840153",
    "UNIQUE_ID": "5",
    "FILE_SEQ_NUM":"78781",
    "IS_ENCRYPTED":"N"
})
    encrypted_data = None
    cipher = AES.new(session_key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    padded_data = pad(payload.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    encrypted_data = base64.b64encode(encrypted_data).decode('utf-8')
    # print(encrypted_data)
    encrypted_key = None
    with open(PUBLIC_KEY_FILE, 'rb') as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_v1_5.new(public_key)
    encrypted_key = cipher_rsa.encrypt(session_key.encode('utf-8'))
    encrypted_key = base64.b64encode(encrypted_key).decode('utf-8')

    payload = {
        "requestId": "",
        "service": "LOP",
        "encryptedKey": encrypted_key,
        "oaepHashingAlgorithm": "NONE",
        "iv": base64.b64encode(iv.encode('utf-8')).decode('utf-8'),
        "encryptedData": encrypted_data,
        "clientInfo": "",
        "optionalParam": ""
    }
    response = requests.post(REVERSE_PAYMENT_URL, headers=headers, data=json.dumps(payload))
    response.raise_for_status()


    if response:
        response = response.json()
    
        private_key = None
        with open(PRIVATE_KEY_FILE, "rb") as key_file:
            private_key = RSA.import_key(key_file.read())
            
        session_key = None
        encrypted_key_bytes = base64.b64decode(response["encryptedKey"])
        cipher = PKCS1_v1_5.new(private_key)
        session_key = cipher.decrypt(encrypted_key_bytes, None)
        session_key = session_key
        
        iv = base64.b64decode(response["encryptedData"])[:16]
        
        decrypted_data = None
        encrypted_data_bytes = base64.b64decode(response["encryptedData"])[16:]
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(encrypted_data_bytes), AES.block_size)
        decrypted_data = plaintext.decode("utf-8")
        
        frappe.msgprint(f"Reverse Data: {decrypted_data}")
    
    # except requests.exceptions.RequestException as e:
    #     print(f"An error occurred: {e}")

    
        

# #    Run the main function
# if __name__ == "__main__":
#     session_key = "qqqqwwww11112222"
#     iv = "aaaabbbbccccdddd"

#     # Payload
#     payload = json.dumps({
#         "AGGRID": "BULK0079",
#         "AGGRNAME": "BASTAR",
#         "CORPID": "SESPRODUCT",
#         "USERID": "HARUN",
#         "URN": "SR263840153",
#         "UNIQUEID": "hello124"
#     })

#     # Encrypt payload and session key
#     encrypted_data = None
#     cipher = AES.new(session_key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
#     padded_data = pad(payload.encode('utf-8'), AES.block_size)
#     encrypted_data = cipher.encrypt(padded_data)
#     encrypted_data = base64.b64encode(encrypted_data).decode('utf-8')

#     encrypted_key = None
#     with open(PUBLIC_KEY_FILE, 'rb') as f:
#         public_key = RSA.import_key(f.read())
#     cipher_rsa = PKCS1_v1_5.new(public_key)
#     encrypted_key = cipher_rsa.encrypt(session_key.encode('utf-8'))
#     encrypted_key = base64.b64encode(encrypted_key).decode('utf-8')

#     print(f"Encrypted Key: {encrypted_key}")

#     final_json = {
#         "requestId": "",
#         "service": "LOP",
#         "encryptedKey": encrypted_key,
#         "oaepHashingAlgorithm": "NONE",
#         "iv": base64.b64encode(iv.encode('utf-8')).decode('utf-8'),
#         "encryptedData": encrypted_data,
#         "clientInfo": "",
#         "optionalParam": ""
#     }

#     print("Final Payload Sent to API:")
#     print(json.dumps(final_json, indent=4))

#     response = None
#     headers = {
#         'Content-Type': 'application/json',
#         'accept': '*/*',
#         'APIKEY': API_KEY
#     }
#     response = requests.post(API_URL, headers=headers, data=json.dumps(final_json))
#     print(f"Response Code: {response.status_code}")
#     print(f"Response Body: {response.text}")
#     response = response.json()  # Return the parsed JSON response
    

#     if response:
#         # try:
#             # Decryption Process
#         private_key = None
#         with open(PRIVATE_KEY_FILE, "rb") as key_file:
#             private_key = RSA.import_key(key_file.read())
            
#         session_key = None
#         encrypted_key_bytes = base64.b64decode(response["encryptedKey"])
#         cipher = PKCS1_v1_5.new(private_key)
#         session_key = cipher.decrypt(encrypted_key_bytes, None)
#         session_key = session_key
        
#         iv = base64.b64decode(response["encryptedData"])[:16]
        
#         decrypted_data = None
#         encrypted_data_bytes = base64.b64decode(response["encryptedData"])[16:]
#         cipher = AES.new(session_key, AES.MODE_CBC, iv)
#         plaintext = unpad(cipher.decrypt(encrypted_data_bytes), AES.block_size)
#         decrypted_data = plaintext.decode("utf-8")
        
#         print(f"Decrypted Data: {decrypted_data}")
#         # frappe.throw(str(decrypted_data))
#         # return decrypted_data

# # ========









# ======================= Successful Api Request Code =====================================

# import base64
# import json
# import requests
# from Crypto.Cipher import AES, PKCS1_v1_5
# from Crypto.PublicKey import RSA
# from Crypto.Util.Padding import pad
# from Crypto.Random import get_random_bytes
# from Crypto.Hash import SHA256
# from Crypto.Signature import pkcs1_15

# # Encryption Configurations
# SYMM_CIPHER = "AES/CBC/PKCS5Padding"
# ASYMM_CIPHER = "RSA/ECB/PKCS1Padding"
# PUBLIC_KEY_FILE = "server.crt"
# API_URL = "https://apibankingonesandbox.icicibank.com/api/Corporate/CIB/v1/Create"
# API_KEY = "SHUyF6MtXmvgtW1OnsWS6VWt1nAu4J2e"

# # Function to encrypt payload using AES
# def encrypt_symmetric(session_key, iv, payload):
#     try:
#         cipher = AES.new(session_key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
#         padded_data = pad(payload.encode('utf-8'), AES.block_size)
#         encrypted_data = cipher.encrypt(padded_data)
#         # iv_and_encrypted_data = iv.encode('utf-8') + encrypted_data
#         iv_and_encrypted_data = encrypted_data
#         return base64.b64encode(iv_and_encrypted_data).decode('utf-8')
#     except Exception as e:
#         print(f"Symmetric Encryption Error: {e}")
#         return None

# # Function to encrypt session key using RSA
# def encrypt_asymmetric(session_key, public_key_path):
#     try:
#         with open(public_key_path, 'rb') as f:
#             public_key = RSA.import_key(f.read())
#         cipher_rsa = PKCS1_v1_5.new(public_key)
#         encrypted_key = cipher_rsa.encrypt(session_key.encode('utf-8'))
#         return base64.b64encode(encrypted_key).decode('utf-8')
#     except Exception as e:
#         print(f"Asymmetric Encryption Error: {e}")
#         return None

# # Function to make API call
# def send_api_request(final_json):
#     headers = {
#         'Content-Type': 'application/json',
#         'accept': '*/*',
#         'APIKEY': API_KEY
#     }
#     try:
#         # print(f"final_json {final_json}")
#         response = requests.post(API_URL, headers=headers, data=json.dumps(final_json))
#         print(f"Response Code: {response.status_code}")
#         print(f"Response Body: {response.text}")
#     except Exception as e:
#         print(f"API Request Error: {e}")

# # Main Function
# def main():
#     # Random session key and IV
#     session_key = "qqqqwwww11112222"
#     iv = "aaaabbbbccccdddd"

#     # Payload
#     payload = json.dumps({
#         "AGGRID": "BULK0079",
#         "AGGRNAME": "BASTAR",
#         "CORPID": "SESPRODUCT",
#         "USERID": "HARUN",
#         "URN": "SR263840153",
#         "UNIQUEID": "hello123"
#     })

#     # Encrypt payload and session key
#     encrypted_data = encrypt_symmetric(session_key, iv, payload)
#     encrypted_key = encrypt_asymmetric(session_key, PUBLIC_KEY_FILE)
#     print(f"encrypted_key {encrypted_key}")
#     # Prepare final JSON payload
#     final_json = {
#         "requestId": "",
#         "service": "LOP",
#         "encryptedKey": encrypted_key,
#         "oaepHashingAlgorithm": "NONE",
#         "iv": base64.b64encode(iv.encode('utf-8')).decode('utf-8'),
#         "encryptedData": encrypted_data,
#         "clientInfo": "",
#         "optionalParam": ""
#     }

#     # Print the final JSON
#     print(json.dumps(final_json, indent=4))

#     # Send API request
#     send_api_request(final_json)

# # Run the main function
# if __name__ == "__main__":
#     main()



# =======================================================================

# import base64
# import json
# import requests
# from Crypto.Cipher import AES, PKCS1_v1_5
# from Crypto.PublicKey import RSA
# from Crypto.Util.Padding import pad, unpad



# PUBLIC_KEY_FILE = "server.crt"
# PRIVATE_KEY_FILE = "pri_key.pem"
# API_URL = "https://apibankingonesandbox.icicibank.com/api/Corporate/CIB/v1/Create"
# API_KEY = "SHUyF6MtXmvgtW1OnsWS6VWt1nAu4J2e"

# # Encryption Functions
# def encrypt_symmetric(session_key, iv, payload):
#     try:
#         cipher = AES.new(session_key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
#         padded_data = pad(payload.encode('utf-8'), AES.block_size)
#         encrypted_data = cipher.encrypt(padded_data)
#         return base64.b64encode(encrypted_data).decode('utf-8')
#     except Exception as e:
#         print(f"Symmetric Encryption Error: {e}")
#         return None

# def encrypt_asymmetric(session_key, public_key_path):
#     try:
#         with open(public_key_path, 'rb') as f:
#             public_key = RSA.import_key(f.read())
#         cipher_rsa = PKCS1_v1_5.new(public_key)
#         encrypted_key = cipher_rsa.encrypt(session_key.encode('utf-8'))
#         return base64.b64encode(encrypted_key).decode('utf-8')
#     except Exception as e:
#         print(f"Asymmetric Encryption Error: {e}")
#         return None

# # API Request Function
# def send_api_request(final_json):
#     headers = {
#         'Content-Type': 'application/json',
#         'accept': '*/*',
#         'APIKEY': API_KEY
#     }
#     try:
#         response = requests.post(API_URL, headers=headers, data=json.dumps(final_json))
#         print(f"Response Code: {response.status_code}")
#         print(f"Response Body: {response.text}")
#         return response.json()  # Return the parsed JSON response
#     except Exception as e:
#         print(f"API Request Error: {e}")
#         return None

# # Decryption Functions
# def load_private_key(private_key_file):
#     with open(private_key_file, "rb") as key_file:
#         return RSA.import_key(key_file.read())

# def decrypt_session_key(encrypted_key, private_key):
#     encrypted_key_bytes = base64.b64decode(encrypted_key)
#     cipher = PKCS1_v1_5.new(private_key)
#     session_key = cipher.decrypt(encrypted_key_bytes, None)
#     return session_key

# def decrypt_data(encrypted_data, session_key, iv):
#     encrypted_data_bytes = base64.b64decode(encrypted_data)[16:]
#     cipher = AES.new(session_key, AES.MODE_CBC, iv)
#     plaintext = unpad(cipher.decrypt(encrypted_data_bytes), AES.block_size)
#     return plaintext.decode("utf-8")

# def send_bulk_payment_request():
#     pass

# # Main Function
# def main():
#     # Random session key and IV
#     session_key = "qqqqwwww11112222"
#     iv = "aaaabbbbccccdddd"

#     # Payload
#     payload = json.dumps({
#         "AGGRID": "BULK0079",
#         "AGGRNAME": "BASTAR",
#         "CORPID": "SESPRODUCT",
#         "USERID": "HARUN",
#         "URN": "SR263840153",
#         "UNIQUEID": "hello123"
#     })

#     # Encrypt payload and session key
#     encrypted_data = encrypt_symmetric(session_key, iv, payload)
#     encrypted_key = encrypt_asymmetric(session_key, PUBLIC_KEY_FILE)
#     print(f"Encrypted Key: {encrypted_key}")

#     # Prepare final JSON payload
#     final_json = {
#         "requestId": "",
#         "service": "LOP",
#         "encryptedKey": encrypted_key,
#         "oaepHashingAlgorithm": "NONE",
#         "iv": base64.b64encode(iv.encode('utf-8')).decode('utf-8'),
#         "encryptedData": encrypted_data,
#         "clientInfo": "",
#         "optionalParam": ""
#     }

#     # Print the final JSON
#     print("Final Payload Sent to API:")
#     print(json.dumps(final_json, indent=4))

#     # Send API request and get the response
#     response = send_api_request(final_json)
#     if response:
#         try:
#             # Decryption Process
#             private_key = load_private_key(PRIVATE_KEY_FILE)
#             session_key = decrypt_session_key(response["encryptedKey"], private_key)
#             iv = base64.b64decode(response["encryptedData"])[:16]
#             decrypted_data = decrypt_data(response["encryptedData"], session_key,iv)
#             print(f"Decrypted Data: {decrypted_data}")
            
#             status = send_bulk_payment_request()
#             return decrypted_data
#         except Exception as e:
#             print(f"Decryption Error: {e}")

# #    Run the main function
# if __name__ == "__main__":
#     main()