import base64
import json
import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
# import frappe
import os

current_path = os.path.dirname(os.path.abspath(__file__))
PUBLIC_KEY_FILE = os.path.join(current_path, "server.crt") 
PRIVATE_KEY_FILE = os.path.join(current_path, "pri_key.pem") 
API_URL = "https://apibankingonesandbox.icicibank.com/api/Corporate/CIB/v1/Create"
# API_URL = "https://apibankingonesandbox.icicibank.com/api/v1/cibbulkpayment/bulkPayment"
API_KEY = "SHUyF6MtXmvgtW1OnsWS6VWt1nAu4J2e"
#    Run the main function
if __name__ == "__main__":
    session_key = "qqqqwwww11112222"
    iv = "aaaabbbbccccdddd"

    # Payload
    # payload = json.dumps({
    #     "AGGRID": "BULK0079",
    #     "AGGRNAME": "BASTAR",
    #     "CORPID": "SESPRODUCT",
    #     "USERID": "HARUN",
    #     "URN": "SR263840153",
    #     "UNIQUEID": "hello124"
    # })
    bank_str = "RkhSfDd8MDEvMTgvMjAyNXxzYWxzdHMzMTJ8MzN8SU5SfDAwMDQwNTAwMjc3N3wwMDExXg0KTURSfDAwMDQwNTAwMjc3N3wwMDExfE11bm5hfDMzfElOUnxzYWxzMXQxfElDSUMwMDAwMDExfFdJQl4NCk1DV3wwMDA0NTEwMDAzMDF8MDAwNHxyZW51fDF8SU5SfEhBUlVOfElDSUMwMDAwMDExfFdJQl4NCk1DV3wwNDExMDE1MTgyNDB8MDQxMXxyZW51fDF8SU5SfEJBU0hBfElDSUMwMDAwMDExfFdJQl4NCk1DV3wwMDA0NTEwMDAzMDF8MDAwNHxyZW51fDF8SU5SfEFCRFVMTEF8SUNJQzAwMDAwMTF8V0lCXg0KTUNPfDAwMDQwNTAwMTI1N3wwMDExfFJBS0VTSHw5fElOUnxPVEhFUlRFU1QxfE5GVHxETFhCMDAwMDA5Ml4NCk1DT3wwMDA0MDUwMDEyNTd8MDAxMXxSQUtFU0h8MTF8SU5SfE9USEVSVEVTVHxORlR8RExYQmtrazAwMDkyXg0KTUNPfDAwMDQwNTAwMTI1N3wwMDExfFJBS0VTSHwxMHxJTlJ8T1RIRVJURVNUMXxORlR8RExYQjAwMDAwOTJe"

    payload = json.dumps({
    "AGGR_ID": "BULK0079",
    "AGGR_NAME": "BASTAR",
    "CORP_ID": "SESPRODUCT",
    "USER_ID": "HARUN",
    "URN": "SR263840153",
    "UNIQUE_ID": "680747",
    "FILE_DESCRIPTION": "TEST FILE",
    "AGOTP": "416485",
    "FILE_NAME": "11111.txt",
    "FILE_CONTENT": str(bank_str)  
})

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

    print("Final Payload Sent to API:")
    print(json.dumps(final_json, indent=4))

    response = None
    headers = {
        'Content-Type': 'application/json',
        'accept': '*/*',
        'APIKEY': API_KEY
    }
    response = requests.post(API_URL, headers=headers, data=json.dumps(final_json))
    # print(f"Response Code: {response.status_code}")
    # print(f"Response Body: {response.text}")
    response = {'requestId': '', 'encryptedKey': 'tP2M+Rjr2F0wWD1bv2LhdzNPNGrRzI+uBU51/EhifYAZHrQ4NrHlbEkZJYHvvXEZr2VEnMXLfJdU3TaSizlhcWMrx1oJXr5g9iX69J2KdUrvJtvImk5grXDbByr53lSOff6p9u5w79HlsZXz0UuCT1IcK0pYc/zaJWiFoVzj8Qvp7MipRut01FFRrCJhba3YHx7yPrM3C80RsqW5Vz0D14S5CaVrqiF/aQRU5KqPyfcwzfGcwUPrez/Io+Eu2iirfvnMfH7AlWIU+bwe2vzOqSEIQiBwpkmpk6BUHVg5zCLs0DO5bFVYtEf+ImsaNZUukUaaxR/aD7tUdGuUUFoV/UtyvjJJmTq+8LmSaZZQsx2y/EzDAZLHTftgPH8WEZ2bdJyyOiihQV6CS9B6lSbDj5Tjinthy4eYkIh44GUmORJIh4iHpVzVHCnGc1TXMLhOqb0Q617P0KghQw3EW7TXgFKBg4OVcszCxLe2ccFohu9YbrfdmI1ptaVCJ4BpzbZgkESvHr881lGpNTMnBdiZwS7GgUgr9TWoZAHuC3e0n7dtmLqE3U8V5w0KKnC5hDFmXMxLZYRaPrFJsRkipVjlFFLe9lfd8x+wXTW3Q9yNpU6d3rXiOsRKTxOJiDXVGaEQBTna79cXfzHPDikIbAMec6x3yw4ZxoyZcQcg1QBzxyw=', 'encryptedData': 'fYp7feouTmzV2a9jf0I3Uv4AGuNDKSlzY4Xv2nzP31JDgEvhDuoMUS4UfXlNIxaKf27x3IM/X95aBZYdYEvARZoJpClwyYBa5625GYZ5pVHf9TMqkv9IVRWM5ARA2eSA'}
    # response = response.json()  # Return the parsed JSON response

    if response:
        # try:
            # Decryption Process
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
        
        print(f"Decrypted Data: {decrypted_data}")
        # frappe.throw(str(decrypted_data))
        # return decrypted_data