import base64
import json
import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import os


current_path = os.path.dirname(os.path.abspath(__file__))

PUBLIC_KEY_FILE = os.path.join(current_path, "server.crt") 
PRIVATE_KEY_FILE = os.path.join(current_path, "pri_key.pem") 
REVERSE_PAYMENT_URL = "https://apibankingonesandbox.icicibank.com/api/v1/ReverseMis"
API_KEY = "SHUyF6MtXmvgtW1OnsWS6VWt1nAu4J2e"

def check_payment_status(file_seq_no):
    session_key = "qqqqwwww11112224"
    iv = "aaaabbbbccccdddd"
    headers = {
        'Content-Type': 'application/json',
        'accept': '*/*',
        'APIKEY': API_KEY
    }
    payload = json.dumps({
    "AGGRID": "BULK0079",
    "CORPID": "SESPRODUCT",
    "USERID": "HARUN",
    "URN": "SR263840153",
    "UNIQUEID": "3",
    "FILESEQNUM":str(file_seq_no),
    "ISENCRYPTED":"N"
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
    print("request initiated")
    # print(payload)
    response = requests.post(REVERSE_PAYMENT_URL, headers=headers, data=json.dumps(payload))
    print(response)
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
        
        print(f"Reverse APi Response Data: {decrypted_data}")
        
check_payment_status(78836)