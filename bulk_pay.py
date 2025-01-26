import requests
import json
import base64
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
# import frappe
import os

API_URL = "https://apibankingonesandbox.icicibank.com/api/v1/cibbulkpayment/bulkPayment"
API_KEY = "SHUyF6MtXmvgtW1OnsWS6VWt1nAu4J2e"
current_path = os.path.dirname(os.path.abspath(__file__))
PUBLIC_KEY_FILE = os.path.join(current_path, "server.crt") 
PRIVATE_KEY_FILE = os.path.join(current_path, "pri_key.pem") 


headers = {
    'Content-Type': 'application/json',
    'accept': '*/*',
    'APIKEY': API_KEY
}

sample_str = """
    FHR|7|01/16/2025|salsts312|33|INR|000405002777|0011^
    MDR|000405002777|0011|Munna|33|INR|sals1t1|ICIC0000011|WIB^
    MCW|000451000301|0004|renu|1|INR|HARUN|ICIC0000011|WIB^
    MCW|041101518240|0411|renu|1|INR|BASHA|ICIC0000011|WIB^
    MCW|000451000301|0004|renu|1|INR|ABDULLA|ICIC0000011|WIB^
    MCO|000405001257|0011|RAKESH|9|INR|OTHERTEST1|NFT|DLXB0000092^
    MCO|000405001257|0011|RAKESH|11|INR|OTHERTEST|NFT|DLXBkkk00092^
    MCO|000405001257|0011|RAKESH|10|INR|OTHERTEST1|NFT|DLXB0000092^
"""

encoded_str = base64.b64encode(sample_str.encode("utf-8")).decode("utf-8")
bank_str = "RkhSfDd8MDEvMTgvMjAyNXxzYWxzdHMzMTJ8MzN8SU5SfDAwMDQwNTAwMjc3N3wwMDExXg0KTURSfDAwMDQwNTAwMjc3N3wwMDExfE11bm5hfDMzfElOUnxzYWxzMXQxfElDSUMwMDAwMDExfFdJQl4NCk1DV3wwMDA0NTEwMDAzMDF8MDAwNHxyZW51fDF8SU5SfEhBUlVOfElDSUMwMDAwMDExfFdJQl4NCk1DV3wwNDExMDE1MTgyNDB8MDQxMXxyZW51fDF8SU5SfEJBU0hBfElDSUMwMDAwMDExfFdJQl4NCk1DV3wwMDA0NTEwMDAzMDF8MDAwNHxyZW51fDF8SU5SfEFCRFVMTEF8SUNJQzAwMDAwMTF8V0lCXg0KTUNPfDAwMDQwNTAwMTI1N3wwMDExfFJBS0VTSHw5fElOUnxPVEhFUlRFU1QxfE5GVHxETFhCMDAwMDA5Ml4NCk1DT3wwMDA0MDUwMDEyNTd8MDAxMXxSQUtFU0h8MTF8SU5SfE9USEVSVEVTVHxORlR8RExYQmtrazAwMDkyXg0KTUNPfDAwMDQwNTAwMTI1N3wwMDExfFJBS0VTSHwxMHxJTlJ8T1RIRVJURVNUMXxORlR8RExYQjAwMDAwOTJe"
# print(encoded_str)
# payload = json.dumps({
#     "AGGR_ID": "BULK0079",
#     "AGGR_NAME": "BASTAR",
#     "CORP_ID": "SESPRODUCT",
#     "USER_ID": "HARUN",
#     "URN": "SR263840153",
#     "UNIQUE_ID": "680747",
#     "FILE_DESCRIPTION": "TEST FILE",
#     "AGOTP": "764575",
#     "FILE_NAME": "11111.txt",
#     "FILE_CONTENT": str(bank_str)  
# })
payload = json.dumps({
    "requestId": "",
    "service": "LOP",
    "encryptedKey": "YsyTH0g5NqEUFMGm0KJ0tfeG0XaL/jCXyMCcMotJPZpnA/aTXe9lRt7IcbjH1kBIlejQP4jXscQzIO+KZIIOFBCPyE3+D2wiskEnVyT2sgn2otY8vmI0j+izSOYotcdSJxRrngl8dfG9NDdtDEorzS/NkAYFi34m6m7SQPUNTHlRGu2l8cHqBR8NnXLCInV+M6hMlZKL/Sn8R/66guBbWm89tWkR7lMr3HWwnltMB2HzGtemZehf19eQ+X0mKxz9bKIo8RwQF7qDh39Cs8Rr1+IRDsZZBrzCzKcXhR5TZQbUa66vvrYiP3Zi59jWat6+kX3zh+A8YcFPulf3fBlrHBO6qIRgro5Q46pcuoMDzO6aqUUMOYpgiuJMT/ZB+7OsqPQacJO7YOJeDgxcnmTCugaXdd1W5VMID8Ios6kmzgztN1cWwjjjDKJHoURRr2OHrolMUMm2oUF0e5mgPiOlR2jLWGqM5UeUL3icLs39FSmIW6j9cNnJgHDJEaqTaavYB4DCly7joAvROb4I3IUmbf4udwUiGlaQXhJzFvhe1MiiLfIVCMmORuBO0e6k31qoItRqY13+vqMm0BsWhKo9zJpx5M3/OnElusubxWMn+/b6XE499PlCZPCanaedqblCaZd8JIWIEtgD6ePELLm0OLyoop0iq+zPuqpnHYv+pCE=",
    "oaepHashingAlgorithm": "NONE",
    "iv": "YWFhYWJiYmJjY2NjZGRkZA==",
    "encryptedData": "5E988p7bq4HpbQ9GFkOopcs8x1k/ZR31PWqmoOQpbZowOA/JKAFYpl6Rk0AxqzlVaOvGvu+96pZRQoRbqqvOLTyLihMoaIkbDavH8GUmxxjmfwMJhjdZGYIU3umfBX9Okrjs8rstopgs4A1NVxbBIUhyKFje1aX+Y1Fb5KnihqaT2YI0qa3XG+Q782dCAAs/m7qnFWMzClsCDjgt60SNzrkhggkntgYnRTBZXNB0kyn/tZko2f2V63M7gVanx6ZF6duGfIuZBlfKwxZznhSGASgVX4ATN+8cgfROlQXdIHf1iVlae0pNekvQUCOQuiPu42XztXVuJBt8jI3CDYUWr+ccEJN7M+Iu5S/KZuGhqQMB60P4vbIS61L3DT6t76GMDQOOuATEgIXY/BWYxNXI+g11scH57/aT/5JWG0FB+kjbiSh6RAiHh0kK2gvSHHXj1BwS3bO98UbiHML2s3oh2oJMZOaEYTM6KO9+Uwq6dZqV0FK1az081cxNTTqLx6YNLjKwcfK7XKHuz2eWpwzUFYzlr2nmnWu0AfkD8mR7IrYP5PVlSV5q1ecjLAp+J+I24EeDC7NhgRe5sI2stV5JfVogwiaXnFCzOItfl4TghqYNNTtPYptCBB//cZ5GT+K9BDLZH+RTFBo6CK6GsU1+RSkfuc4lbpARsAUuedkgywIFCVYHgbbItr/Wiao1l1OZe1ldYWSfjZvrZ6x82UAs8/Wh5QXBoYzdQ2lnfSEKh9v0lP/1/4SFtCd9v+uFDPAyKnMNLttS0rJS3UeTDBggt7f0aIhRUQnEBUK6VNokfbmhh5pRDM95TmTl0LAZhYXAur/6w5I5diY1NC8mhNMcpOpxFRLnDV9JTWtvipEVF78VP6i6coSdL3sFLuq49EIfvxuoRMP548qXV2u0oQD/BfvYStskw+GbhXksj5ZEALEMGAJfOwWTHTkAOAg/Z462Ff1CHTFE1XSwJ+N9Gfs07xMIO6wXJrd9BZvvacqTI8mdh30gTV7KbXwbhw0KSPVCCU5GECDBtIPMQHOMEZy6o70AelKt0vmvoI+2R/d4jOdl5p6bTBfAOxk3bPe7aqOcCEd2mRNAjPOeWjt4IvPs51THEL/ap6I3ffrtrkU6DhiUGOX7VFPOe8uUiPmwJBm9TjtEmpnruOYvccR2DC/4Ew==",
    "clientInfo": "",
    "optionalParam": ""
})

try:
    response = requests.post(API_URL, headers=headers, data=payload)
    response.raise_for_status()

    # Log the response
    # print("Response Status Code:", response.status_code)
    print("Response Text:", response.text)
    print("Response JSON:", response.json())
    if response:
        response = response.json()
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
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
