# Copyright (c) 2025, Sanpra Software Solutions and contributors
# For license information, please see license.txt

import base64
import json
import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import frappe
from datetime import datetime
from frappe import _
import os
from frappe.model.document import Document
import xml.etree.ElementTree as ET


current_path = os.path.dirname(os.path.abspath(__file__))
PUBLIC_KEY_FILE = os.path.join(current_path, "prod_pub_key.crt")
PRIVATE_KEY_FILE = os.path.join(current_path, "prod_priv_key.pem")
OTP_API_URL = "https://apibankingone.icicibank.com/api/Corporate/CIB/v1/Create"
PAYMENT_API_URL = "https://apibankingone.icicibank.com/api/v1/cibbulkpayment/bulkPayment"
REVERSE_PAYMENT_URL = "https://apibankingone.icicibank.com/api/v1/ReverseMis"
API_KEY = "XMEJXRZwBBa80zv06iVURuMaT3GcF66Y"
SESSION_KEY = os.urandom(16)
IV = os.urandom(16)

AGGR_ID = "BULK0079"
AGGR_NAME = "BASTAR"
CORP_ID = "596778175"
USER_ID = "MOHAMMAD"
URN = "SR263840153"


def encrypt_data(data, session_key, iv):
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_data).decode('utf-8')


def encrypt_key(session_key):
    with open(PUBLIC_KEY_FILE, 'rb') as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_v1_5.new(public_key)
    encrypted_key = cipher_rsa.encrypt(session_key)
    return base64.b64encode(encrypted_key).decode('utf-8')


def decrypt_data(encrypted_data, encrypted_key):
    with open(PRIVATE_KEY_FILE, "rb") as key_file:
        private_key = RSA.import_key(key_file.read())

    encrypted_key_bytes = base64.b64decode(encrypted_key)
    cipher = PKCS1_v1_5.new(private_key)
    session_key = cipher.decrypt(encrypted_key_bytes, None)

    iv = base64.b64decode(encrypted_data)[:16]
    encrypted_data_bytes = base64.b64decode(encrypted_data)[16:]
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(encrypted_data_bytes), AES.block_size)

    return plaintext.decode("utf-8")
class SupplierBankPayment(Document):
	def before_submit(self):
		zero_rows = self.get("payment_entry_details",{"make_payment":0})
		for z in zero_rows:
			self.payment_entry_details.remove(z)
	@frappe.whitelist()
	def on_update_after_submit(self):
		self.validate()
	def before_save(self):
		if self.docstatus == 0:
			for pe in self.get("payment_entry_details"):
				if pe.paid_amount > pe.payable_amount:
					frappe.throw("Paid Amount cannot be greater than payable amount")
	
	@frappe.whitelist()
	def validate(self):
		if not self.get("payment_entry_details"):
			frappe.throw("Payment Entry Details Cannot be empty")
		if not any(i.make_payment for i in self.get("payment_entry_details")):
			frappe.throw("Select at least one Record to proceed Transaction")
		record_count = str(len(self.get("payment_entry_details",{"make_payment":1}))+1)
		date = datetime.now().strftime("%m/%d/%Y")
		total_amt = sum(i.get("paid_amount",0) for i in self.get("payment_entry_details",{"make_payment":1}))
		header_str = f"FHR|{record_count}|{date}|BDF|{total_amt}|INR|{str(self.account_no)}|0011^MDR|{str(self.account_no)}|0011|BDF|{total_amt}|INR|BDF|ICIC0000011|WIB^"
		self.header_string = header_str
		self.final_string = header_str + "".join([i.beneficiary_string for i in self.get("payment_entry_details") if i.make_payment == 1])
		
	@frappe.whitelist()
	def get_pe_details(self):
		pe_docs = frappe.get_all("Payment Entry", {"posting_date": ["between", [self.from_date, self.to_date]], "payment_type": "Pay","docstatus":1}, ["name","posting_date","paid_to","party","party_name","paid_to_account_currency","paid_amount","custom_in_process_amount","custom_transferred_amount"])
		if not pe_docs:
			frappe.msgprint("No Data Found")
		
		
		for i in pe_docs:
			is_skip = False
			def_bank_acc,acc_no,ifsc_code = frappe.get_value("Supplier",i.get("party"),["default_party_bank_account","party_account_number,party_branch_code"]) or (None,None,None)
			if not acc_no:
				frappe.msgprint(f"Entry Skipped due to missing account No.for {i.get('party')}")
				is_skip = True
			if not ifsc_code:
				frappe.msgprint(f"Entry Skipped due to missing IFSC Code for {i.get('party')}")
				is_skip = True
			if not def_bank_acc:
				frappe.msgprint(f"Entry Skipped due to missing Default Bank Account for {i.get('party')}")
				is_skip = True
			if not is_skip and (i.get("paid_amount",0) - (i.get("custom_transferred_amount",0) + i.get("custom_in_process_amount",0))>0):
				is_wib = 1 if frappe.get_value("Bank Account",def_bank_acc,"bank") == "ICICI BANK" else 0
				beneficiary_str = ""
				beneficiary_str+="MCW|" if is_wib else "MCO|"
				beneficiary_str+=str(acc_no+"|")
				beneficiary_str+=str(acc_no[:4]+"|") if is_wib else "0011|"
				beneficiary_str+=str(i.get("party_name","")+"|")
				beneficiary_str+=str(i.get("paid_amount",""))+"|"
				beneficiary_str+=str(i.get("paid_to_account_currency","")+"|")
				beneficiary_str+=str(i.get("remark","Remark")[:6]+"|")	
				beneficiary_str+=str(ifsc_code+"|") if is_wib else "NFT|"
				beneficiary_str+="WIB^" if is_wib else str(ifsc_code+"^")

				self.append("payment_entry_details", {
					"payment_entry": i.get("name", ""),
					"posting_date":i.get("posting_date",""),
					"account_currency_to":i.get("paid_to_account_currency",""),
					"account_paid_to":i.get("paid_to",""),
					"party":i.get("party",""),
					"party_name":i.get("party_name",""),
					"paid_amount":i.get("paid_amount",0) - (i.get("custom_transferred_amount",0) + i.get("custom_in_process_amount",0)),
					"payable_amount":i.get("paid_amount",0) - (i.get("custom_transferred_amount",0) + i.get("custom_in_process_amount",0)),
					"remark":i.get("remark"),
					"account_no":acc_no,
					"is_wib":is_wib,
					"beneficiary_string":beneficiary_str
				})


	@frappe.whitelist()
	def get_otp(self):
		otp_log = {}
		UNIQUEID = str(self.name)
		decrypted_data = None
		try:
			payload = json.dumps({
				"AGGRID": AGGR_ID,
				"AGGRNAME": AGGR_NAME,
				"CORPID": CORP_ID,
				"USERID": USER_ID,
				"URN": URN,
				"UNIQUEID": UNIQUEID
			})

			encrypted_data = encrypt_data(payload, SESSION_KEY, IV)
			encrypted_key = encrypt_key(SESSION_KEY)

			final_json = {
				"requestId": "",
				"service": "LOP",
				"encryptedKey": encrypted_key,
				"oaepHashingAlgorithm": "NONE",
				"iv": base64.b64encode(IV).decode('utf-8'),
				"encryptedData": encrypted_data,
				"clientInfo": "",
				"optionalParam": ""
			}

			response = requests.post(OTP_API_URL, headers={'Content-Type': 'application/json', 'accept': '*/*', 'APIKEY': API_KEY}, data=json.dumps(final_json))
			otp_log["encrypted_response"] = str(response.json())
			if response:
				decrypted_data = decrypt_data(response.json()["encryptedData"], response.json()["encryptedKey"])
				decrypted_data = json.loads(decrypted_data)
				otp_log["decrypted_response"] = str(decrypted_data)
	
		except Exception as e:
			otp_log["error"] = str(e)
			frappe.msgprint(
				_("Error occurred: {0}").format(str(e)),
				title="Error",
				indicator="red"
			)


		finally:
			otp_log["log_time"] = frappe.utils.now()
			self.append("otp_api_log_details", otp_log)
			self.save()
		if not decrypted_data:
			decrypted_data = {}
		return decrypted_data.get('MESSAGE') or decrypted_data.get('Message') or None

	@frappe.whitelist()
	def make_payment(self, otp):
		payment_log = {}
		UNIQUEID = str(self.name)
		FILE_NAME = UNIQUEID+".txt"
		try:
			sample_str = str(self.final_string)
			encoded_str = base64.b64encode(sample_str.encode("utf-8")).decode("utf-8")
			payload = json.dumps({
				"AGGR_ID": AGGR_ID,
				"AGGR_NAME": AGGR_NAME,
				"CORP_ID": CORP_ID,
				"USER_ID": USER_ID,
				"URN": URN,
				"UNIQUE_ID": UNIQUEID,
				"FILE_DESCRIPTION": "TEST FILE",
				"AGOTP": otp,
				"FILE_NAME": FILE_NAME,
				"FILE_CONTENT": encoded_str
			})

			encrypted_data = encrypt_data(payload, SESSION_KEY, IV)
			encrypted_key = encrypt_key(SESSION_KEY)

			payload = {
				"requestId": "",
				"service": "LOP",
				"encryptedKey": encrypted_key,
				"oaepHashingAlgorithm": "NONE",
				"iv": base64.b64encode(IV).decode('utf-8'),
				"encryptedData": encrypted_data,
				"clientInfo": "",
				"optionalParam": ""
			}

			response = requests.post(PAYMENT_API_URL, headers={'Content-Type': 'application/json', 'accept': '*/*', 'APIKEY': API_KEY}, data=json.dumps(payload))
			payment_log["encrypted_response"] = str(response.json())
			if response:
				decrypted_data = decrypt_data(response.json()["encryptedData"], response.json()["encryptedKey"])
				decrypted_data = json.loads(decrypted_data)
				payment_log["decrypted_response"] = str(decrypted_data)
				if "FILE_SEQUENCE_NUM" in decrypted_data:
					self.file_sequence_number = decrypted_data["FILE_SEQUENCE_NUM"]
					self.save()
					for pe in self.get("payment_entry_details",{"make_payment":1}):
						in_process_amt = frappe.get_value("Payment Entry",pe.payment_entry,"custom_in_process_amount")
						frappe.db.set_value("Payment Entry",pe.payment_entry,"custom_in_process_amount",pe.paid_amount + in_process_amt)
						
					self.check_payment_status(decrypted_data["FILE_SEQUENCE_NUM"])
				frappe.msgprint(f"{decrypted_data.get('MESSAGE_DESC',decrypted_data)}")
		except Exception as e:
			payment_log["error"] = str(e)
			frappe.msgprint(
				_("Error occurred: {0}").format(str(e)),
				title="Error",
				indicator="red"
			)

		finally:
			payment_log["log_time"] = frappe.utils.now()
			self.append("bulk_payment_api_log_details", payment_log)
			self.save()

	@frappe.whitelist()
	def check_payment_status(self, file_seq_no):
		status_log = {}
		UNIQUEID = str(self.name)
		FILE_SEQ_NUM = str(file_seq_no)
		try:
			payload = json.dumps({
				"AGGRID": AGGR_ID,
				"CORPID": CORP_ID,
				"USERID": "BDF19771255",
				"URN": URN,
				"ISENCRYPTED": "N",
				"UNIQUEID": UNIQUEID,
				"FILESEQNUM": FILE_SEQ_NUM
			})
			encrypted_data = encrypt_data(payload, SESSION_KEY, IV)
			encrypted_key = encrypt_key(SESSION_KEY)
			payload = {
				"requestId": "",
				"service": "LOP",
				"encryptedKey": encrypted_key,
				"oaepHashingAlgorithm": "NONE",
				"iv": base64.b64encode((IV)).decode('utf-8'),
				"encryptedData": encrypted_data,
				"clientInfo": "",
				"optionalParam": ""
			}
			response = requests.post(REVERSE_PAYMENT_URL, headers={'Content-Type': 'application/json', 'accept': '*/*', 'APIKEY': API_KEY}, data=json.dumps(payload))
			status_log["encrypted_response"] = str(response.json())
			
			if response:
				decrypted_data = decrypt_data(response.json()["encryptedData"], response.json()["encryptedKey"])
				status_log["decrypted_response"] = str(decrypted_data)
			
		except Exception as e:
			status_log["error"] = str(e)
			frappe.msgprint(
				_("Error occurred: {0}").format(str(e)),
				title="Error",
				indicator="red"
			)

		finally:
			status_log["log_time"] = frappe.utils.now()
			self.append("payment_status_api_log_details", status_log)
			self.save()

     
@frappe.whitelist()
def check_payment_status():
	payment_docs = frappe.get_all("Supplier Bank Payment",{"docstatus":1,"file_sequence_number":["!=",None]},["name","file_sequence_number"])
	for pd in payment_docs:
		unique_id = pd.get("name")
		file_seq_no = pd.get("file_sequence_number")
		payload = json.dumps({
			"AGGRID": AGGR_ID,
			"CORPID": CORP_ID,
			"USERID": "BDF19771255",
			"URN": URN,
			"ISENCRYPTED": "N",
			"UNIQUEID": unique_id,
			"FILESEQNUM": str(file_seq_no)
		})

		encrypted_data = encrypt_data(payload, SESSION_KEY, IV)
		encrypted_key = encrypt_key(SESSION_KEY)

		payload = {
			"requestId": "",
			"service": "LOP",
			"encryptedKey": encrypted_key,
			"oaepHashingAlgorithm": "NONE",
			"iv": base64.b64encode(IV).decode('utf-8'),
			"encryptedData": encrypted_data,
			"clientInfo": "",
			"optionalParam": ""
		}

		response = requests.post(
			"https://apibankingone.icicibank.com/api/v1/ReverseMis", 
			headers={'Content-Type': 'application/json', 'accept': '*/*', 'APIKEY': "XMEJXRZwBBa80zv06iVURuMaT3GcF66Y"}, 
			data=json.dumps(payload)
		)
				
		if response:
			decrypted_data = decrypt_data(response.json()["encryptedData"], response.json()["encryptedKey"])
			decrypted_data = json.loads(decrypted_data)
			records = decrypted_data['XML']['FILEUPLOAD_BINARY_OUTPUT']['Records']['Record']
			is_debit_record = True
			is_debit_success = False
			sbp_doc = frappe.get_doc("Supplier Bank Payment",pd)
			idx = -2
			for record in records[1:]:  
				idx += 1
				transaction_response = None
				fields = record.split('|')
				transaction_type = fields[0]
				network_id = fields[1]
				credit_account_number = fields[2]
				debit_account_number = fields[3]
				ifsc_code = fields[4]
				total_amount = fields[5]
				host_reference_number = fields[6]
				host_response_code = fields[7]
				host_response_message = fields[8]
				transaction_remarks = fields[9]
				transaction_status = fields[10]
				if is_debit_record:
					is_debit_record = False
					if transaction_remarks == "Payment Success":
						is_debit_success = True
					else:
						break
				else:
					transaction_response = (
							f"Transaction Type: {transaction_type}\n"
							f"Network ID: {network_id}\n"
							f"Credit Account Number: {credit_account_number}\n"
							f"Debit Account Number: {debit_account_number}\n"
							f"IFSC Code: {ifsc_code}\n"
							f"Total Amount: {total_amount}\n"
							f"Host Reference Number: {host_reference_number}\n"
							f"Host Response Code: {host_response_code}\n"
							f"Host Response Message: {host_response_message}\n"
							f"Transaction Remarks: {transaction_remarks}\n"
							f"Transaction Status: {transaction_status}\n"
						)
					sbp_doc.get("payment_entry_details")[idx].transaction_response = transaction_response
					sbp_doc.get("payment_entry_details")[idx].transaction_remark = transaction_remarks
					update = sbp_doc.get("payment_entry_details")[idx].updated_on_payment_entry 
					if transaction_remarks == "Payment Success":
						if not update:
							amount = sbp_doc.get("payment_entry_details")[idx].paid_amount
							payment_entry = sbp_doc.get("payment_entry_details")[idx].payment_entry
							in_progress = frappe.get_value("Payment Entry", payment_entry, 'custom_in_process_amount')
							transferred = frappe.get_value("Payment Entry", payment_entry, 'custom_transferred_amount')
							frappe.db.set_value("Payment Entry", payment_entry, 'custom_in_process_amount', in_progress - amount)
							frappe.db.set_value("Payment Entry", payment_entry, 'custom_transferred_amount', transferred + amount)
							sbp_doc.get("payment_entry_details")[idx].updated_on_payment_entry = 1
					else:
						if not update:
							amount = sbp_doc.get("payment_entry_details")[idx].paid_amount
							payment_entry = sbp_doc.get("payment_entry_details")[idx].payment_entry
							in_progress = frappe.get_value("Payment Entry", payment_entry, 'custom_in_process_amount')
							frappe.db.set_value("Payment Entry", payment_entry, 'custom_in_process_amount', in_progress - amount)
							sbp_doc.get("payment_entry_details")[idx].updated_on_payment_entry = 1
					sbp_doc.save()


    
