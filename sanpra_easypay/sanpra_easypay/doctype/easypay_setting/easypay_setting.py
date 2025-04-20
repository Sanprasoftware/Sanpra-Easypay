# Copyright (c) 2025, Sanpra Software Solutions and contributors
# For license information, please see license.txt

import os
import json
import shutil
import frappe
from frappe.model.document import Document

class EasyPaySetting(Document):
	def before_save(self):
		site_path = frappe.get_site_path()
		# Update site_config.json
		config_path = os.path.join(site_path, 'site_config.json')

		if os.path.exists(config_path):
			with open(config_path, 'r') as f:
				config = json.load(f)
		else:
			config = {}

		if self.public_ssl_certificate_crt:
			crt_path, dest_path = self.copy_to_env_and_get_dest_path(site_path, self.public_ssl_certificate_crt)
			if crt_path:
				if crt_path.split('.')[-1] != 'crt':
					frappe.throw("Public SSL Certificate File Should Have Only .crt Format")
		
				config['easypay_ssl_certificate_path'] = dest_path
				with open(config_path, 'w') as f:
					json.dump(config, f, indent=4)
				self.public_ssl_certificate_crt = ""
				frappe.msgprint("Public SSL Certificate File Is Updated")
				os.remove(crt_path)

		if self.private_key_pem:
			crt_path, dest_path = self.copy_to_env_and_get_dest_path(site_path, self.private_key_pem)
			if crt_path:
				if crt_path.split('.')[-1] != 'pem':
					frappe.throw("Private Key File Should Have Only .pem Format")
		
				config['easypay_private_key_pem'] = dest_path
				with open(config_path, 'w') as f:
					json.dump(config, f, indent=4)
				self.private_key_pem = ""
				frappe.msgprint("Private Key File Is Updated")
				os.remove(crt_path)

	def copy_to_env_and_get_dest_path(self, site_path, field):
		# Resolve full path
		crt_path = self.resolve_file_path(field)

		# Define destination
		env_folder = os.path.join(site_path, 'etc')
		os.makedirs(env_folder, exist_ok=True)

		crt_filename = os.path.basename(crt_path)
		dest_path = os.path.join(env_folder, crt_filename)

		# Copy the certificate file
		shutil.copyfile(crt_path, dest_path)
		return crt_path, dest_path

	def resolve_file_path(self, file_url):
		"""Convert Frappe-style file URL to absolute path."""
		if file_url:
			if file_url.startswith("/private/files/"):
				return os.path.join(frappe.get_site_path("private", "files"), os.path.basename(file_url))
			elif file_url.startswith("/public/files/"):
				return os.path.join(frappe.get_site_path("public", "files"), os.path.basename(file_url))
			else:
				frappe.throw(f"Unsupported file path: {file_url}")