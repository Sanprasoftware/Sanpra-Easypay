# Copyright (c) 2025, Sanpra Software Solutions and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class SupplierAdvancePayments(Document):
	def before_save(self):
		zero_rows = self.get("purchase_invoice_details",{"check":0})
		for z in zero_rows:
			self.purchase_invoice_details.remove(z)
	def before_submit(self):
		self.create_payment_entries()
	def before_cancel(self):
		self.delete_payment_entries()
	@frappe.whitelist()
	def get_invoices(self):
		all_invoices = frappe.get_all("Purchase Invoice",{"company":self.company,"status":["in",["Partly Paid","Unpaid","Overdue"]],"posting_date":["between",[self.from_date,self.to_date]],"custom_payment_entry_done":0},["name","supplier","supplier_name","posting_date","total_qty","outstanding_amount","total_net_weight","posting_date","credit_to","company"])
		for i in all_invoices:
			self.append("purchase_invoice_details",{
				"purchase_invoice":i.name,
				"supplier":i.supplier,
				"supplier_name":i.supplier_name,
				"total_quantity":i.total_qty,
				"total_weight":i.total_net_weight,
				"posting_date":i.posting_date,
				"outstanding_amount":i.outstanding_amount,
				"company":i.company,
				"credit_to":i.credit_to
			})
   
	def create_payment_entries(self):
		for i in self.get("purchase_invoice_details",{"check":1}):
			pe_doc = frappe.new_doc("Payment Entry")
			pe_doc.party_type = "Supplier"
			pe_doc.party = i.supplier,
			pe_doc.payment_type = "Pay"
			pe_doc.posting_date = i.posting_date
			pe_doc.company = i.company
			pe_doc.paid_amount = i.outstanding_amount
			pe_doc.received_amount = i.outstanding_amount
			pe_doc.paid_from = self.account_paid_from
			pe_doc.paid_to = i.credit_to
			pe_doc.paid_from_account_currency = "INR"
			pe_doc.paid_to_account_currency = "INR"
			pe_doc.append("references",{
				"reference_doctype":"Purchase Invoice",
				"reference_name":i.purchase_invoice,
				"due_date":frappe.get_value("Purchase Invoice",i.purchase_invoice,"due_date"),
				"bill_no":frappe.get_value("Purchase Invoice",i.purchase_invoice,"bill_no")
			})
			pe_doc.custom_supplier_advance_payments = self.name
			pe_doc.save()
			i.payment_entry = pe_doc.name
			if frappe.get_value("Purchase Invoice",i.purchase_invoice,"outstanding_amount") == i.outstanding_amount:
				frappe.db.set_value("Purchase Invoice",i.purchase_invoice,"custom_payment_entry_done",1)
   
	def delete_payment_entries(self):
		if self.get("purchase_invoice_details"):
			for i in self.get("purchase_invoice_details"):
				frappe.delete_doc("Payment Entry",i.payment_entry)
				i.payment_entry = ""
				frappe.db.set_value("Purchase Invoice",i.purchase_invoice,"custom_payment_entry_done",0)
   