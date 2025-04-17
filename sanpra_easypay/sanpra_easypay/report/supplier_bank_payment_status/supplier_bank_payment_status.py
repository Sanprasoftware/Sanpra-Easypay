# Copyright (c) 2025, Sanpra Software Solutions and contributors
# For license information, please see license.txt

import frappe


def execute(filters=None):
	exclude_fields = {"name", "creation", "modified", "modified_by", "owner", "docstatus", "idx", "parent", "parentfield", "parenttype"}
	columns, data = get_columns(filters), get_data(filters)
	return columns, data

def get_columns(filters):
	columns = [
        {"label": "Party", "fieldname": "party", "fieldtype": "Link", "options": "Supplier", "width": 150},
        {"label": "Party Type", "fieldname": "party_type", "fieldtype": "Data", "width": 120},
        {"label": "Party Name", "fieldname": "party_name", "fieldtype": "Data", "width": 200},
		{"label": "Posting Date", "fieldname": "posting_date", "fieldtype": "Date", "width": 120},
        {"label": "Payment Entry", "fieldname": "payment_entry", "fieldtype": "Link", "options": "Payment Entry", "width": 150},
        {"label": "Account Paid From", "fieldname": "account_paid_from", "fieldtype": "Data", "width": 200},
        {"label": "Account Paid To", "fieldname": "account_paid_to", "fieldtype": "Data", "width": 200},
        {"label": "Paid Amount", "fieldname": "paid_amount", "fieldtype": "Currency", "width": 120},
        {"label": "Account No", "fieldname": "account_no", "fieldtype": "Data", "width": 150},
        # {"label": "Make Payment", "fieldname": "make_payment", "fieldtype": "Check", "width": 100},
        # {"label": "Beneficiary String", "fieldname": "beneficiary_string", "fieldtype": "Data", "width": 300},
        {"label": "Transaction Remark", "fieldname": "transaction_remark", "fieldtype": "Data", "width": 200},
        {"label": "Transaction Amount", "fieldname": "transaction_amount", "fieldtype": "Currency", "width": 120},
        # {"label": "Payable Amount", "fieldname": "payable_amount", "fieldtype": "Currency", "width": 120},
	]
	return columns

def get_data(filters=None):
    exclude_fields = {"creation", "modified", "modified_by", "owner", "docstatus", "idx","parentfield", "parenttype"}
    filt = {} #"company":filters.get("company")
    if filters.get("party_type"):
        filt["party_type"] = filters.get("party_type")
    if filters.get("party"):
        filt["party"] = filters.get("party")
    if filters.get("pay_status") == "Payment Success":
        filt["transaction_remark"] = "Payment Success"
    elif filters.get("pay_status") != "Payment Success":
        filt["transaction_remark"] = ["!=","Payment Success"]
        
    if filters.get("status"):
        status = {
            "Draft":0,
            "Submitted":1
        }
        filt["docstatus"] = status[filters.get("status")]
        
    order_by = "paid_amount DESC" if filters.get("desc") else "paid_amount ASC"
    data = frappe.get_all("Payment Entry Details",filt,["*"],order_by=order_by)
    processed_data = []
    for row in data:
        row["account_paid_from"] = frappe.get_value("Supplier Bank Payment", row.parent, "account_paid_from") if row.get("parent") else None
        processed_data.append({key: value for key, value in row.items() if key not in exclude_fields})

    return processed_data
