// Copyright (c) 2025, Sanpra Software Solutions and contributors
// For license information, please see license.txt

frappe.query_reports["Supplier Bank Payment Status"] = {
	"filters": [
		// {
		// 	"label": "Company",
		// 	"fieldname": "company",
		// 	"fieldtype": "Link",
		// 	"options": "Company",
		// 	"width": 100,
		// 	"reqd": 1

		// },
		{
			"label": "Party Type",
			"fieldname": "party_type",
			"fieldtype": "Link",
			"options": "DocType",
			"width": 100,
			"reqd": 0,
			"get_query": function() {
                return {
                    filters: [
                        ["name", "in", ["Employee", "Supplier"]]
                    ]
                };
			}
		},
		{
			"label": "Party",
			"fieldname": "party",
			"fieldtype": "Dynamic Link",
			"options": "party_type",
			"width": 100,
			"reqd": 0
		},
		{
			"label": "Status",
			"fieldname": "status",
			"fieldtype": "Select",
			"options": ["Draft","Submitted"],
			"width": 100,
			"reqd": 1
		},
		{
			"label": "Payment Status",
			"fieldname": "pay_status",
			"fieldtype": "Select",
			"options": ["","Payment Success","Other"],
			"width": 100,
			"reqd": 0,
		}
		// {
		// 	"label": "DESC",
		// 	"fieldname": "desc",
		// 	"fieldtype": "Check",
		// 	"reqd": 0
		// },
	]
};
