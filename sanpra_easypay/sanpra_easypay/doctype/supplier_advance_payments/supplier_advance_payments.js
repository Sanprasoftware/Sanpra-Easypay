// Copyright (c) 2025, Sanpra Software Solutions and contributors
// For license information, please see license.txt

frappe.ui.form.on("Supplier Advance Payments", {
	get_invoices(frm) {
        frm.clear_table("purchase_invoice_details")
        frm.call({
            method:"get_invoices",
            doc:frm.doc,
            freeze:true
        })
	},
    select_all(frm) {
        if(frm.doc.purchase_invoice_details){
            const check = !frm.doc.purchase_invoice_details[0].check
            frm.doc.purchase_invoice_details.forEach(row=>{
                row.check = check
            })
            frm.dirty()
            frm.refresh_fields()    
     }
    }
});
