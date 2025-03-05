// Copyright (c) 2025, Sanpra Software Solutions and contributors
// For license information, please see license.txt
let show_dialog = false
frappe.ui.form.on("Supplier Bank Payment", {
    select_all(frm) {
        if(frm.doc.payment_entry_details){
            const check = !frm.doc.payment_entry_details[0].make_payment
            frm.doc.payment_entry_details.forEach(row=>{
                row.make_payment = check
            })
            frm.refresh_fields()    
     }
    },
	async get_payment_entries(frm) {
        frm.clear_table("payment_entry_details")
        if(frm.doc.from_date && frm.doc.to_date){
            if(frm.doc.from_date > frm.doc.to_date){
                frappe.throw("From Date Cannot be Greater than To Date")
                return;
            }
            frm.call({
                method:"get_pe_details",
                doc:frm.doc,
                freeze:true
            })
        }else{
            frappe.throw("From Date and To Date is Mandatory")
        }
        frm.refresh_fields()
	},
    refresh: function (frm) {


    const css1 = `
    .btn-gradient-skyblue {
        background: linear-gradient(to right, #87CEEB, #00BFFF) !important;
        color: #ffffff !important; 
        font-size: 14px !important;
        font-weight: 500 !important;
        padding: 10px 16px !important;
        border-radius: 4px !important; 
        border: 1px solid transparent !important;
        cursor: pointer !important;
        transition: background 0.3s ease-in-out, transform 0.2s ease-in-out;
    }
    .btn-gradient-skyblue:hover {
        background: linear-gradient(to right, #1E90FF, #87CEFA) !important; 
    }
    .btn-gradient-skyblue:focus {
        background: linear-gradient(to right, #1E90FF, #00BFFF) !important;
        outline: 0;
        box-shadow: 0 0 0 0.2rem rgba(30, 144, 255, 0.5) !important; 
    }
    .btn-gradient-skyblue:active {
        background: linear-gradient(to right, #4682B4, #5F9EA0) !important; 
        transform: scale(0.98) !important; 
    }
`;
const style1 = document.createElement('style');
style1.type = 'text/css';
style1.innerHTML = css1;
document.head.appendChild(style1);

        if(frm.doc.file_sequence_number && frm.doc.docstatus == 1){
            let status_btn = frm.add_custom_button('Check Status', async function () {
                await frm.call({
                    method:"check_payment_status",
                    freeze:true,
                    doc:frm.doc,
                    args:{
                        file_seq_no:String(frm.doc.file_sequence_number)
                    }
                })
            })
            status_btn.addClass('btn-gradient-skyblue');
        }
        if (!frm.doc.file_sequence_number && frm.doc.docstatus == 1) {
            let button = frm.add_custom_button('Make Payment', async function () {
                let OtpResponse = await frm.call({
                    method: "get_otp",
                    doc:frm.doc,
                    freeze: 'true'
                });
                if (OtpResponse.message.toLowerCase() === "success"){
                    frappe.show_alert({
                        message: __('OTP Sent to your registered mobile number!'),
                        indicator: 'green'
                    }, 5);
                    show_dialog = true
                    
                }else{
                    frappe.show_alert({
                        message: __('Something Went Wrong'),
                        indicator: 'red'
                    }, 5);
                }
                

                const otp_dialog = new frappe.ui.Dialog({
                    title: 'Enter OTP',
                    fields: [
                        {
                            label: 'OTP',
                            fieldname: 'otp',
                            fieldtype: 'Data',
                            reqd: 1,
                        },
                    ],
                    primary_action_label: 'Submit OTP',
                    async primary_action(otp) {
                        console.log(otp);
                        otp_dialog.hide();
                        makePaymentResponse = await frm.call({
                            method:"make_payment",
                            freeze:true,
                            doc:frm.doc,
                            args:{
                                otp:otp["otp"]
                            }
                        })
                        console.log(makePaymentResponse);
                        
                    },
                    
                });
                if(show_dialog){
                    otp_dialog.show();
                }
            });

            const css = `
                .btn-custom-orange {
                    background-color: #FFA726 !important;
                    color: #ffffff !important; 
                    font-size: 14px !important;
                    font-weight: 500 !important;
                    padding: 10px 16px !important;
                    border-radius: 4px !important; 
                    border: 1px solid transparent !important;
                    cursor: pointer !important;
                    transition: background-color 0.3s ease-in-out, transform 0.2s ease-in-out;
                }
                .btn-custom-orange:hover {
                    background-color: #FB8C00 !important; 
                }
                .btn-custom-orange:focus {
                    background-color: #FB8C00 !important;
                    outline: 0;
                    box-shadow: 0 0 0 0.2rem rgba(251, 140, 0, 0.5) !important; 
                }
                .btn-custom-orange:active {
                    background-color: #EF6C00 !important; 
                    transform: scale(0.98) !important; 
                }
            `;

            const style = document.createElement('style');
            style.type = 'text/css';
            style.innerHTML = css;
            document.head.appendChild(style);

            button.addClass('btn-custom-orange');
            
        }
    },
});
frappe.ui.form.on("Payment Entry Details",{
    paid_amount:function(frm,cdt,cdn){
        let d = locals[cdt][cdn]
        if(d.paid_amount > d.payable_amount){
            d.paid_amount = d.payable_amount
            frappe.msgprint("Paid Amount cannot be greater than payable amount")
            frm.refresh_fields()
        }
    }
})
