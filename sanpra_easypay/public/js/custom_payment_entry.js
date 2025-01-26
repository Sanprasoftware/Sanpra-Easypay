frappe.ui.form.on('Payment Entry', {
    refresh: function (frm) {
        if (frm.doc.docstatus == 1 && frm.doc.payment_type == "Pay") {
            let button = frm.add_custom_button('Make Payment', async function () {
                let sendOtpResponse = await frm.call({
                    method: "sanpra_easypay.sanpra_easypay.encryption.get_otp",
                    freeze: 'true'
                });
                frappe.show_alert({
                    message: __('OTP Sent to your registered mobile number!'),
                    indicator: 'green'
                }, 5);

                console.log(sendOtpResponse);

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
                            method:"sanpra_easypay.sanpra_easypay.encryption.make_payment",
                            freeze:true,
                            args:{
                                otp:otp["otp"]
                            }
                        })
                        console.log(makePaymentResponse);
                        
                    },
                });
                otp_dialog.show();
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
