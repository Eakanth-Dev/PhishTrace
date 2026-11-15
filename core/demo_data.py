"""DEMONSTRATION DATA ONLY. All names, numbers and domains are fictional; domains use the reserved
'.example' TLD or documentation IP ranges and cannot resolve to real sites. Never rendered as links."""

DEMO_CASES = [
    {"id": "phish_url", "type": "url", "label": "Suspicious phishing URL (demo)",
     "content": "http://secure-sbi-kyc-update.example/login?verify=account&session=a1b2c3",
     "note": "Brand name on a non-official domain, hyphen stuffing, no HTTPS, sensitive keywords."},
    {"id": "legit_url", "type": "url", "label": "Legitimate URL (demo)",
     "content": "https://www.python.org/downloads/",
     "note": "Official domain with no suspicious structure. Still never guaranteed safe."},
    {"id": "ip_url", "type": "url", "label": "IP-based login URL (demo)",
     "content": "http://203.0.113.45/bank/login.php?redirect=http://203.0.113.46/collect",
     "note": "Documentation-range IP, embedded redirect parameter."},
    {"id": "kyc_email", "type": "email", "label": "Fake bank KYC email (demo)",
     "content": (
         "From: \"HDFC Bank Alerts\" <alerts@hdfc-secure-kyc.example>\n"
         "Reply-To: support.desk@mailbox-helper.example\n"
         "To: customer@mail.example\n"
         "Subject: URGENT: Your account will be blocked - complete KYC today\n"
         "Date: Mon, 10 Nov 2025 09:14:05 +0530\n"
         "Received: from mail-relay.hdfc-secure-kyc.example by mx.mail.example; Mon, 10 Nov 2025 09:14:10 +0530\n"
         "Authentication-Results: mx.mail.example; spf=fail smtp.mailfrom=hdfc-secure-kyc.example; dkim=none; dmarc=fail\n"
         "Content-Type: text/html; charset=utf-8\n\n"
         "<html><body><p>Dear Customer,</p><p>Your account will be blocked within 24 hours because your KYC has expired. "
         "Update your PAN and Aadhaar immediately.</p>"
         "<p><a href=\"http://hdfc-secure-kyc.example/update?id=77\">www.hdfcbank.com/kyc</a></p>"
         "<p>Enter your net banking password and card number to confirm.</p></body></html>")},
    {"id": "upi_msg", "type": "message", "label": "Suspicious UPI refund message (demo)",
     "content": "Dear customer, a refund of Rs. 4,999 is pending. Approve the collect request in your UPI app and enter your UPI PIN "
                "to receive the money. Share OTP with our executive to confirm. Act within 15 minutes or the refund will expire."},
    {"id": "delivery_msg", "type": "message", "label": "Fake delivery notification (demo)",
     "content": "India Post: Your parcel is on hold due to an incomplete address. Pay a \u20b925 redelivery fee at "
                "indiapost-redelivery.example/track within 24 hours or it will be returned."},
    {"id": "internship_msg", "type": "message", "label": "Fake internship offer (demo)",
     "content": "Congratulations! You are selected for Data Analyst internship. Pay \u20b91,500 refundable registration fee today "
                "to confirm your seat. WhatsApp our HR manager at +91 90000 00000."},
    {"id": "upi_qr", "type": "qr_payload", "label": "Suspicious UPI QR destination (demo)",
     "content": "upi://pay?pa=refund.desk@examplebank&pn=Refund%20Desk&am=4999&cu=INR&tn=refund%20claim",
     "note": "Decoded payload of a demo QR. Use 'Generate demo QR image' to test the image path."},
]


def by_type(t):
    return [c for c in DEMO_CASES if c["type"] == t]


def make_demo_qr_png(payload: str):
    """Generate a QR PNG with OpenCV's encoder (None if unavailable)."""
    try:
        import cv2
        import numpy as np
        qr = cv2.QRCodeEncoder.create().encode(payload)
        qr = cv2.copyMakeBorder(qr, 20, 20, 20, 20, cv2.BORDER_CONSTANT, value=255)
        qr = cv2.resize(qr, None, fx=6, fy=6, interpolation=cv2.INTER_NEAREST)
        ok, buf = cv2.imencode(".png", qr)
        return buf.tobytes() if ok else None
    except Exception:
        return None
