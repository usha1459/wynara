import secrets
import string
import qrcode
from io import BytesIO
import os
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch, cm
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from PIL import Image as PILImage, ImageDraw, ImageFont
import base64
import random

def generate_otp(length=6):
    """Generate a random OTP"""
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def generate_wapl_id():
    """Generate unique WAPL ID in format WAPL2026XXXXXX"""
    import sqlite3
    from database import DB_NAME
    
    conn = None
    try:
        # Connect directly
        conn = sqlite3.connect(DB_NAME, timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get the latest WAPL ID
        cursor.execute("SELECT wapl_id FROM students ORDER BY id DESC LIMIT 1")
        last_student = cursor.fetchone()
        
        if last_student and last_student['wapl_id']:
            # Extract number from last WAPL ID (e.g., WAPL2026000001 -> 1)
            last_number = int(last_student['wapl_id'][-6:])
            new_number = last_number + 1
        else:
            new_number = 1
        
        # Format: WAPL + YEAR + 6-digit number
        year = datetime.now().year
        wapl_id = f"WAPL{year}{new_number:06d}"
        
        return wapl_id
        
    except Exception as e:
        print(f"Error generating WAPL ID: {e}")
        # Fallback to random number if database query fails
        year = datetime.now().year
        random_num = random.randint(1, 999999)
        return f"WAPL{year}{random_num:06d}"
    finally:
        if conn:
            conn.close()


def generate_certificate_id():
    """Generate certificate unique ID: CERT + timestamp + 6-char random string"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_str = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
    return f'CERT{timestamp}{random_str}'

def generate_qr_code(data, output_path):
    """Generate QR code and save to file"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_path)
    return output_path

def generate_certificate_pdf(student_name, wapl_id, domain_name, issue_date, expiry_date, qr_code_path, output_path, hr_name=None, certificate_text=None):
    """Generate certificate by overlaying text on base image"""
    try:
        # Use base certificate image with logo
        base_image_path = 'uploads/certificates/certificate_wapl_id.jpg'
        
        if not os.path.exists(base_image_path):
            # Fallback to ReportLab if template missing
            return generate_certificate_pdf_reportlab(student_name, wapl_id, domain_name, issue_date, expiry_date, qr_code_path, output_path, hr_name, certificate_text)
        
        # Open base image
        img = PILImage.open(base_image_path).convert("RGB")
        draw = ImageDraw.Draw(img)
        
        w, h = img.size
        cx = w // 2  # Center X
        
        # Define colors
        GOLD = "#8a6a2f"
        BLUE = "#1f2b44"
        BLACK = "black"
        
        # Load fonts - adjust paths if needed
        try:
            name_font = ImageFont.truetype("fonts/PlayfairDisplay-Bold.ttf", 90)
            title_font = ImageFont.truetype("fonts/PlayfairDisplay-Bold.ttf", 54)
            body_font = ImageFont.truetype("fonts/PlayfairDisplay-Bold.ttf", 44)
            small_font = ImageFont.truetype("fonts/PlayfairDisplay-Regular.ttf", 36)
        except:
            # Fallback to default if fonts not found
            name_font = ImageFont.load_default()
            title_font = ImageFont.load_default()
            body_font = ImageFont.load_default()
            small_font = ImageFont.load_default()
        
        # Title text
        draw.text((cx, 395), "This certificate is proudly presented to", GOLD, title_font, anchor="mm")
        
        # Student name (prominent)
        draw.text((cx, 480), student_name.upper(), BLUE, name_font, anchor="mm")
        
        # Body text with wrapping
        if certificate_text:
            body_text = certificate_text
        else:
            body_text = f"This certificate recognizes the candidate's hands-on experience in {domain_name} and successful assessment by WAPL."
        
        # Simple text wrapping
        wrapped_lines = []
        words = body_text.split()
        current_line = ""
        max_width = w - 400
        
        for word in words:
            test_line = current_line + (" " if current_line else "") + word
            bbox = draw.textbbox((0, 0), test_line, font=body_font)
            if bbox[2] <= max_width:
                current_line = test_line
            else:
                if current_line:
                    wrapped_lines.append(current_line)
                current_line = word
        
        if current_line:
            wrapped_lines.append(current_line)
        
        # Draw wrapped body text
        body_y = 580
        for line in wrapped_lines:
            draw.text((cx, body_y), line, GOLD, body_font, anchor="ma")
            body_y += 58  # Line spacing
        
        # Bottom section coordinates
        left_x = 180
        base_y = h - 300
        
        # Issue and expiry dates
        draw.text((left_x, base_y), f"Valid From: {issue_date}", BLACK, small_font)
        draw.text((left_x, base_y + 50), f"Valid Until: {expiry_date}", BLACK, small_font)
        draw.text((left_x, base_y + 100), f"WAPL ID: {wapl_id}", BLACK, small_font)
        
        # HR name (if provided)
        if hr_name:
            draw.text((left_x, base_y + 150), f"Issued by: {hr_name}", BLACK, small_font)
        
        # QR Code
        if os.path.exists(qr_code_path):
            qr_img = PILImage.open(qr_code_path)
            qr_img = qr_img.resize((220, 220))
            img.paste(qr_img, (w - 400, base_y - 80))
        
        # Convert to PDF and save
        rgb_img = img.convert('RGB')
        rgb_img.save(output_path, 'PDF')
        return output_path
    
    except Exception as e:
        print(f"Error generating certificate: {str(e)}")
        # Fallback to ReportLab
        return generate_certificate_pdf_reportlab(student_name, wapl_id, domain_name, issue_date, expiry_date, qr_code_path, output_path, hr_name, certificate_text)


def generate_certificate_pdf_reportlab(student_name, wapl_id, domain_name, issue_date, expiry_date, qr_code_path, output_path, hr_name=None, certificate_text=None):
    """Fallback: Generate professional PDF certificate using ReportLab"""
    # Create custom canvas
    c = canvas.Canvas(output_path, pagesize=A4)
    width, height = A4
    
    # Draw decorative border
    border_color = colors.HexColor('#1a237e')
    c.setStrokeColor(border_color)
    c.setLineWidth(3)
    c.rect(0.5*cm, 0.5*cm, width - 1*cm, height - 1*cm)
    
    # Draw inner decorative line
    c.setLineWidth(1)
    c.rect(1*cm, 1*cm, width - 2*cm, height - 2*cm)
    
    # Add corner decorative elements
    accent_color = colors.HexColor('#283593')
    c.setFillColor(accent_color)
    corner_size = 15
    c.circle(1.5*cm, height - 1.5*cm, corner_size, fill=1)
    c.circle(width - 1.5*cm, height - 1.5*cm, corner_size, fill=1)
    c.circle(1.5*cm, 1.5*cm, corner_size, fill=1)
    c.circle(width - 1.5*cm, 1.5*cm, corner_size, fill=1)
    
    # Title
    c.setFont("Helvetica-Bold", 32)
    c.setFillColor(colors.HexColor('#1a237e'))
    c.drawCentredString(width/2, height - 3*cm, "CERTIFICATE OF REGISTRATION")
    
    # Subtitle line
    c.setFont("Helvetica", 11)
    c.setFillColor(colors.HexColor('#424242'))
    c.drawCentredString(width/2, height - 3.7*cm, "WAPL - Student Portfolio and Placement Management System")
    
    # Main text
    c.setFont("Helvetica", 13)
    c.setFillColor(colors.HexColor('#424242'))
    c.drawCentredString(width/2, height - 5.5*cm, "This is to certify that")
    
    # Student name (prominent)
    c.setFont("Helvetica-Bold", 26)
    c.setFillColor(colors.HexColor('#1a237e'))
    c.drawCentredString(width/2, height - 6.8*cm, student_name)
    
    # Details section
    c.setFont("Helvetica", 12)
    c.setFillColor(colors.HexColor('#424242'))
    c.drawCentredString(width/2, height - 7.7*cm, "has successfully registered with WAPL")
    
    # Details table-like layout
    c.setFont("Helvetica-Bold", 11)
    c.setFillColor(colors.HexColor('#283593'))
    c.drawString(2*cm, height - 8.8*cm, "WAPL ID:")
    c.drawString(2*cm, height - 9.5*cm, "Domain:")
    
    c.setFont("Helvetica", 11)
    c.setFillColor(colors.HexColor('#1a237e'))
    c.drawString(4.5*cm, height - 8.8*cm, wapl_id)
    c.drawString(4.5*cm, height - 9.5*cm, domain_name)
    
    # HR Name
    if hr_name:
        c.setFont("Helvetica-Bold", 11)
        c.setFillColor(colors.HexColor('#283593'))
        c.drawString(2*cm, height - 10.2*cm, "Issued by:")
        
        c.setFont("Helvetica", 11)
        c.setFillColor(colors.HexColor('#1a237e'))
        c.drawString(4.5*cm, height - 10.2*cm, hr_name)
    
    # Validity dates
    c.setFont("Helvetica-Bold", 11)
    c.setFillColor(colors.HexColor('#283593'))
    c.drawString(2*cm, height - 11*cm, "Issue Date:")
    c.drawString(2*cm, height - 11.7*cm, "Expiry Date:")
    
    c.setFont("Helvetica", 11)
    c.setFillColor(colors.HexColor('#1a237e'))
    c.drawString(4.5*cm, height - 11*cm, str(issue_date))
    c.drawString(4.5*cm, height - 11.7*cm, str(expiry_date))
    
    # Certificate text/matter
    if certificate_text:
        c.setFont("Helvetica", 10)
        c.setFillColor(colors.HexColor('#424242'))
        # Wrap text
        from reportlab.lib.utils import simpleSplit
        lines = simpleSplit(certificate_text, "Helvetica", 10, width - 4*cm)
        text_y = height - 13*cm
        for line in lines[:4]:  # Max 4 lines
            c.drawString(1.5*cm, text_y, line)
            text_y -= 0.5*cm
    
    # QR Code section
    if os.path.exists(qr_code_path):
        qr_x = width/2 - 1.2*cm
        qr_y = height - 15.5*cm
        c.drawImage(qr_code_path, qr_x, qr_y, width=2.4*cm, height=2.4*cm)
        
        c.setFont("Helvetica", 9)
        c.setFillColor(colors.HexColor('#666666'))
        c.drawCentredString(width/2, qr_y - 0.5*cm, "Scan QR Code to Verify")
    
    # Certificate ID footer
    c.setFont("Helvetica", 8)
    c.setFillColor(colors.HexColor('#999999'))
    c.drawCentredString(width/2, 1.2*cm, f"Certificate ID: {wapl_id}")
    
    # Save the canvas
    c.save()
    return output_path

def send_email_simulation(to_email, subject, body):
    """Simulate email sending (console log for now)"""
    print(f"\n{'='*60}")
    print(f"EMAIL SIMULATION")
    print(f"{'='*60}")
    print(f"To: {to_email}")
    print(f"Subject: {subject}")
    print(f"Body:\n{body}")
    print(f"{'='*60}\n")

def sanitize_input(text):
    """Sanitize input to prevent XSS"""
    if not text:
        return ""
    import html
    return html.escape(str(text))

def allowed_file(filename, allowed_extensions):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def save_uploaded_file(file, upload_folder, user_id, file_type):
    """Save uploaded file with unique name"""
    if file and file.filename:
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        filename = f"{user_id}_{timestamp}_{file.filename}"
        filepath = os.path.join(upload_folder, filename)
        file.save(filepath)
        return filepath
    return None
