from flask import Blueprint, request, jsonify, session, redirect, url_for, send_file
from datetime import datetime
from database import db
from utils import sanitize_input, generate_certificate_id, generate_qr_code, generate_certificate_pdf
import json
import os

hr_bp = Blueprint('hr', __name__)

def require_hr_auth(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'hr':
            from flask import redirect, url_for, request
            # Check if it's an API request
            if request.path.startswith('/api/'):
                return jsonify({'error': 'HR access required'}), 403
            # Otherwise redirect to login
            return redirect(url_for('auth.login_page'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@hr_bp.route('/api/hr/students', methods=['GET'])
@require_hr_auth
def get_students():
    try:
        user_id = session['user_id']
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Get assigned students
        students = db.execute_query(
            '''SELECT s.*, d.domain_name, u.email 
               FROM students s
               LEFT JOIN domains d ON s.domain_id = d.id
               LEFT JOIN users u ON s.user_id = u.id
               WHERE s.assigned_hr_id = ? AND s.account_status = 'active'
               ORDER BY s.full_name''',
            (hr_id,),
            fetch_all=True
        )
        
        # Parse JSON fields and get recruitment status
        result = []
        for student in students:
            student_dict = dict(student)
            student_dict['education_details'] = json.loads(student['education_details']) if student['education_details'] else []
            student_dict['skills'] = json.loads(student['skills']) if student['skills'] else []
            student_dict['projects'] = json.loads(student['projects']) if student['projects'] else []
            
            # Get recruitment status
            status = db.execute_query(
                'SELECT status, notes FROM recruitment_status WHERE student_id = ? AND hr_id = ?',
                (student['id'], hr_id),
                fetch_one=True
            )
            student_dict['recruitment_status'] = status['status'] if status else 'viewed'
            student_dict['recruitment_notes'] = status['notes'] if status else ''
            
            result.append(student_dict)
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/student/<int:student_id>', methods=['GET'])
@require_hr_auth
def get_student(student_id):
    try:
        user_id = session['user_id']
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Get student (only if assigned to this HR)
        student = db.execute_query(
            '''SELECT s.*, d.domain_name, u.email 
               FROM students s
               LEFT JOIN domains d ON s.domain_id = d.id
               LEFT JOIN users u ON s.user_id = u.id
               WHERE s.id = ? AND s.assigned_hr_id = ? AND s.account_status = 'active' ''',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404
        
        # Get active certificate
        certificate = db.execute_query(
            '''SELECT * FROM certificates 
               WHERE student_id = ? AND expiry_date > ? AND is_active = 1
               ORDER BY issue_date DESC LIMIT 1''',
            (student_id, datetime.now()),
            fetch_one=True
        )
        
        student_dict = dict(student)
        student_dict['education_details'] = json.loads(student['education_details']) if student['education_details'] else []
        student_dict['skills'] = json.loads(student['skills']) if student['skills'] else []
        student_dict['projects'] = json.loads(student['projects']) if student['projects'] else []
        student_dict['certificate'] = dict(certificate) if certificate else None
        
        return jsonify(student_dict), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/students/filter', methods=['GET'])
@require_hr_auth
def filter_students():
    try:
        user_id = session['user_id']
        domain_id = request.args.get('domain_id')
        skills_filter = request.args.get('skills', '')
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Build query
        query = '''SELECT s.*, d.domain_name, u.email 
                   FROM students s
                   LEFT JOIN domains d ON s.domain_id = d.id
                   LEFT JOIN users u ON s.user_id = u.id
               WHERE s.assigned_hr_id = ? AND s.account_status = 'active' '''
        params = [hr_id]
        
        if domain_id:
            query += ' AND s.domain_id = ?'
            params.append(domain_id)
        
        if skills_filter:
            query += ' AND s.skills LIKE ?'
            params.append(f'%{skills_filter}%')
        
        query += ' ORDER BY s.full_name'
        
        students = db.execute_query(query, tuple(params), fetch_all=True)
        
        # Parse JSON fields
        result = []
        for student in students:
            student_dict = dict(student)
            student_dict['education_details'] = json.loads(student['education_details']) if student['education_details'] else []
            student_dict['skills'] = json.loads(student['skills']) if student['skills'] else []
            student_dict['projects'] = json.loads(student['projects']) if student['projects'] else []
            result.append(student_dict)
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/student/<int:student_id>/resume/download', methods=['GET'])
@require_hr_auth
def download_student_resume(student_id):
    try:
        user_id = session['user_id']
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Get student (verify it's assigned to this HR)
        student = db.execute_query(
            'SELECT resume, full_name, wapl_id FROM students WHERE id = ? AND assigned_hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404
        
        if not student['resume']:
            return jsonify({'error': 'Student has not uploaded a resume'}), 404
        
        if not os.path.exists(student['resume']):
            return jsonify({'error': 'Resume file not found'}), 404
        
        # Get file extension
        file_ext = os.path.splitext(student['resume'])[1]
        return send_file(student['resume'], as_attachment=True, download_name=f"{student['wapl_id']}_{student['full_name']}_resume{file_ext}")
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/student/<int:student_id>/status', methods=['GET'])
@require_hr_auth
def get_student_recruitment_status(student_id):
    try:
        user_id = session['user_id']
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Verify student is assigned to this HR
        student = db.execute_query(
            'SELECT id FROM students WHERE id = ? AND assigned_hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404
        
        # Get recruitment status
        status = db.execute_query(
            '''SELECT * FROM recruitment_status 
               WHERE student_id = ? AND hr_id = ?''',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if status:
            return jsonify(dict(status)), 200
        else:
            return jsonify({'status': 'viewed', 'notes': ''}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/student/<int:student_id>/status', methods=['POST'])
@require_hr_auth
def update_student_recruitment_status(student_id):
    try:
        user_id = session['user_id']
        data = request.get_json()
        
        # Validate input
        status = sanitize_input(data.get('status', ''))
        notes = sanitize_input(data.get('notes', ''))
        
        valid_statuses = ['viewed', 'shortlisted', 'interview_scheduled', 'selected', 'rejected']
        if status not in valid_statuses:
            return jsonify({'error': 'Invalid status'}), 400
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Verify student is assigned to this HR
        student = db.execute_query(
            'SELECT id FROM students WHERE id = ? AND assigned_hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404
        
        # Check if status record exists
        existing = db.execute_query(
            'SELECT id FROM recruitment_status WHERE student_id = ? AND hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if existing:
            # Update existing record
            db.execute_query(
                '''UPDATE recruitment_status 
                   SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
                   WHERE student_id = ? AND hr_id = ?''',
                (status, notes, student_id, hr_id)
            )
        else:
            # Create new record
            db.execute_query(
                '''INSERT INTO recruitment_status (student_id, hr_id, status, notes)
                   VALUES (?, ?, ?, ?)''',
                (student_id, hr_id, status, notes)
            )
        
        return jsonify({'message': 'Status updated successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/hr/dashboard')
@require_hr_auth
def hr_dashboard():
    from flask import render_template
    return render_template('hr/dashboard.html')

@hr_bp.route("/hr/profile")
def hr_profile():
    from flask import render_template
    return render_template("hr/profile.html")

@hr_bp.route('/hr/students')
@require_hr_auth
def hr_students():
    from flask import render_template
    return render_template('hr/students.html')

@hr_bp.route('/hr/student/<int:student_id>')
@require_hr_auth
def hr_student_detail(student_id):
    from flask import render_template
    return render_template('hr/student_detail.html')
@hr_bp.route('/api/hr/issue-certificate/<int:student_id>', methods=['POST'])
@require_hr_auth
def issue_certificate(student_id):
    """Issue a custom certificate for a student"""
    try:
        user_id = session['user_id']
        data = request.get_json()
        
        # Get HR ID and details
        hr = db.execute_query(
            'SELECT id, full_name, company_name FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        hr_name = hr['full_name']
        
        # Verify student is assigned to this HR
        student = db.execute_query(
            '''SELECT s.*, d.domain_name FROM students s
               LEFT JOIN domains d ON s.domain_id = d.id
               WHERE s.id = ? AND s.assigned_hr_id = ?''',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404
        
        # Validate certificate data
        certificate_text = sanitize_input(data.get('certificate_text', ''))
        if not certificate_text:
            return jsonify({'error': 'Certificate text is required'}), 400
        
        # Generate certificate
        cert_unique_id = generate_certificate_id()
        issue_date = datetime.now()
        expiry_date = issue_date.replace(year=issue_date.year + 1)
        
        # Generate QR code
        qr_data = f"{request.host_url}verify-certificate/{cert_unique_id}"
        qr_code_path = os.path.join('uploads', 'qr_codes', f'{cert_unique_id}.png')
        os.makedirs(os.path.dirname(qr_code_path), exist_ok=True)
        # QR links back to the public verifier so printed copies remain verifiable
        generate_qr_code(qr_data, qr_code_path)
        
        # Generate PDF certificate with custom text and HR name
        pdf_path = os.path.join('uploads', 'certificates', f'{cert_unique_id}.pdf')
        os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
        generate_certificate_pdf(
            student['full_name'],
            student['wapl_id'],
            student['domain_name'],
            issue_date.strftime('%Y-%m-%d'),
            expiry_date.strftime('%Y-%m-%d'),
            qr_code_path,
            pdf_path,
            hr_name=hr_name,
            certificate_text=certificate_text
        )
        
        # Create certificate record
        db.execute_query(
            '''INSERT INTO certificates 
               (student_id, certificate_unique_id, issue_date, expiry_date, qr_code, pdf_path, issued_by_hr_id)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (
                student_id,
                cert_unique_id,
                issue_date,
                expiry_date,
                qr_code_path,
                pdf_path,
                hr_id
            )
        )
        
        # Update student certificate dates
        db.execute_query(
            '''UPDATE students 
               SET certificate_issued_date = ?, certificate_expiry_date = ?
               WHERE id = ?''',
            (issue_date, expiry_date, student_id)
        )
        
        return jsonify({
            'message': 'Certificate issued successfully',
            'certificate_id': cert_unique_id,
            'pdf_url': f'/uploads/certificates/{cert_unique_id}.pdf'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500