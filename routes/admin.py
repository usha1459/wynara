from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from database import db
from utils import generate_wapl_id, sanitize_input
from functools import wraps
import json
import os


admin_bp = Blueprint('admin', __name__)


# ==================== DECORATORS ====================


def require_admin_auth(f):
    """Require any admin (super or regular)"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            if request.path.startswith('/api'):
                return jsonify({'error': 'Admin access required'}), 403
            return redirect(url_for('admin.admin_login_page'))
        return f(*args, **kwargs)
    return wrapper


def require_super_admin_auth(f):
    """Require super admin only"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            if request.path.startswith('/api'):
                return jsonify({'error': 'Admin access required'}), 403
            return redirect(url_for('admin.admin_login_page'))
        
        if not session.get('is_super_admin', False):
            if request.path.startswith('/api'):
                return jsonify({'error': 'Super admin access required'}), 403
            return jsonify({'error': 'Insufficient permissions - Super admin only'}), 403
        
        return f(*args, **kwargs)
    return wrapper


# ==================== AUTH ROUTES ====================


@admin_bp.route('/api/auth/logout', methods=['POST', 'GET'])
def logout():
    """Logout - clears session"""
    try:
        session.clear()
        return jsonify({'message': 'Logged out successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/secure-admin-panel/wapl/logout')
def logout_redirect():
    """Logout page - clears session and redirects"""
    session.clear()
    return redirect('/secure-admin-panel/wapl/login')


# ==================== PAGE ROUTES ====================


@admin_bp.route('/secure-admin-panel/wapl/login')
def admin_login_page():
    """Admin login page"""
    if 'user_id' in session and session.get('role') == 'admin':
        return redirect('/secure-admin-panel/wapl/dashboard')
    return render_template('admin/login.html')


@admin_bp.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Admin login API"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = db.execute_query(
            "SELECT * FROM users WHERE email = ? AND role = 'admin'",
            (email,),
            fetch_one=True
        )
        
        if not user or not check_password_hash(user['password_hash'], password):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        admin = db.execute_query(
            "SELECT * FROM admins WHERE user_id = ?",
            (user['id'],),
            fetch_one=True
        )
        
        if not admin:
            return jsonify({'error': 'Admin profile not found'}), 404
        
        session['user_id'] = user['id']
        session['role'] = 'admin'
        session['email'] = user['email']
        session['is_super_admin'] = bool(admin['is_super_admin'])
        
        db.execute_query(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.now(), user['id'])
        )
        
        return jsonify({
            'message': 'Login successful',
            'redirect': '/secure-admin-panel/wapl/dashboard',
            'is_super_admin': bool(admin['is_super_admin'])
        }), 200
        
    except Exception as e:
        print(f"Admin login error: {e}")
        return jsonify({'error': 'An error occurred during login'}), 500


@admin_bp.route('/secure-admin-panel/wapl/dashboard')
@require_admin_auth
def admin_dashboard():
    """Admin dashboard page"""
    return render_template('admin/dashboard.html')


@admin_bp.route('/secure-admin-panel/wapl/students')
@require_admin_auth
def admin_students():
    """Students management page"""
    return render_template('admin/students.html')


@admin_bp.route('/secure-admin-panel/wapl/add-student')
@require_admin_auth
def add_student_page():
    """Add student page"""
    return render_template('admin/add_student.html')


@admin_bp.route('/secure-admin-panel/wapl/hrs')
@require_admin_auth
def admin_hrs():
    """HRs management page"""
    return render_template('admin/hrs.html')


@admin_bp.route('/secure-admin-panel/wapl/assign-students')
@require_admin_auth
def admin_assign_students():
    """Assign students to HR page"""
    return render_template('admin/assign_students.html')


@admin_bp.route('/secure-admin-panel/wapl/domains')
@require_super_admin_auth
def admin_domains():
    """Domains management page - Super Admin only"""
    return render_template('admin/domains.html')


@admin_bp.route('/secure-admin-panel/wapl/certificates')
@require_admin_auth
def admin_certificates():
    """Certificates management page"""
    return render_template('admin/certificates.html')


@admin_bp.route('/secure-admin-panel/wapl/recruitment')
@require_admin_auth
def admin_recruitment():
    """Recruitment management page"""
    return render_template('admin/recruitment.html')


@admin_bp.route('/secure-admin-panel/wapl/admins')
@require_super_admin_auth
def admin_admins_page():
    """Admin management page - Super Admin only"""
    return render_template('admin/admins.html')


# ==================== API ROUTES ====================


@admin_bp.route('/api/admin/check-super-admin', methods=['GET'])
@require_admin_auth
def check_super_admin():
    """Check if current admin is super admin"""
    return jsonify({'is_super_admin': session.get('is_super_admin', False)}), 200


@admin_bp.route('/api/admin/dashboard/stats', methods=['GET'])
@require_admin_auth
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        total_students = db.execute_query(
            "SELECT COUNT(*) as count FROM students",
            fetch_one=True
        )
        
        active_students = db.execute_query(
            "SELECT COUNT(*) as count FROM students WHERE account_status = 'active'",
            fetch_one=True
        )
        
        pending_students = db.execute_query(
            "SELECT COUNT(*) as count FROM students WHERE account_status = 'pending'",
            fetch_one=True
        )
        
        suspended_students = db.execute_query(
            "SELECT COUNT(*) as count FROM students WHERE account_status = 'suspended'",
            fetch_one=True
        )
        
        total_hrs = db.execute_query(
            "SELECT COUNT(*) as count FROM hrs",
            fetch_one=True
        )
        
        total_certificates = db.execute_query(
            "SELECT COUNT(*) as count FROM certificates",
            fetch_one=True
        )
        
        total_domains = db.execute_query(
            "SELECT COUNT(*) as count FROM domains WHERE is_active = 1",
            fetch_one=True
        )
        
        assigned_students = db.execute_query(
            "SELECT COUNT(*) as count FROM students WHERE assigned_hr_id IS NOT NULL",
            fetch_one=True
        )
        
        return jsonify({
            'total_students': total_students['count'] if total_students else 0,
            'active_students': active_students['count'] if active_students else 0,
            'pending_students': pending_students['count'] if pending_students else 0,
            'suspended_students': suspended_students['count'] if suspended_students else 0,
            'total_hrs': total_hrs['count'] if total_hrs else 0,
            'total_certificates': total_certificates['count'] if total_certificates else 0,
            'total_domains': total_domains['count'] if total_domains else 0,
            'assigned_students': assigned_students['count'] if assigned_students else 0
        }), 200
        
    except Exception as e:
        print(f"Error getting dashboard stats: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== ADMIN MANAGEMENT ROUTES ====================


@admin_bp.route('/api/admin/admins', methods=['GET'])
@require_super_admin_auth
def get_admins():
    """Get all admins - Super Admin only"""
    try:
        admins = db.execute_query("""
            SELECT 
                a.*,
                u.email,
                u.last_login,
                creator.full_name as created_by_name
            FROM admins a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN admins creator ON a.created_by_admin_id = creator.id
            ORDER BY a.is_super_admin DESC, a.full_name
        """, fetch_all=True)
        
        return jsonify(admins), 200
    except Exception as e:
        print(f"Error getting admins: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/admin/create', methods=['POST'])
@require_super_admin_auth
def create_admin():
    """Create new admin - Super Admin only"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        fullname = data.get('fullName', '').strip()
        phone = data.get('phone', '').strip()
        is_super_admin = data.get('isSuperAdmin', False)
        
        if not all([email, password, fullname, phone]):
            return jsonify({'error': 'All fields required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        existing = db.execute_query("SELECT id FROM users WHERE email = ?", (email,), fetch_one=True)
        if existing:
            return jsonify({'error': 'Email already registered'}), 400
        
        password_hash = generate_password_hash(password)
        user_id = db.execute_query(
            "INSERT INTO users (email, password_hash, role, is_verified) VALUES (?, ?, ?, ?)",
            (email, password_hash, 'admin', 1)
        )
        
        current_admin = db.execute_query("SELECT id FROM admins WHERE user_id = ?", (session['user_id'],), fetch_one=True)
        
        db.execute_query(
            "INSERT INTO admins (user_id, full_name, phone, is_super_admin, created_by_admin_id) VALUES (?, ?, ?, ?, ?)",
            (user_id, fullname, phone, 1 if is_super_admin else 0, current_admin['id'] if current_admin else None)
        )
        
        print(f"Admin created: {email}")
        return jsonify({'message': 'Admin created successfully'}), 201
    except Exception as e:
        print(f"Error creating admin: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/admin/<int:admin_id>', methods=['DELETE'])
@require_super_admin_auth
def delete_admin(admin_id):
    """Delete admin - Super Admin only"""
    try:
        admin = db.execute_query("SELECT is_super_admin, user_id, created_by_admin_id FROM admins WHERE id = ?", (admin_id,), fetch_one=True)
        if not admin:
            return jsonify({'error': 'Admin not found'}), 404
        
        if admin['is_super_admin']:
            return jsonify({'error': 'Cannot delete super admin'}), 403
        
        if not admin['created_by_admin_id']:
            return jsonify({'error': 'Cannot delete system administrator'}), 403
        
        current_admin = db.execute_query("SELECT id FROM admins WHERE user_id = ?", (session['user_id'],), fetch_one=True)
        if current_admin and current_admin['id'] == admin_id:
            return jsonify({'error': 'Cannot delete yourself'}), 403
        
        db.execute_query("DELETE FROM admins WHERE id = ?", (admin_id,))
        db.execute_query("DELETE FROM users WHERE id = ?", (admin['user_id'],))
        
        print(f"Admin {admin_id} deleted")
        return jsonify({'message': 'Admin deleted successfully'}), 200
    except Exception as e:
        print(f"Error deleting admin: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== STUDENT MANAGEMENT ROUTES ====================


@admin_bp.route('/api/admin/students', methods=['GET'])
@require_admin_auth
def get_students():
    """Get all students"""
    try:
        students = db.execute_query("""
            SELECT 
                s.*,
                u.email,
                h.full_name as hr_name,
                h.company_name as hr_company,
                GROUP_CONCAT(d.domain_name, ', ') as domain_names
            FROM students s
            LEFT JOIN users u ON s.user_id = u.id
            LEFT JOIN hrs h ON s.assigned_hr_id = h.id
            LEFT JOIN student_domains sd ON s.id = sd.student_id
            LEFT JOIN domains d ON sd.domain_id = d.id
            GROUP BY s.id
            ORDER BY s.registration_date DESC
        """, fetch_all=True)
        
        return jsonify(students), 200
    except Exception as e:
        print(f"Error getting students: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/student/create', methods=['POST'])
@require_admin_auth
def create_student():
    """Admin creates a student account directly - ACTIVE status"""
    try:
        data = request.get_json()
        email = sanitize_input(data.get('email', '').strip().lower())
        password = data.get('password', '')
        full_name = sanitize_input(data.get('fullName', '').strip())
        phone = sanitize_input(data.get('phone', '').strip())
        address = sanitize_input(data.get('address', '').strip())
        domain_ids = data.get('domainIds', [])
        
        print(f"📝 Creating student: {email}")
        print(f"📝 Domains: {domain_ids}")
        
        # Validation
        if not all([email, password, full_name, phone]):
            return jsonify({'error': 'Email, password, full name, and phone are required'}), 400
        
        if not domain_ids or len(domain_ids) == 0:
            return jsonify({'error': 'Please select at least one domain'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        # Check if email exists
        existing_user = db.execute_query(
            'SELECT id FROM users WHERE email = ?',
            (email,),
            fetch_one=True
        )
        
        if existing_user:
            # Check if user has a student profile
            existing_student = db.execute_query(
                'SELECT id FROM students WHERE user_id = ?',
                (existing_user['id'],),
                fetch_one=True
            )
            
            if existing_student:
                return jsonify({'error': 'Email already registered with a complete student profile'}), 400
            else:
                # User exists but no student profile - complete the registration
                print(f"⚠️ Found orphaned user, completing registration...")
                user_id = existing_user['id']
                
                # Update password in case it's different
                password_hash = generate_password_hash(password)
                db.execute_query(
                    'UPDATE users SET password_hash = ?, is_verified = 1 WHERE id = ?',
                    (password_hash, user_id)
                )
        else:
            # Create new user account
            password_hash = generate_password_hash(password)
            user_id = db.execute_query(
                'INSERT INTO users (email, password_hash, role, is_verified) VALUES (?, ?, ?, ?)',
                (email, password_hash, 'student', 1)
            )
            print(f"✅ User created with ID: {user_id}")
        
        # Validate domains
        for domain_id in domain_ids:
            domain = db.execute_query(
                'SELECT id FROM domains WHERE id = ? AND is_active = 1',
                (domain_id,),
                fetch_one=True
            )
            if not domain:
                return jsonify({'error': f'Invalid or inactive domain selected'}), 400
        
        # Generate WAPL ID
        wapl_id = generate_wapl_id()
        print(f"✅ Generated WAPL ID: {wapl_id}")
        
        # Create student record
        try:
            # Try new schema with address
            student_id = db.execute_query(
                '''INSERT INTO students 
                   (user_id, wapl_id, full_name, phone, address, account_status, registration_date)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (user_id, wapl_id, full_name, phone, address or '', 'active', datetime.now())
            )
            print(f"✅ Student profile created with ID: {student_id}")
        except Exception as schema_error:
            print(f"⚠️ New schema failed, trying old schema: {schema_error}")
            # Try old schema without address
            student_id = db.execute_query(
                '''INSERT INTO students 
                   (user_id, wapl_id, full_name, phone, account_status, registration_date)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (user_id, wapl_id, full_name, phone, 'active', datetime.now())
            )
            print(f"✅ Student profile created with ID: {student_id} (old schema)")
        
        # Assign domains
        try:
            for domain_id in domain_ids:
                db.execute_query(
                    "INSERT INTO student_domains (student_id, domain_id) VALUES (?, ?)",
                    (student_id, domain_id)
                )
            print(f"✅ Assigned {len(domain_ids)} domains via junction table")
        except Exception as domain_error:
            print(f"⚠️ Junction table failed, using old domain_id column: {domain_error}")
            # Fallback to old schema - single domain
            db.execute_query(
                "UPDATE students SET domain_id = ? WHERE id = ?",
                (domain_ids[0], student_id)
            )
            print(f"✅ Assigned domain {domain_ids[0]} via domain_id column")
        
        print(f"✅✅ Student created successfully: {email} (WAPL ID: {wapl_id})")
        
        return jsonify({
            'message': 'Student created successfully',
            'wapl_id': wapl_id,
            'status': 'active',
            'student_id': student_id
        }), 201
        
    except Exception as e:
        print(f"❌ Error creating student: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/student/<int:student_id>/status', methods=['PUT'])
@require_admin_auth
def update_student_status(student_id):
    """Update student account status"""
    try:
        data = request.get_json()
        status = data.get('status', '').strip()
        
        valid_statuses = ['pending', 'active', 'suspended', 'revoked']
        if status not in valid_statuses:
            return jsonify({'error': 'Invalid status'}), 400
        
        db.execute_query("UPDATE students SET account_status = ? WHERE id = ?", (status, student_id))
        
        print(f"Student {student_id} status changed to {status}")
        return jsonify({'message': 'Student status updated'}), 200
    except Exception as e:
        print(f"Error updating student status: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/student/<int:student_id>', methods=['DELETE'])
@require_admin_auth
def delete_student(student_id):
    """Delete student"""
    try:
        student = db.execute_query("SELECT user_id FROM students WHERE id = ?", (student_id,), fetch_one=True)
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        db.execute_query("DELETE FROM students WHERE id = ?", (student_id,))
        db.execute_query("DELETE FROM users WHERE id = ?", (student['user_id'],))
        
        print(f"Student {student_id} deleted")
        return jsonify({'message': 'Student deleted successfully'}), 200
    except Exception as e:
        print(f"Error deleting student: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== HR MANAGEMENT ROUTES ====================


@admin_bp.route('/api/admin/hrs', methods=['GET'])
@require_admin_auth
def get_hrs():
    """Get all HRs"""
    try:
        hrs = db.execute_query("""
            SELECT 
                h.*,
                u.email,
                (SELECT COUNT(*) FROM students WHERE assigned_hr_id = h.id) as assigned_count
            FROM hrs h
            LEFT JOIN users u ON h.user_id = u.id
            ORDER BY h.created_at DESC
        """, fetch_all=True)
        
        return jsonify(hrs), 200
    except Exception as e:
        print(f"Error getting HRs: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/hr/create', methods=['POST'])
@require_admin_auth
def create_hr():
    """Create new HR"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        fullname = data.get('fullName', '').strip()
        companyname = data.get('companyName', '').strip()
        phone = data.get('phone', '').strip()
        designation = data.get('designation', '').strip()
        
        if not all([email, password, fullname, companyname, phone, designation]):
            return jsonify({'error': 'All fields required'}), 400
        
        existing = db.execute_query("SELECT id FROM users WHERE email = ?", (email,), fetch_one=True)
        if existing:
            return jsonify({'error': 'Email already exists'}), 400
        
        password_hash = generate_password_hash(password)
        user_id = db.execute_query(
            "INSERT INTO users (email, password_hash, role, is_verified) VALUES (?, ?, ?, ?)",
            (email, password_hash, 'hr', 1)
        )
        
        current_admin = db.execute_query("SELECT id FROM admins WHERE user_id = ?", (session['user_id'],), fetch_one=True)
        
        db.execute_query(
            "INSERT INTO hrs (user_id, full_name, company_name, phone, designation, created_by_admin_id) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, fullname, companyname, phone, designation, current_admin['id'] if current_admin else None)
        )
        
        print(f"HR created: {email}")
        return jsonify({'message': 'HR created successfully'}), 201
    except Exception as e:
        print(f"Error creating HR: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/hr/<int:hr_id>', methods=['DELETE'])
@require_admin_auth
def delete_hr(hr_id):
    """Delete HR"""
    try:
        hr = db.execute_query("SELECT user_id FROM hrs WHERE id = ?", (hr_id,), fetch_one=True)
        if not hr:
            return jsonify({'error': 'HR not found'}), 404
        
        db.execute_query("DELETE FROM hrs WHERE id = ?", (hr_id,))
        db.execute_query("DELETE FROM users WHERE id = ?", (hr['user_id'],))
        
        print(f"HR {hr_id} deleted")
        return jsonify({'message': 'HR deleted successfully'}), 200
    except Exception as e:
        print(f"Error deleting HR: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/hr/<int:hr_id>/students', methods=['GET'])
@require_admin_auth
def get_hr_students(hr_id):
    """Get students assigned to specific HR"""
    try:
        students = db.execute_query("""
            SELECT 
                s.*,
                u.email,
                GROUP_CONCAT(d.domain_name, ', ') as domain_names
            FROM students s
            LEFT JOIN users u ON s.user_id = u.id
            LEFT JOIN student_domains sd ON s.id = sd.student_id
            LEFT JOIN domains d ON sd.domain_id = d.id
            WHERE s.assigned_hr_id = ?
            GROUP BY s.id
            ORDER BY s.full_name
        """, (hr_id,), fetch_all=True)
        
        return jsonify(students), 200
    except Exception as e:
        print(f"Error getting HR students: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== STUDENT ASSIGNMENT ROUTES ====================


@admin_bp.route('/api/admin/assign-students', methods=['POST'])
@require_admin_auth
def assign_students():
    """Assign students to HR"""
    try:
        data = request.get_json()
        hr_id = data.get('hrId')
        student_ids = data.get('studentIds', [])
        
        if not hr_id or not student_ids:
            return jsonify({'error': 'HR ID and student IDs required'}), 400
        
        hr = db.execute_query("SELECT id FROM hrs WHERE id = ?", (hr_id,), fetch_one=True)
        if not hr:
            return jsonify({'error': 'HR not found'}), 404
        
        for student_id in student_ids:
            db.execute_query("UPDATE students SET assigned_hr_id = ? WHERE id = ?", (hr_id, student_id))
        
        print(f"{len(student_ids)} students assigned to HR {hr_id}")
        return jsonify({'message': f'{len(student_ids)} students assigned successfully'}), 200
    except Exception as e:
        print(f"Error assigning students: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/unassign-students', methods=['POST'])
@require_admin_auth
def unassign_students():
    """Unassign students from HR"""
    try:
        data = request.get_json()
        student_ids = data.get('studentIds', [])
        
        if not student_ids:
            return jsonify({'error': 'Student IDs required'}), 400
        
        for student_id in student_ids:
            db.execute_query("UPDATE students SET assigned_hr_id = NULL WHERE id = ?", (student_id,))
        
        print(f"{len(student_ids)} students unassigned")
        return jsonify({'message': f'{len(student_ids)} students unassigned successfully'}), 200
    except Exception as e:
        print(f"Error unassigning students: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/students/unassigned', methods=['GET'])
@require_admin_auth
def get_unassigned_students():
    """Get students not assigned to any HR"""
    try:
        students = db.execute_query("""
            SELECT 
                s.*,
                u.email,
                GROUP_CONCAT(d.domain_name, ', ') as domain_names
            FROM students s
            LEFT JOIN users u ON s.user_id = u.id
            LEFT JOIN student_domains sd ON s.id = sd.student_id
            LEFT JOIN domains d ON sd.domain_id = d.id
            WHERE s.assigned_hr_id IS NULL AND s.account_status = 'active'
            GROUP BY s.id
            ORDER BY s.full_name
        """, fetch_all=True)
        
        return jsonify(students), 200
    except Exception as e:
        print(f"Error getting unassigned students: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== DOMAIN MANAGEMENT ROUTES ====================


@admin_bp.route('/api/admin/domains', methods=['GET'])
def get_domains():
    """Get all domains - PUBLIC ACCESS for registration"""
    try:
        domains = db.execute_query("SELECT * FROM domains ORDER BY domain_name", fetch_all=True)
        return jsonify(domains), 200
    except Exception as e:
        print(f"Error getting domains: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/domain/create', methods=['POST'])
@require_super_admin_auth
def create_domain():
    """Create new domain - Super Admin only"""
    try:
        data = request.get_json()
        domain_name = data.get('domainName', '').strip()
        
        if not domain_name:
            return jsonify({'error': 'Domain name required'}), 400
        
        existing = db.execute_query(
            "SELECT id FROM domains WHERE LOWER(domain_name) = LOWER(?)",
            (domain_name,),
            fetch_one=True
        )
        if existing:
            return jsonify({'error': 'Domain already exists'}), 400
        
        current_admin = db.execute_query("SELECT id FROM admins WHERE user_id = ?", (session['user_id'],), fetch_one=True)
        
        db.execute_query(
            "INSERT INTO domains (domain_name, is_active, created_by_admin_id) VALUES (?, 1, ?)",
            (domain_name, current_admin['id'] if current_admin else None)
        )
        
        print(f"Domain '{domain_name}' created successfully")
        return jsonify({'message': 'Domain created successfully'}), 201
    except Exception as e:
        print(f"Error creating domain: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/domain/<int:domain_id>/status', methods=['PUT'])
@require_super_admin_auth
def update_domain_status(domain_id):
    """Toggle domain active status - Super Admin only"""
    try:
        data = request.get_json()
        is_active = data.get('isActive', False)
        
        domain = db.execute_query("SELECT * FROM domains WHERE id = ?", (domain_id,), fetch_one=True)
        if not domain:
            return jsonify({'error': 'Domain not found'}), 404
        
        db.execute_query("UPDATE domains SET is_active = ? WHERE id = ?", (1 if is_active else 0, domain_id))
        
        action = 'activated' if is_active else 'deactivated'
        print(f"Domain {domain_id} {action}")
        return jsonify({'message': f'Domain {action} successfully'}), 200
    except Exception as e:
        print(f"Error updating domain status: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/domain/<int:domain_id>', methods=['DELETE'])
@require_super_admin_auth
def delete_domain(domain_id):
    """Delete domain - Super Admin only"""
    try:
        domain = db.execute_query("SELECT domain_name FROM domains WHERE id = ?", (domain_id,), fetch_one=True)
        if not domain:
            return jsonify({'error': 'Domain not found'}), 404
        
        students_count = db.execute_query(
            "SELECT COUNT(*) as count FROM student_domains WHERE domain_id = ?",
            (domain_id,),
            fetch_one=True
        )
        
        if students_count and students_count['count'] > 0:
            return jsonify({'error': f'Cannot delete domain. {students_count["count"]} student(s) are assigned'}), 400
        
        db.execute_query("DELETE FROM domains WHERE id = ?", (domain_id,))
        
        print(f"Domain '{domain['domain_name']}' deleted")
        return jsonify({'message': f'Domain deleted successfully'}), 200
    except Exception as e:
        print(f"Error deleting domain: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== CERTIFICATE MANAGEMENT ROUTES ====================


@admin_bp.route('/api/admin/students/without-certificates', methods=['GET'])
@require_admin_auth
def get_students_without_certificates():
    """Get all active students without certificates"""
    try:
        students = db.execute_query("""
            SELECT 
                s.*,
                u.email,
                GROUP_CONCAT(d.domain_name, ', ') as domain_names
            FROM students s
            JOIN users u ON s.user_id = u.id
            LEFT JOIN student_domains sd ON s.id = sd.student_id
            LEFT JOIN domains d ON sd.domain_id = d.id
            LEFT JOIN certificates c ON s.id = c.student_id AND c.is_active = 1
            WHERE s.account_status = 'active' AND c.id IS NULL
            GROUP BY s.id
            ORDER BY s.registration_date DESC
        """, fetch_all=True)
        
        return jsonify(students), 200
    except Exception as e:
        print(f"Error getting students without certificates: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/certificates', methods=['GET'])
@require_admin_auth
def get_certificates():
    """Get all certificates"""
    try:
        certificates = db.execute_query("""
            SELECT 
                c.*,
                s.full_name,
                s.wapl_id,
                GROUP_CONCAT(d.domain_name, ', ') as domain_names
            FROM certificates c
            LEFT JOIN students s ON c.student_id = s.id
            LEFT JOIN student_domains sd ON s.id = sd.student_id
            LEFT JOIN domains d ON sd.domain_id = d.id
            GROUP BY c.id
            ORDER BY c.issue_date DESC
        """, fetch_all=True)
        
        return jsonify(certificates), 200
    except Exception as e:
        print(f"Error getting certificates: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/certificates/issue', methods=['POST'])
@require_admin_auth
def issue_certificates():
    """Issue certificates to students with QR code and PDF generation"""
    try:
        from utils import generate_certificate_id, generate_qr_code, generate_certificate_pdf
        
        data = request.get_json()
        student_ids = data.get('studentIds', [])
        
        if not student_ids:
            return jsonify({'error': 'Student IDs required'}), 400
        
        # Create directories if they don't exist
        os.makedirs('uploads/certificates', exist_ok=True)
        os.makedirs('uploads/qr_codes', exist_ok=True)
        
        issued_count = 0
        errors = []
        
        for student_id in student_ids:
            try:
                # Get student details with domains
                student = db.execute_query("""
                    SELECT 
                        s.*,
                        u.email,
                        GROUP_CONCAT(d.domain_name, ', ') as domain_names
                    FROM students s
                    LEFT JOIN users u ON s.user_id = u.id
                    LEFT JOIN student_domains sd ON s.id = sd.student_id
                    LEFT JOIN domains d ON sd.domain_id = d.id
                    WHERE s.id = ?
                    GROUP BY s.id
                """, (student_id,), fetch_one=True)
                
                if not student:
                    errors.append(f"Student ID {student_id} not found")
                    continue
                
                # Check if already has active certificate
                existing_cert = db.execute_query(
                    "SELECT id FROM certificates WHERE student_id = ? AND is_active = 1",
                    (student_id,),
                    fetch_one=True
                )
                
                if existing_cert:
                    errors.append(f"{student['full_name']} already has an active certificate")
                    continue
                
                # Generate unique certificate ID
                cert_unique_id = generate_certificate_id()
                
                # Set dates
                issue_date = datetime.now()
                expiry_date = issue_date + timedelta(days=365)
                
                # Format dates for display
                issue_date_str = issue_date.strftime('%d %B %Y')
                expiry_date_str = expiry_date.strftime('%d %B %Y')
                
                # Generate QR code
                qr_data = f"https://wapl.com/verify/{cert_unique_id}"
                qr_code_path = f'uploads/qr_codes/{cert_unique_id}_qr.png'
                generate_qr_code(qr_data, qr_code_path)
                
                # Generate PDF certificate using your template
                pdf_path = f'uploads/certificates/{cert_unique_id}.pdf'
                
                domain_display = student['domain_names'] if student['domain_names'] else 'General Training'
                
                generate_certificate_pdf(
                    student_name=student['full_name'],
                    wapl_id=student['wapl_id'],
                    domain_name=domain_display,
                    issue_date=issue_date_str,
                    expiry_date=expiry_date_str,
                    qr_code_path=qr_code_path,
                    output_path=pdf_path,
                    hr_name=None,
                    certificate_text=f"This certificate recognizes the candidate's hands-on experience in {domain_display} and successful assessment by WAPL."
                )
                
                # Insert certificate into database
                db.execute_query("""
                    INSERT INTO certificates 
                    (student_id, certificate_unique_id, issue_date, expiry_date, 
                     qr_code, pdf_path, is_active, display_name) 
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """, (
                    student_id,
                    cert_unique_id,
                    issue_date,
                    expiry_date,
                    qr_code_path,
                    pdf_path,
                    student['full_name']
                ))
                
                # Update student record
                db.execute_query("""
                    UPDATE students 
                    SET certificate_issued_date = ?, certificate_expiry_date = ? 
                    WHERE id = ?
                """, (issue_date, expiry_date, student_id))
                
                issued_count += 1
                print(f"✅ Certificate {cert_unique_id} issued to {student['full_name']}")
                
            except Exception as student_error:
                error_msg = f"Error for {student.get('full_name', f'student {student_id}') if 'student' in locals() else f'student {student_id}'}: {str(student_error)}"
                errors.append(error_msg)
                print(f"❌ {error_msg}")
        
        # Prepare response message
        if issued_count == 0 and errors:
            return jsonify({'error': '; '.join(errors)}), 400
        
        message = f'{issued_count} certificate(s) issued successfully'
        if errors:
            message += f'. Warnings: {"; ".join(errors)}'
        
        return jsonify({
            'message': message, 
            'issued_count': issued_count,
            'errors': errors if errors else None
        }), 201
        
    except Exception as e:
        print(f"❌ Error issuing certificates: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ==================== RECRUITMENT ROUTES ====================


@admin_bp.route('/api/admin/recruitment', methods=['GET'])
@require_admin_auth
def get_recruitment_stats():
    """Get recruitment statistics"""
    try:
        records = db.execute_query("""
            SELECT 
                r.*,
                s.full_name as student_name,
                s.wapl_id,
                h.full_name as hr_name,
                h.company_name
            FROM recruitment_status r
            LEFT JOIN students s ON r.student_id = s.id
            LEFT JOIN hrs h ON r.hr_id = h.id
            ORDER BY r.updated_at DESC
        """, fetch_all=True)
        
        return jsonify(records), 200
    except Exception as e:
        print(f"Error getting recruitment stats: {e}")
        return jsonify({'error': str(e)}), 500
