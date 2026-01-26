import sqlite3
import os
from datetime import datetime
from werkzeug.security import generate_password_hash
from contextlib import contextmanager
import secrets
import string


# Use /tmp directory on Vercel/Render (serverless), current directory locally
if os.environ.get('VERCEL') or os.environ.get('RENDER'):
    DB_NAME = '/tmp/wapl.db'
else:
    DB_NAME = 'wapl.db'

@contextmanager
def get_db_connection():
    """Get database connection with proper timeout and WAL mode"""
    conn = None
    try:
        # Add 30-second timeout to prevent lock errors
        conn = sqlite3.connect(DB_NAME, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for better concurrency
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA busy_timeout=30000')  # 30 seconds
        yield conn
    except Exception as e:
        if conn:
            conn.rollback()
        raise e
    finally:
        if conn:
            conn.close()

def init_db():
    """Initialize database with all tables"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('student', 'hr', 'admin')),
                is_verified BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME
            )
        ''')
        
        # Domains table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_name TEXT NOT NULL UNIQUE,
                is_active BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_by_admin_id INTEGER
            )
        ''')
        
        # Admins table (WITH is_super_admin)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                full_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                is_super_admin INTEGER DEFAULT 0,
                created_by_admin_id INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (created_by_admin_id) REFERENCES admins(id)
            )
        ''')
        
        # Add is_super_admin column if it doesn't exist
        try:
            cursor.execute("ALTER TABLE admins ADD COLUMN is_super_admin INTEGER DEFAULT 0")
            print("✅ Added is_super_admin column to admins table")
        except Exception:
            pass
        
        # Add created_by_admin_id column if it doesn't exist
        try:
            cursor.execute("ALTER TABLE admins ADD COLUMN created_by_admin_id INTEGER")
            print("✅ Added created_by_admin_id column to admins table")
        except Exception:
            pass
        
        # HRs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hrs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                full_name TEXT NOT NULL,
                company_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                designation TEXT NOT NULL,
                created_by_admin_id INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (created_by_admin_id) REFERENCES admins(id)
            )
        ''')
        
        # Students table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                wapl_id TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                profile_pic TEXT,
                resume TEXT,
                domain_id INTEGER,
                registration_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                certificate_issued_date DATETIME,
                certificate_expiry_date DATETIME,
                assigned_hr_id INTEGER,
                address TEXT,
                education_details TEXT,
                skills TEXT,
                projects TEXT,
                account_status TEXT NOT NULL DEFAULT 'pending',
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (domain_id) REFERENCES domains(id),
                FOREIGN KEY (assigned_hr_id) REFERENCES hrs(id)
            )
        ''')

        # Ensure account_status column exists
        try:
            cursor.execute("ALTER TABLE students ADD COLUMN account_status TEXT NOT NULL DEFAULT 'pending'")
            print("✅ Added account_status column to students table")
        except Exception:
            pass
        
        # Set default status for existing rows
        cursor.execute("UPDATE students SET account_status = COALESCE(account_status, 'pending') WHERE account_status IS NULL OR account_status = ''")
        
        # Student-Domain junction table (MANY-TO-MANY)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS student_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                domain_id INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
                FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
                UNIQUE(student_id, domain_id)
            )
        ''')
        
        # OTP verifications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS otp_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                otp_code TEXT NOT NULL,
                purpose TEXT NOT NULL CHECK(purpose IN ('registration', 'login', 'password_reset')),
                is_used BOOLEAN DEFAULT 0,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Certificates table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                certificate_unique_id TEXT UNIQUE NOT NULL,
                issue_date DATETIME NOT NULL,
                expiry_date DATETIME NOT NULL,
                qr_code TEXT NOT NULL,
                pdf_path TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                issued_by_hr_id INTEGER,
                display_name TEXT,
                FOREIGN KEY (student_id) REFERENCES students(id),
                FOREIGN KEY (issued_by_hr_id) REFERENCES hrs(id)
            )
        ''')

        # Ensure display_name column exists
        try:
            cursor.execute("ALTER TABLE certificates ADD COLUMN display_name TEXT")
            print("✅ Added display_name column to certificates table")
        except Exception:
            pass

        # Ensure issued_by_hr_id column exists
        try:
            cursor.execute("ALTER TABLE certificates ADD COLUMN issued_by_hr_id INTEGER")
            print("✅ Added issued_by_hr_id column to certificates table")
        except Exception:
            pass

        # Certificate audit trail table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificate_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                certificate_id INTEGER NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('activate','deactivate')),
                reason TEXT,
                changed_by_admin_id INTEGER,
                changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (certificate_id) REFERENCES certificates(id),
                FOREIGN KEY (changed_by_admin_id) REFERENCES admins(id)
            )
        ''')
        
        # Recruitment status table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS recruitment_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                hr_id INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('viewed', 'shortlisted', 'interview_scheduled', 'selected', 'rejected')),
                notes TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES students(id),
                FOREIGN KEY (hr_id) REFERENCES hrs(id),
                UNIQUE(student_id, hr_id)
            )
        ''')
        
        conn.commit()
        
        # Pre-populate domains
        default_domains = ['AI', 'ML', 'DevOps', 'Web Development', 'Data Science']
        for domain in default_domains:
            cursor.execute('''
                INSERT OR IGNORE INTO domains (domain_name, is_active, created_by_admin_id)
                VALUES (?, 1, NULL)
            ''', (domain,))
        
        # Create default SUPER admin account
        admin_email = 'admin@wapl.com'
        admin_password_hash = generate_password_hash('admin123')
        
        cursor.execute('SELECT id FROM users WHERE email = ?', (admin_email,))
        admin_user = cursor.fetchone()
        
        if not admin_user:
            cursor.execute('''
                INSERT INTO users (email, password_hash, role, is_verified)
                VALUES (?, ?, 'admin', 1)
            ''', (admin_email, admin_password_hash))
            
            admin_user_id = cursor.lastrowid
            
            cursor.execute('''
                INSERT INTO admins (user_id, full_name, phone, is_super_admin)
                VALUES (?, 'Super Admin', '1234567890', 1)
            ''', (admin_user_id,))
            
            print("✅ Default Super Admin created (Email: admin@wapl.com, Password: admin123)")
        else:
            # Make existing admin a super admin
            cursor.execute('SELECT id FROM admins WHERE user_id = ?', (admin_user['id'],))
            admin_profile = cursor.fetchone()
            if admin_profile:
                cursor.execute('UPDATE admins SET is_super_admin = 1 WHERE user_id = ?', (admin_user['id'],))
                print("✅ Existing admin promoted to Super Admin")
        
        conn.commit()
        print("✅ Database initialized successfully with WAL mode enabled!")

# Database helper class
# Database helper class
class db:
    @staticmethod
    def execute_query(query, params=(), fetch_one=False, fetch_all=False):
        """Execute query with proper connection handling"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            # Determine if this is a write operation
            is_write = query.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER', 'DROP'))
            
            if fetch_one:
                result = cursor.fetchone()
                if is_write:
                    conn.commit()
                return dict(result) if result else None
            elif fetch_all:
                results = cursor.fetchall()
                if is_write:
                    conn.commit()
                return [dict(row) for row in results]
            else:
                # For INSERT/UPDATE/DELETE operations
                last_id = cursor.lastrowid
                conn.commit()  # Commit BEFORE returning
                return last_id
    
    @staticmethod
    def execute_many(query, params_list):
        """Execute multiple queries with proper connection handling"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(query, params_list)
            conn.commit()
