from flask import Flask, render_template, redirect, url_for, session
from flask_session import Session
import os


# Import database
from database import init_db, db


# Import blueprints
from routes.auth import auth_bp
from routes.student import student_bp
from routes.admin import admin_bp
from routes.hr import hr_bp
from routes.public import public_bp


# Initialize Flask app
app = Flask(__name__)


# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '4912607a8134bfce8bc6f56c27071068ffd364ed38b905ccf61d69bb9d9df861')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_session'
app.config['SESSION_PERMANENT'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file upload


# Initialize session
Session(app)


# ==================== DIRECTORY SETUP ====================


def ensure_directories():
    """Create necessary directories if they don't exist"""
    directories = [
        'uploads/profile_pics',
        'uploads/resumes',
        'uploads/certificates',
        'uploads/qr_codes',
        'flask_session',
        'fonts'
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"✓ Directory ensured: {directory}")
        except Exception as e:
            print(f"⚠ Warning: Could not create directory {directory}: {e}")


# Create directories on startup
ensure_directories()


# Initialize database
init_db()


# ==================== REGISTER BLUEPRINTS ====================


app.register_blueprint(auth_bp)
app.register_blueprint(student_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(hr_bp)
app.register_blueprint(public_bp)


# ==================== ERROR HANDLERS ====================


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


@app.errorhandler(413)
def file_too_large(error):
    return {'error': 'File size exceeds maximum limit'}, 413


# ==================== ROOT ROUTE ====================


@app.route('/')
def index():
    """Homepage route"""
    if 'user_id' in session:
        role = session.get('role')
        if role == 'student':
            return redirect(url_for('student.student_dashboard'))
        elif role == 'admin':
            return redirect(url_for('admin.admin_dashboard'))
        elif role == 'hr':
            return redirect(url_for('hr.hr_dashboard'))
    
    return render_template('index.html')


# ==================== CONTEXT PROCESSOR ====================


@app.context_processor
def inject_user():
    """Make user info available in all templates"""
    return {
        'logged_in': 'user_id' in session,
        'user_role': session.get('role'),
        'user_id': session.get('user_id')
    }


# ==================== APPLICATION STARTUP ====================


if __name__ == '__main__':
    # Display startup message
    print("\n" + "="*60)
    print("🚀 Starting WAPL ID Management System")
    print("="*60)
    print("✅ Database initialized successfully")
    print("\n📍 Server starting on http://localhost:5000")
    print("📍 Network: http://0.0.0.0:5000")
    print("="*60 + "\n")
    
    # Run the Flask development server
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )

app = app