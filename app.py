from flask import Flask, render_template, redirect, url_for, session, send_from_directory
from flask_session import Session
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

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

# Use /tmp directory on Vercel or Render (writable), local directory otherwise
if os.environ.get('VERCEL') or os.environ.get('RENDER'):
    app.config['SESSION_FILE_DIR'] = '/tmp/flask_session'
else:
    app.config['SESSION_FILE_DIR'] = './flask_session'

app.config['SESSION_PERMANENT'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file upload


# Initialize session
Session(app)


# ==================== DIRECTORY SETUP ====================


def ensure_directories():
    """Create necessary directories if they don't exist"""
    # Use /tmp on Vercel/Render for writable storage, local directory otherwise
    if os.environ.get('VERCEL') == 'True' or os.environ.get('RENDER'):
        base_path = '/tmp'
    else:
        base_path = '.'
    
    directories = [
        f'{base_path}/uploads/profile_pics',
        f'{base_path}/uploads/resumes',
        f'{base_path}/uploads/certificates',
        f'{base_path}/uploads/qr_codes',
        f'{base_path}/flask_session',
        f'{base_path}/fonts'
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"✓ Directory ensured: {directory}")
        except Exception as e:
            print(f"⚠ Warning: Could not create directory {directory}: {e}")
    
    return base_path


# Create directories and get base path for uploads
UPLOAD_BASE_PATH = ensure_directories()


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


# ==================== FILE SERVING ====================


@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    """Serve uploaded files (profile pics, resumes, certificates, QR codes)"""
    uploads_dir = os.path.join(UPLOAD_BASE_PATH, 'uploads')
    
    # Determine MIME type based on file extension
    if filename.lower().endswith('.pdf'):
        mime_type = 'application/pdf'
    elif filename.lower().endswith(('.jpg', '.jpeg')):
        mime_type = 'image/jpeg'
    elif filename.lower().endswith('.png'):
        mime_type = 'image/png'
    else:
        mime_type = 'application/octet-stream'
    
    return send_from_directory(uploads_dir, filename, mimetype=mime_type)


@app.route('/download/<path:filename>')
def download_file(filename):
    """Download uploaded files as attachments (forces download instead of view)"""
    uploads_dir = os.path.join(UPLOAD_BASE_PATH, 'uploads')
    
    # Determine MIME type based on file extension
    if filename.lower().endswith('.pdf'):
        mime_type = 'application/pdf'
    elif filename.lower().endswith(('.jpg', '.jpeg')):
        mime_type = 'image/jpeg'
    elif filename.lower().endswith('.png'):
        mime_type = 'image/png'
    else:
        mime_type = 'application/octet-stream'
    
    # Use as_attachment=True to force download
    return send_from_directory(
        uploads_dir, 
        filename, 
        mimetype=mime_type,
        as_attachment=True,
        download_name=filename.split('_', 2)[-1] if '_' in filename else filename
    )


# ==================== CONTEXT PROCESSOR ====================

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
    
    # Get port from environment or default to 5000
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'False') == 'True'
    
    print(f"\n📍 Server starting on http://0.0.0.0:{port}")
    print(f"🔧 Debug mode: {debug_mode}")
    print("="*60 + "\n")
    
    # Run the Flask development server
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug_mode
    )
