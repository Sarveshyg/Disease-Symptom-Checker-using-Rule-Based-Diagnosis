# app.py - Complete Cybersecurity-Enhanced Diagnosis System

import subprocess
import hashlib
import secrets
import json
import logging
import re
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet

# ============================================================================
# FLASK APP INITIALIZATION
# ============================================================================

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Secure secret key
CORS(app)

# Rate limiting to prevent DDoS attacks
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# ============================================================================
# ENCRYPTION SETUP
# ============================================================================

class DataEncryption:
    """Handle encryption/decryption of sensitive data"""
    
    def __init__(self):
        # In production, load this from environment variable
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
    
    def encrypt_data(self, data):
        """Encrypt sensitive data"""
        if isinstance(data, str):
            data = data.encode()
        return self.cipher.encrypt(data).decode()
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data"""
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode()
        return self.cipher.decrypt(encrypted_data).decode()
    
    def hash_data(self, data):
        """One-way hash for sensitive fields"""
        return hashlib.sha256(data.encode()).hexdigest()

encryption = DataEncryption()

# ============================================================================
# SECURITY LOGGING
# ============================================================================

# Configure security audit logger
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

# File handler for security logs
security_handler = logging.FileHandler('security_audit.log')
security_formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
)
security_handler.setFormatter(security_formatter)
security_logger.addHandler(security_handler)

# Console handler for debugging
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)
console_handler.setFormatter(security_formatter)
security_logger.addHandler(console_handler)

def log_security_event(username, action, status, details=None):
    """Log security-relevant events"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'username': username,
        'action': action,
        'status': status,
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'details': details
    }
    
    if status == 'FAILED' or status == 'SUSPICIOUS':
        security_logger.warning(json.dumps(log_entry))
    elif status == 'CRITICAL':
        security_logger.critical(json.dumps(log_entry))
    else:
        security_logger.info(json.dumps(log_entry))

# ============================================================================
# USER AUTHENTICATION & AUTHORIZATION
# ============================================================================

# In-memory user database (Replace with proper database in production)
users_db = {
    'doctor': {
        'password': hashlib.sha256('Doctor@123'.encode()).hexdigest(),
        'role': 'doctor',
        'name': 'Dr. Smith'
    },
    'patient': {
        'password': hashlib.sha256('Patient@123'.encode()).hexdigest(),
        'role': 'patient',
        'name': 'John Doe'
    },
    'admin': {
        'password': hashlib.sha256('Admin@123'.encode()).hexdigest(),
        'role': 'admin',
        'name': 'Admin User'
    }
}

# Active sessions storage
active_sessions = {}

# Track failed login attempts (prevent brute force)
failed_login_attempts = {}
MAX_FAILED_ATTEMPTS = 5

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_session_token():
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

def is_account_locked(username):
    """Check if account is locked due to failed attempts"""
    if username in failed_login_attempts:
        attempts, last_attempt = failed_login_attempts[username]
        
        # Lock account for 15 minutes after max attempts
        if attempts >= MAX_FAILED_ATTEMPTS:
            time_diff = (datetime.now() - last_attempt).seconds
            if time_diff < 900:  # 15 minutes
                return True
            else:
                # Reset after lockout period
                failed_login_attempts[username] = (0, datetime.now())
    return False

def record_failed_login(username):
    """Record failed login attempt"""
    if username in failed_login_attempts:
        attempts, _ = failed_login_attempts[username]
        failed_login_attempts[username] = (attempts + 1, datetime.now())
    else:
        failed_login_attempts[username] = (1, datetime.now())

def require_auth(allowed_roles=None):
    """Authentication decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get('Authorization')
            
            if not token:
                log_security_event('anonymous', 'unauthorized_access', 'FAILED', 
                                 f"No token provided for {request.endpoint}")
                return jsonify({"error": "Authentication required"}), 401
            
            if token not in active_sessions:
                log_security_event('unknown', 'invalid_token', 'FAILED', 
                                 f"Invalid token used for {request.endpoint}")
                return jsonify({"error": "Invalid or expired session"}), 401
            
            user = active_sessions[token]
            
            # Check role-based access
            if allowed_roles and user['role'] not in allowed_roles:
                log_security_event(user['username'], 'forbidden_access', 'FAILED',
                                 f"Role {user['role']} attempted to access {request.endpoint}")
                return jsonify({"error": "Insufficient permissions"}), 403
            
            # Add user info to request context
            request.current_user = user
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ============================================================================
# INPUT VALIDATION
# ============================================================================

def validate_symptoms(symptoms):
    """Validate symptom inputs to prevent injection attacks"""
    
    if not isinstance(symptoms, list):
        raise ValueError("Symptoms must be a list")
    
    if len(symptoms) == 0:
        raise ValueError("At least one symptom required")
    
    if len(symptoms) > 20:
        raise ValueError("Too many symptoms (max 20)")
    
    # Allow only alphanumeric and underscores
    allowed_pattern = re.compile(r'^[a-zA-Z_]+$')
    
    for symptom in symptoms:
        if not isinstance(symptom, str):
            raise ValueError("Each symptom must be a string")
        
        if not allowed_pattern.match(symptom):
            raise ValueError(f"Invalid symptom format: '{symptom}'. Only letters and underscores allowed")
        
        if len(symptom) > 50:
            raise ValueError(f"Symptom name too long: '{symptom}'")
    
    return True

def validate_username(username):
    """Validate username format"""
    if not isinstance(username, str):
        return False
    if len(username) < 3 or len(username) > 30:
        return False
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False
    return True

def validate_password(password):
    """Validate password strength"""
    if not isinstance(password, str):
        return False
    if len(password) < 8:
        return False
    # Must contain letter and number
    if not re.search(r'[a-zA-Z]', password) or not re.search(r'[0-9]', password):
        return False
    return True

# ============================================================================
# DIAGNOSIS STORAGE (ENCRYPTED)
# ============================================================================

# In-memory storage (Replace with encrypted database in production)
diagnosis_records = []

def store_diagnosis_record(patient_id, symptoms, diagnosis_result):
    """Store encrypted diagnosis record"""
    
    # Encrypt sensitive data
    encrypted_patient_id = encryption.encrypt_data(patient_id)
    encrypted_symptoms = encryption.encrypt_data(json.dumps(symptoms))
    encrypted_diagnosis = encryption.encrypt_data(json.dumps(diagnosis_result))
    
    record = {
        'id': len(diagnosis_records) + 1,
        'patient_id_encrypted': encrypted_patient_id,
        'symptoms_encrypted': encrypted_symptoms,
        'diagnosis_encrypted': encrypted_diagnosis,
        'timestamp': datetime.now().isoformat(),
        'performed_by': request.current_user['username']
    }
    
    diagnosis_records.append(record)
    
    log_security_event(
        request.current_user['username'],
        'diagnosis_stored',
        'SUCCESS',
        f"Diagnosis record #{record['id']} stored"
    )
    
    return record['id']

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/')
def home():
    """Serve main page"""
    return render_template('index.html')

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Prevent brute force attacks
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "Invalid request"}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        # Validate inputs
        if not validate_username(username):
            log_security_event(username, 'login', 'FAILED', 'Invalid username format')
            return jsonify({"error": "Invalid credentials"}), 401
        
        if not validate_password(password):
            log_security_event(username, 'login', 'FAILED', 'Invalid password format')
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Check if account is locked
        if is_account_locked(username):
            log_security_event(username, 'login', 'BLOCKED', 'Account locked due to failed attempts')
            return jsonify({"error": "Account temporarily locked. Try again later"}), 403
        
        # Verify credentials
        if username not in users_db:
            record_failed_login(username)
            log_security_event(username, 'login', 'FAILED', 'User not found')
            return jsonify({"error": "Invalid credentials"}), 401
        
        if users_db[username]['password'] != hash_password(password):
            record_failed_login(username)
            log_security_event(username, 'login', 'FAILED', 'Incorrect password')
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Reset failed attempts on successful login
        if username in failed_login_attempts:
            del failed_login_attempts[username]
        
        # Create session
        token = generate_session_token()
        active_sessions[token] = {
            'username': username,
            'role': users_db[username]['role'],
            'name': users_db[username]['name'],
            'login_time': datetime.now().isoformat()
        }
        
        log_security_event(username, 'login', 'SUCCESS', f"Role: {users_db[username]['role']}")
        
        return jsonify({
            "token": token,
            "role": users_db[username]['role'],
            "name": users_db[username]['name'],
            "message": "Login successful"
        })
    
    except Exception as e:
        log_security_event('unknown', 'login', 'ERROR', str(e))
        return jsonify({"error": "Internal server error"}), 500

@app.route('/logout', methods=['POST'])
def logout():
    """User logout endpoint"""
    token = request.headers.get('Authorization')
    
    if token and token in active_sessions:
        username = active_sessions[token]['username']
        del active_sessions[token]
        log_security_event(username, 'logout', 'SUCCESS', 'User logged out')
        return jsonify({"message": "Logged out successfully"})
    
    return jsonify({"message": "Already logged out"})

@app.route('/diagnose', methods=['POST'])
@limiter.limit("10 per minute")  # Prevent abuse
@require_auth(allowed_roles=['doctor', 'patient'])
def diagnose_symptoms():
    """Main diagnosis endpoint with security"""
    try:
        data = request.get_json()
        
        if not data:
            log_security_event(request.current_user['username'], 'diagnose', 'FAILED', 
                             'No data provided')
            return jsonify({"error": "No data provided"}), 400
        
        symptoms = data.get('symptoms', [])
        patient_id = data.get('patient_id', 'anonymous')
        
        # Validate symptoms input
        try:
            validate_symptoms(symptoms)
        except ValueError as e:
            log_security_event(request.current_user['username'], 'diagnose', 'FAILED',
                             f"Invalid symptoms: {str(e)}")
            return jsonify({"error": str(e)}), 400
        
        # Log diagnosis request
        log_security_event(
            request.current_user['username'],
            'diagnose',
            'INITIATED',
            f"Patient: {patient_id}, Symptoms: {len(symptoms)}"
        )
        
        # Run C++ diagnosis engine
        command = ['./code.exe'] + symptoms
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=10  # Prevent hanging
        )
        
        # Parse results
        output_lines = result.stdout.strip().split('\n')
        disease_scores = {}
        
        for line in output_lines:
            if ':' in line:
                disease, score = line.split(':', 1)
                disease_scores[disease.strip()] = float(score.strip())
        
        # Store encrypted diagnosis record
        record_id = store_diagnosis_record(patient_id, symptoms, disease_scores)
        
        log_security_event(
            request.current_user['username'],
            'diagnose',
            'SUCCESS',
            f"Record ID: {record_id}, Diseases found: {len(disease_scores)}"
        )
        
        return jsonify({
            "diagnosis": disease_scores,
            "record_id": record_id,
            "timestamp": datetime.now().isoformat(),
            "performed_by": request.current_user['name']
        })
    
    except subprocess.TimeoutExpired:
        log_security_event(request.current_user['username'], 'diagnose', 'ERROR',
                         'Diagnosis timeout')
        return jsonify({"error": "Diagnosis process timeout"}), 504
    
    except subprocess.CalledProcessError as e:
        log_security_event(request.current_user['username'], 'diagnose', 'ERROR',
                         f"C++ error: {e.stderr}")
        return jsonify({"error": "Diagnosis engine error", "details": e.stderr}), 500
    
    except Exception as e:
        log_security_event(request.current_user['username'], 'diagnose', 'ERROR', str(e))
        return jsonify({"error": "Internal server error"}), 500

@app.route('/records', methods=['GET'])
@require_auth(allowed_roles=['doctor', 'admin'])
def get_diagnosis_records():
    """Get diagnosis records (doctors and admins only)"""
    try:
        # Decrypt and return records
        decrypted_records = []
        
        for record in diagnosis_records:
            try:
                decrypted_record = {
                    'id': record['id'],
                    'patient_id': encryption.decrypt_data(record['patient_id_encrypted']),
                    'symptoms': json.loads(encryption.decrypt_data(record['symptoms_encrypted'])),
                    'diagnosis': json.loads(encryption.decrypt_data(record['diagnosis_encrypted'])),
                    'timestamp': record['timestamp'],
                    'performed_by': record['performed_by']
                }
                decrypted_records.append(decrypted_record)
            except Exception as e:
                # Skip corrupted records
                continue
        
        log_security_event(
            request.current_user['username'],
            'view_records',
            'SUCCESS',
            f"Viewed {len(decrypted_records)} records"
        )
        
        return jsonify({
            "records": decrypted_records,
            "total": len(decrypted_records)
        })
    
    except Exception as e:
        log_security_event(request.current_user['username'], 'view_records', 'ERROR', str(e))
        return jsonify({"error": "Failed to retrieve records"}), 500

@app.route('/security-logs', methods=['GET'])
@require_auth(allowed_roles=['admin'])
def get_security_logs():
    """View security audit logs (admin only)"""
    try:
        with open('security_audit.log', 'r') as f:
            logs = f.readlines()
        
        # Return last 100 log entries
        recent_logs = logs[-100:]
        
        log_security_event(
            request.current_user['username'],
            'view_security_logs',
            'SUCCESS',
            f"Viewed {len(recent_logs)} log entries"
        )
        
        return jsonify({
            "logs": recent_logs,
            "total": len(recent_logs)
        })
    
    except Exception as e:
        log_security_event(request.current_user['username'], 'view_security_logs', 'ERROR', str(e))
        return jsonify({"error": "Failed to retrieve logs"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint (no auth required)"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "active_sessions": len(active_sessions)
    })
    
@app.route('/security-demo')
def security_demo():
    return render_template('security_demo.html')

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(429)
def rate_limit_exceeded(e):
    log_security_event(
        request.headers.get('Authorization', 'anonymous'),
        'rate_limit_exceeded',
        'SUSPICIOUS',
        f"Exceeded rate limit for {request.endpoint}"
    )
    return jsonify({"error": "Too many requests. Please slow down"}), 429

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🔒 SECURE DIAGNOSIS SYSTEM - Starting...")
    print("="*60)
    print("\n📋 Default User Credentials:")
    print("-" * 60)
    print("Doctor   - Username: doctor   | Password: Doctor@123")
    print("Patient  - Username: patient  | Password: Patient@123")
    print("Admin    - Username: admin    | Password: Admin@123")
    print("-" * 60)
    print("\n✅ Security Features Enabled:")
    print("  • Authentication & Authorization")
    print("  • Data Encryption (AES)")
    print("  • Rate Limiting (DDoS Protection)")
    print("  • Input Validation (Injection Prevention)")
    print("  • Security Audit Logging")
    print("  • Account Lockout (Brute Force Protection)")
    print("="*60 + "\n")
    
    # Create security log file if not exists
    open('security_audit.log', 'a').close()
    
    app.run(debug=True, port=5000, host='0.0.0.0')
