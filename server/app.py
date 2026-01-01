from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import mysql.connector
import hashlib
import json
import os
import base64
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'forensics_secret_key_2024'

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'forensics_user',
    'password': 'Forensics@123',
    'database': 'forensics_db'
}

# Evidence storage path
EVIDENCE_PATH = os.path.join(os.path.dirname(__file__), 'evidence_storage')

# Load public key for signature verification
def load_public_key():
    key_path = os.path.join(os.path.dirname(__file__), 'keys', 'public_key.pem')
    with open(key_path, 'rb') as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

PUBLIC_KEY = load_public_key()

# Database connection
def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

# Initialize database tables
def init_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Chain of custody ledger table
    # Chain of custody ledger table
    cursor.execute('''
       CREATE TABLE IF NOT EXISTS chain_of_custody (
           id INT AUTO_INCREMENT PRIMARY KEY,
           case_id VARCHAR(50) NOT NULL,
           source_computer VARCHAR(100) NOT NULL,
           source_ip VARCHAR(45) NOT NULL,
           collector_agent VARCHAR(50) NOT NULL,
           artifact_count INT NOT NULL,
           evidence_hash VARCHAR(64) NOT NULL,
           signature_status VARCHAR(20) NOT NULL,
           hash_status VARCHAR(20) NOT NULL,
           overall_status VARCHAR(20) NOT NULL,
           previous_log_hash VARCHAR(64),
           current_log_hash VARCHAR(64),
           full_artifacts JSON,
           received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
       )
   ''')
    
    # Create default admin user (password: admin123)
    admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
    try:
        cursor.execute('''
            INSERT INTO users (username, password) VALUES (%s, %s)
        ''', ('admin', admin_password))
    except:
        pass
    
    conn.commit()
    cursor.close()
    conn.close()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user:
        return User(user['id'], user['username'])
    return None

# Verify digital signature
def verify_signature(data, signature):
    try:
        PUBLIC_KEY.verify(
            base64.b64decode(signature),
            data.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

# Calculate hash of data
def calculate_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Get previous log hash for chain
def get_previous_log_hash():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT current_log_hash FROM chain_of_custody ORDER BY id DESC LIMIT 1')
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    if result:
        return result['current_log_hash']
    return '0' * 64

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user:
            login_user(User(user['id'], user['username']))
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM chain_of_custody ORDER BY received_at DESC')
    records = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('dashboard.html', records=records, username=current_user.username)

@app.route('/evidence/<int:record_id>')
@login_required
def view_evidence(record_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM chain_of_custody WHERE id = %s', (record_id,))
    record = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if record:
        # Parse the full_artifacts JSON
        try:
            full_artifacts = json.loads(record['full_artifacts'])
        except:
            full_artifacts = {}
        
        return render_template('evidence_detail.html', record=record, full_artifacts=full_artifacts)
    return redirect(url_for('dashboard'))

# API endpoint to receive evidence
@app.route('/api/upload', methods=['POST'])
def upload_evidence():
    try:
        data = request.json
        
        # Extract data from request
        case_id = data.get('case_id')
        source_computer = data.get('source_computer')
        source_ip = request.remote_addr
        collector_agent = data.get('collector_agent', 'TAC-v1.0')
        artifacts = data.get('artifacts', [])
        evidence_hash = data.get('evidence_hash')
        signature = data.get('signature')
        
        # Verify signature
        signature_status = 'VERIFIED' if verify_signature(evidence_hash, signature) else 'FAILED'
        
        # Recalculate hash from artifacts
        artifacts_json = json.dumps(artifacts, sort_keys=True)
        recalculated_hash = calculate_hash(artifacts_json)
        hash_status = 'MATCH' if recalculated_hash == evidence_hash else 'MISMATCH'
        
        # Determine overall status
        overall_status = 'ACCEPTED' if signature_status == 'VERIFIED' and hash_status == 'MATCH' else 'REJECTED'
        
        # Get previous log hash for chain
        previous_log_hash = get_previous_log_hash()
        
        # Calculate current log hash
        log_data = f"{case_id}{source_computer}{evidence_hash}{previous_log_hash}"
        current_log_hash = calculate_hash(log_data)
        
        # Save to database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
           INSERT INTO chain_of_custody 
           (case_id, source_computer, source_ip, collector_agent, artifact_count, 
            evidence_hash, signature_status, hash_status, overall_status, 
            previous_log_hash, current_log_hash, full_artifacts)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
       ''', (case_id, source_computer, source_ip, collector_agent, len(artifacts),
            evidence_hash, signature_status, hash_status, overall_status,
            previous_log_hash, current_log_hash, json.dumps(artifacts)))
 
        record_id = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()
        
        # Save evidence files if accepted
        if overall_status == 'ACCEPTED':
            evidence_dir = os.path.join(EVIDENCE_PATH, f"case_{case_id}_{record_id}")
            os.makedirs(evidence_dir, exist_ok=True)
            
            with open(os.path.join(evidence_dir, 'artifacts.json'), 'w') as f:
                json.dump(artifacts, f, indent=2)
            
            with open(os.path.join(evidence_dir, 'chain_of_custody.json'), 'w') as f:
                json.dump({
                    'case_id': case_id,
                    'source_computer': source_computer,
                    'evidence_hash': evidence_hash,
                    'signature_status': signature_status,
                    'hash_status': hash_status,
                    'overall_status': overall_status,
                    'received_at': datetime.now().isoformat()
                }, f, indent=2)
        
        return jsonify({
            'status': overall_status,
            'record_id': record_id,
            'signature_status': signature_status,
            'hash_status': hash_status,
            'message': 'Evidence processed successfully'
        })
        
    except Exception as e:
        return jsonify({
            'status': 'ERROR',
            'message': str(e)
        }), 500

# API endpoint to check server status
@app.route('/api/status')
def api_status():
    return jsonify({
        'status': 'online',
        'server': 'Forensics Verification Backend',
        'version': '1.0'
    })

if __name__ == '__main__':
    init_database()
    app.run(host='0.0.0.0', port=5000, debug=True, ssl_context='adhoc')
