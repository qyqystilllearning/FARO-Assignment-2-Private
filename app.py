import os
import json
import base64
import time
from flask import Flask, render_template, url_for, redirect, request, flash, send_file, Response, session
from werkzeug.utils import secure_filename
from uuid import uuid4
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

# --- CRYPTOGRAPHY IMPORTS ---
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding # Rename for clarity
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as sym_padding # Rename for clarity
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['KEYSTORE_FOLDER'] = 'instance/keystore' # Folder for NoSQL DB

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['KEYSTORE_FOLDER'], exist_ok=True)

# ==========================================
#  HELPER: NoSQL Key Storage (Requirement #4)
# ==========================================
KEYSTORE_PATH = os.path.join(app.config['KEYSTORE_FOLDER'], 'private_keys.json')

def save_private_key_to_nosql(user_id, encrypted_private_key_pem):
    """Writes key to JSON file (Simulated NoSQL)"""
    data = {}
    if os.path.exists(KEYSTORE_PATH):
        with open(KEYSTORE_PATH, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}
    
    # User ID is the Key, Encrypted PEM is the Value
    data[str(user_id)] = encrypted_private_key_pem.decode('utf-8')
    
    with open(KEYSTORE_PATH, 'w') as f:
        json.dump(data, f)

def get_private_key_from_nosql(user_id):
    """Reads key from JSON file (Simulated NoSQL)"""
    if not os.path.exists(KEYSTORE_PATH):
        return None
    with open(KEYSTORE_PATH, 'r') as f:
        data = json.load(f)
        return data.get(str(user_id))

# ==========================================
#  HELPER: Encryption Functions
# ==========================================

def generate_rsa_keypair(password):
    """Generates RSA Keypair. Encrypts Private Key with user password."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Encrypt private key for storage
    encrypted_private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_pem, encrypted_private_pem

def load_private_key(encrypted_pem_str, password):
    """Unlocks a private key using the user's password."""
    return serialization.load_pem_private_key(
        encrypted_pem_str.encode('utf-8'),
        password=password.encode(),
        backend=default_backend()
    )

def encrypt_rsa(data, public_key_pem):
    """Encrypts a symmetric key using an RSA Public Key."""
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    ciphertext = public_key.encrypt( 
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_rsa(encrypted_b64, private_key):
    """Decrypts a symmetric key using an RSA Private Key."""
    ciphertext = base64.b64decode(encrypted_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def encrypt_aes_gcm(data, key):
    """Encrypts file data using AES-GCM (Secure Symmetric)."""
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def decrypt_aes_gcm(encrypted_data, key):
    """Decrypts file data using AES-GCM."""
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# ==========================================
#  DATABASE MODELS
# ==========================================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    
    role = db.Column(db.String(20), nullable=False)  # 'organization' or 'consultant'
    public_key = db.Column(db.Text, nullable=False) # RSA Public Key (SQL Storage)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    filepath = db.Column(db.String(100), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # The AES key encrypted with the OWNER'S Public Key
    encrypted_aes_key = db.Column(db.Text, nullable=False)

class FilePermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file = db.relationship('File', backref=db.backref('permissions', lazy=True))
    user = db.relationship('User', backref=db.backref('shared_files', lazy=True))

class BenchmarkResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    algo = db.Column(db.String(50), nullable=False)
    enc_time_ms = db.Column(db.Float, nullable=False)
    dec_time_ms = db.Column(db.Float, nullable=False)
    ciphertext_size = db.Column(db.Integer, nullable=False)
    file = db.relationship('File', backref=db.backref('benchmark_results', lazy=True))

class AccessRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    consultant_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    
    # The AES key encrypted with the CONSULTANT'S Public Key
    encrypted_shared_key = db.Column(db.Text, nullable=True)

    consultant = db.relationship('User', foreign_keys=[consultant_id])
    file = db.relationship('File', foreign_keys=[file_id])

# ==========================================
#  ROUTES
# ==========================================

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # 1. Generate RSA Keys
        public_pem, encrypted_private_pem = generate_rsa_keypair(password)

        # 2. Save User (Public Key -> SQL)
        user = User(username=username, password=hashed_password, role=role, public_key=public_pem.decode('utf-8'))
        db.session.add(user)
        db.session.commit()
        
        # 3. Save Private Key (Private Key -> NoSQL)
        save_private_key_to_nosql(user.id, encrypted_private_pem)

        flash(f'Account created for {username}!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and bcrypt.check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'organization':
        my_files = File.query.filter_by(owner_id=current_user.id).order_by(File.id.desc()).all()
        pending_requests = AccessRequest.query.join(File).filter(File.owner_id == current_user.id, AccessRequest.status == 'pending').all()

        # NEW: fetch FilePermission rows for files owned by this organization user
        shared_permissions = FilePermission.query.join(File).filter(File.owner_id == current_user.id).order_by(FilePermission.id.desc()).all()

        return render_template('dashboard.html', files=my_files, requests=pending_requests, shared_permissions=shared_permissions)
    
    elif current_user.role == 'consultant':
        all_files = File.query.join(User).filter(User.role == 'organization').order_by(File.id.desc()).all()
        my_requests = {r.file_id: r.status for r in AccessRequest.query.filter_by(consultant_id=current_user.id).all()}
        return render_template('dashboard.html', all_files=all_files, my_requests=my_requests)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if current_user.role != 'organization':
        return redirect(url_for('dashboard'))
    
    if 'file' not in request.files:
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('dashboard'))

    if file:
        filename = file.filename
        file_data = file.read()

        # 1. Generate AES Key
        aes_key = os.urandom(32)

        # 2. Encrypt File
        encrypted_data = encrypt_aes_gcm(file_data, aes_key)

        # 3. Encrypt AES Key with Org Public Key
        encrypted_aes_key_for_storage = encrypt_rsa(aes_key, current_user.public_key.encode('utf-8'))

        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.enc')
        with open(save_path, 'wb') as f:
            f.write(encrypted_data)
        
        new_file = File(filename=filename, filepath=save_path, owner_id=current_user.id, encrypted_aes_key=encrypted_aes_key_for_storage)
        db.session.add(new_file)
        db.session.commit()
        flash('File uploaded and encrypted!', 'success')
        
    return redirect(url_for('dashboard'))

@app.route('/request_access/<int:file_id>')
@login_required
def request_access(file_id):
    if current_user.role != 'consultant':
        return redirect(url_for('dashboard'))
    
    existing = AccessRequest.query.filter_by(consultant_id=current_user.id, file_id=file_id).first()
    if not existing:
        req = AccessRequest(consultant_id=current_user.id, file_id=file_id)
        db.session.add(req)
        db.session.commit()
        flash('Access requested.', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/approve_request/<int:request_id>', methods=['POST'])
@login_required
def approve_request(request_id):
    # The KEY EXCHANGE Logic
    password = request.form.get('password_verify')
    req = AccessRequest.query.get_or_404(request_id)
    file_record = File.query.get(req.file_id)
    
    if file_record.owner_id != current_user.id:
        return redirect(url_for('dashboard'))

    # 1. Get Org's Encrypted Private Key from NoSQL
    enc_priv_pem = get_private_key_from_nosql(current_user.id)
    
    try:
        # 2. Decrypt Org Private Key (Unlock it)
        org_private_key = load_private_key(enc_priv_pem, password)
        
        # 3. Decrypt AES Key
        aes_key = decrypt_rsa(file_record.encrypted_aes_key, org_private_key)
        
        # 4. Re-Encrypt AES Key with Consultant's Public Key
        consultant = User.query.get(req.consultant_id)
        encrypted_shared_key = encrypt_rsa(aes_key, consultant.public_key.encode('utf-8'))
        
        req.status = 'approved'
        req.encrypted_shared_key = encrypted_shared_key
        db.session.commit()
        flash('Request approved! Key encrypted securely.', 'success')

    except Exception as e:
        flash('Incorrect password or encryption error.', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/my_access')
@login_required
def my_access():
    if current_user.role != 'consultant':
        return redirect(url_for('dashboard'))
    approved_requests = AccessRequest.query.filter_by(consultant_id=current_user.id, status='approved').all()
    return render_template('my_access.html', requests=approved_requests)


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Handle profile picture upload
        if 'profile_pic' not in request.files:
            flash('No file part in request.', 'danger')
            return redirect(url_for('profile'))

        file = request.files['profile_pic']
        if file.filename == '':
            flash('No selected file.', 'danger')
            return redirect(url_for('profile'))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            ext = filename.rsplit('.', 1)[1].lower()
            unique_name = f"{uuid4()}.{ext}"
            save_path = os.path.join(app.root_path, 'static', 'profile_pics', unique_name)
            file.save(save_path)

            # Update user record
            current_user.image_file = unique_name
            db.session.commit()
            flash('Profile picture updated.', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid file type. Allowed: png, jpg, jpeg', 'danger')
            return redirect(url_for('profile'))

    return render_template('profile.html')

@app.route('/download/<int:file_id>', methods=['GET', 'POST'])
@app.route('/download/request/<int:request_id>', methods=['POST'])
@login_required
def download_file(file_id=None, request_id=None):
    """
    Supports two download flows:
    - Owner download: `GET/POST /download/<file_id>` where owner provides password to decrypt their file.
    - Consultant download: `POST /download/request/<request_id>` where consultant provides password to decrypt shared AES key.
    """
    # --- Owner flow (organization) ---
    if file_id is not None and current_user.role == 'organization':
        file_record = File.query.get_or_404(file_id)
        if file_record.owner_id != current_user.id:
            flash('You are not authorized to download this file.', 'danger')
            return redirect(url_for('dashboard'))

        if request.method == 'GET':
            return render_template('confirm_download.html', file_id=file_id, filename=file_record.filename)

        # POST: attempt decrypt using owner's private key
        password = request.form.get('password_verify')
        enc_priv_pem = get_private_key_from_nosql(current_user.id)
        try:
            owner_private_key = load_private_key(enc_priv_pem, password)
            aes_key = decrypt_rsa(file_record.encrypted_aes_key, owner_private_key)

            with open(file_record.filepath, 'rb') as f:
                encrypted_file_data = f.read()

            decrypted_data = decrypt_aes_gcm(encrypted_file_data, aes_key)
            return Response(
                decrypted_data,
                mimetype="application/octet-stream",
                headers={"Content-disposition": f"attachment; filename={file_record.filename}"}
            )
        except Exception:
            flash('Incorrect password or decryption failure.', 'danger')
            return redirect(url_for('dashboard'))

    # --- Consultant flow ---
    if request_id is not None and current_user.role == 'consultant':
        # Consultants must POST with password
        if request.method != 'POST':
            return redirect(url_for('my_access'))

        password = request.form.get('password_verify')
        req = AccessRequest.query.get_or_404(request_id)

        if req.consultant_id != current_user.id or req.status != 'approved':
            return redirect(url_for('dashboard'))

        enc_priv_pem = get_private_key_from_nosql(current_user.id)
        try:
            consultant_private_key = load_private_key(enc_priv_pem, password)
            aes_key = decrypt_rsa(req.encrypted_shared_key, consultant_private_key)

            with open(req.file.filepath, 'rb') as f:
                encrypted_file_data = f.read()

            decrypted_data = decrypt_aes_gcm(encrypted_file_data, aes_key)
            return Response(
                decrypted_data,
                mimetype="application/octet-stream",
                headers={"Content-disposition": f"attachment; filename={req.file.filename}"}
            )
        except Exception:
            flash('Incorrect password or decryption failure.', 'danger')
            return redirect(url_for('my_access'))

    # If nothing matched
    return redirect(url_for('dashboard'))
    
@app.route('/share', methods=['POST'])
@login_required
def share_file():
    recipient_username = request.form['username']
    file_id = request.form['file_id']
    
    # Validate file and recipient
    file_to_share = File.query.get_or_404(file_id)
    
    # Check if current user is the owner
    if file_to_share.owner_id != current_user.id:
        flash('You can only share files you own.', 'danger')
        return redirect(url_for('dashboard'))

    # Find recipient user 
    recipient = User.query.filter_by(username=recipient_username).first()

    # Recipient not found (check before using recipient.role)
    if not recipient:
        flash(f'User "{recipient_username}" not found.', 'danger')
        return redirect(url_for('dashboard'))

    # If shared user is consultant, deny access (you intended to only share with organization users)
    if recipient.role == 'consultant':
        flash('You can only share files with organization users.', 'danger')
        return redirect(url_for('dashboard'))
        
    # Check if already shared
    existing_permission = FilePermission.query.filter_by(
        file_id=file_id,
        shared_with_user_id=recipient.id
    ).first()
    
    if existing_permission:
        flash(f'File already shared with {recipient_username}.', 'info')
        return redirect(url_for('dashboard'))

    # Save new permission to DB
    new_permission = FilePermission( file_id=file_id, shared_with_user_id=recipient.id )
    db.session.add(new_permission)
    db.session.commit()
    
    flash(f'File successfully shared with {recipient_username}.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/revoke_share/<int:permission_id>', methods=['POST'])
@login_required
def revoke_share(permission_id):
    """Allow organization owner to revoke a previously created share (FilePermission)."""
    perm = FilePermission.query.get_or_404(permission_id)
    # Confirm the current user owns the file, otherwise unauthorized
    if perm.file.owner_id != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('dashboard'))

    db.session.delete(perm)
    db.session.commit()
    flash('Share revoked successfully.', 'success')
    return redirect(url_for('dashboard'))

# ... (Import dan kode lain di atas tetap sama) ...

# ==========================================
#  BENCHMARK LOGIC (AES, DES, RC4)
# ==========================================

def run_benchmark(data):
    """
    Runs encryption/decryption tests on raw data using 3 algorithms.
    """
    results = []
    
    # 1. AES-256-CTR
    key_aes = os.urandom(32)
    nonce_aes = os.urandom(16)
    cipher_aes = Cipher(algorithms.AES(key_aes), modes.CTR(nonce_aes), backend=default_backend())
    
    start = time.perf_counter()
    encryptor = cipher_aes.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    enc_time = (time.perf_counter() - start) * 1000
    
    start = time.perf_counter()
    decryptor = cipher_aes.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    dec_time = (time.perf_counter() - start) * 1000
    
    results.append({'algo': 'AES-256-CTR', 'enc_time_ms': enc_time, 'dec_time_ms': dec_time, 'ciphertext_size': len(ct)})

    # 2. 3DES-CBC (Triple DES)
    key_des = os.urandom(24)
    iv_des = os.urandom(8)
    cipher_des = Cipher(algorithms.TripleDES(key_des), modes.CBC(iv_des), backend=default_backend())
    # FIX: Use sym_padding for symmetric encryption padding
    padder = sym_padding.PKCS7(algorithms.TripleDES.block_size).padder()
    
    start = time.perf_counter()
    encryptor = cipher_des.encryptor()
    padded_data = padder.update(data) + padder.finalize() # CBC needs padding
    ct = encryptor.update(padded_data) + encryptor.finalize()
    enc_time = (time.perf_counter() - start) * 1000
    
    start = time.perf_counter()
    decryptor = cipher_des.decryptor()
    pt_padded = decryptor.update(ct) + decryptor.finalize()
    # FIX: Use sym_padding for unpadding
    unpadder = sym_padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
    pt = unpadder.update(pt_padded) + unpadder.finalize()
    dec_time = (time.perf_counter() - start) * 1000
    
    results.append({'algo': '3DES-CBC', 'enc_time_ms': enc_time, 'dec_time_ms': dec_time, 'ciphertext_size': len(ct)})
    
    # 3. RC4 (ARC4)
    key_rc4 = os.urandom(16)
    cipher_rc4 = Cipher(algorithms.ARC4(key_rc4), mode=None, backend=default_backend())
    
    start = time.perf_counter()
    encryptor = cipher_rc4.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    enc_time = (time.perf_counter() - start) * 1000
    
    start = time.perf_counter()
    decryptor = cipher_rc4.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    dec_time = (time.perf_counter() - start) * 1000
    
    results.append({'algo': 'RC4-128', 'enc_time_ms': enc_time, 'dec_time_ms': dec_time, 'ciphertext_size': len(ct)})
    
    return results
# 1. Route Awal: Cek Cache
@app.route('/benchmark_file/<int:file_id>', methods=['GET'])
@login_required
def benchmark_file(file_id):
    file_record = File.query.get_or_404(file_id)

    if file_record.owner_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    # Cek Cache
    existing_results = file_record.benchmark_results
    if existing_results:
        flash('Benchmark results loaded from cache.', 'info')
        try:
            filesize = os.path.getsize(file_record.filepath)
        except:
            filesize = "Unknown"
        return render_template('benchmark_result.html', results=existing_results, filename=file_record.filename, filesize=filesize)

    # Jika Cache Kosong -> Ke Halaman Auth
    return render_template('benchmark_auth.html', file_id=file_id, filename=file_record.filename)


# 2. Route Perantara: Verifikasi Password & Set Session
@app.route('/verify_benchmark/<int:file_id>', methods=['POST'])
@login_required
def verify_benchmark(file_id):
    password = request.form.get('password_verify')
    
    # Ambil Kunci dari NoSQL
    enc_priv_pem = get_private_key_from_nosql(current_user.id)
    
    try:
        # Coba Decrypt Private Key
        # Kita lakukan ini HANYA untuk memverifikasi password benar
        # DAN untuk menyimpannya sementara di session agar route 'execute' bisa membacanya
        owner_private_key = load_private_key(enc_priv_pem, password)
        
        # Simpan kunci privat yang sudah terbuka (PEM String) ke session
        # Ini aman karena session Flask di-sign dengan SECRET_KEY
        private_key_pem_string = owner_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        session['temp_benchmark_key'] = private_key_pem_string
        
        # Password Benar -> Ke Halaman Loading
        return render_template('benchmark_loading.html', file_id=file_id)

    except Exception as e:
        flash('Incorrect password. Cannot unlock Private Key.', 'danger')
        return redirect(url_for('dashboard'))


# 3. Route Eksekusi: Dijalankan otomatis oleh Halaman Loading
@app.route('/execute_benchmark/<int:file_id>')
@login_required
def execute_benchmark(file_id):
    file_record = File.query.get_or_404(file_id)
    
    # Ambil kunci dari session (yang disimpan di langkah sebelumnya)
    private_key_pem = session.get('temp_benchmark_key')
    
    if not private_key_pem:
        flash('Session expired or invalid flow.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Load Kunci Privat dari Session
        owner_private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Buka Amplop RSA (Dapatkan kunci AES)
        aes_key = decrypt_rsa(file_record.encrypted_aes_key, owner_private_key)

        # Buka File Fisik
        with open(file_record.filepath, 'rb') as f:
            encrypted_file_data = f.read()
        
        # Dapatkan Plaintext
        plaintext = decrypt_aes_gcm(encrypted_file_data, aes_key)

        # JALANKAN BENCHMARK (AES, DES, RC4)
        new_results_list = run_benchmark(plaintext)

        # Simpan Cache
        for res in new_results_list:
            new_db_entry = BenchmarkResult(
                file_id=file_record.id,
                algo=res['algo'],
                enc_time_ms=float(res['enc_time_ms']),
                dec_time_ms=float(res['dec_time_ms']),
                ciphertext_size=res['ciphertext_size']
            )
            db.session.add(new_db_entry)
        db.session.commit()

        # BERSIHKAN SESSION (Penting untuk keamanan!)
        session.pop('temp_benchmark_key', None)

        return render_template(
            'benchmark_result.html', 
            results=file_record.benchmark_results, 
            filename=file_record.filename,
            filesize=len(plaintext)
        )

    except Exception as e:
        session.pop('temp_benchmark_key', None) # Bersihkan jika error
        flash(f'Benchmark failed: {e}', 'danger')
        return redirect(url_for('dashboard'))
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=8888)