import os
import time
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, send_file, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from werkzeug.utils import secure_filename
from io import BytesIO
import openpyxl
# <!-- Import fungsi kripto baru kita -->
from crypto_utils import generate_rsa_keys, encrypt_private_key

# --- CONFIGURATION ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads') # Folder for encrypted files
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
PROFILE_PIC_FOLDER = os.path.join(BASE_DIR, 'static', 'profile_pics') # Folder for profile pictures
if not os.path.exists(PROFILE_PIC_FOLDER):
    os.makedirs(PROFILE_PIC_FOLDER)

# Database path setup
DB_PATH = os.path.join(BASE_DIR, 'instance', 'app.db')
instance_dir = os.path.dirname(DB_PATH)
if instance_dir and not os.path.exists(instance_dir):
    os.makedirs(instance_dir, exist_ok=True)
    
# Flask app setup
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROFILE_PIC_FOLDER'] = PROFILE_PIC_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'} # For profile pictures
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

# Database and login manager setup
db = SQLAlchemy(app)
bcrypt = Bcrypt(app) # For password hashing
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Database models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    profile_image_file = db.Column(db.String(100), nullable=False, default='default.jpg')
    # --- TAMBAHAN BARU ---
    # 1. Peran User (Organization vs Consultant)
    role = db.Column(db.String(20), nullable=False, default='organization') 
    # 2. Kunci Publik (Gembok) - Boleh dilihat siapa saja
    public_key = db.Column(db.Text, nullable=True) 
    # 3. Kunci Privat (Kunci Gembok) - Sangat Rahasia (Disimpan dalam bentuk terenkripsi)
    encrypted_private_key = db.Column(db.LargeBinary, nullable=True)

class ShareRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Siapa yang minta? (Consultant)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Siapa yang punya file? (Organization)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # File mana yang diminta?
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    # Status permintaan (pending, approved, rejected)
    status = db.Column(db.String(20), nullable=False, default='pending')
    # --- INTI DARI TUGAS ---
    # Kunci simetris file yang sudah dienkripsi dengan Public Key si Consultant
    encrypted_key_for_requester = db.Column(db.LargeBinary, nullable=True)
    # Relasi untuk memudahkan akses data
    file = db.relationship('File', backref='requests')
    requester = db.relationship('User', foreign_keys=[requester_id], backref='sent_requests')
    owner = db.relationship('User', foreign_keys=[owner_id], backref='received_requests')

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    original_file_name = db.Column(db.String(255), nullable=False)
    encrypted_file_path = db.Column(db.String(255), nullable=False)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encryption_algorithm = db.Column(db.String(50), nullable=False)
    encryption_key = db.Column(db.LargeBinary, nullable=False)
    nonce_or_iv = db.Column(db.LargeBinary, nullable=True) 
    plaintext_size = db.Column(db.Integer, nullable=True)
    uploader = db.relationship('User', backref=db.backref('files', lazy=True))

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

# ParsingExcel stores row/col function
class ParsingExcel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    row_index = db.Column(db.Integer, nullable=False)
    col_index = db.Column(db.Integer, nullable=False)
    encrypted_value = db.Column(db.LargeBinary, nullable=False)
    nonce = db.Column(db.LargeBinary, nullable=False)
    # This relationship makes file.parsed_cells (as a list) work
    file = db.relationship('File', backref=db.backref('parsed_cells', lazy=True))

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Encrypt file data
def encrypt_file_data(plaintext, algorithm, key_size):
    key = os.urandom(key_size)  
    nonce_or_iv = None

    if algorithm == 'AES':
        nonce_or_iv = os.urandom(16)  # CTR nonce
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce_or_iv), backend=default_backend())
    elif algorithm == 'DES':
        nonce_or_iv = os.urandom(8)  # CBC IV
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(nonce_or_iv), backend=default_backend())
    elif algorithm == 'RC4':
        cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
    else:
        raise ValueError("Unsupported algorithm")

    encryptor = cipher.encryptor() 

    # Handle padding for block ciphers (DES)
    if algorithm == 'DES':
        padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    else:
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return ciphertext, key, nonce_or_iv

# Decrypt file data
def decrypt_file_data(ciphertext, algorithm, key, nonce_or_iv):    
    if algorithm == 'AES':
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce_or_iv), backend=default_backend())
    elif algorithm == 'DES':
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(nonce_or_iv), backend=default_backend())
    elif algorithm == 'RC4':
        cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
    else:
        raise ValueError("Unsupported algorithm")

    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Handle unpadding for block ciphers (DES)
    if algorithm == 'DES':
        unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
        plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()
    else:
        plaintext = plaintext_padded
        
    return plaintext

#  encrypt_db_field for plaintext helper
def encrypt_db_field(plaintext, key):
    """Encrypts a single string field for the DB using AES-CTR."""
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    # Ensure plaintext is bytes
    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode('utf-8')
    else:
        # FIX: If not a string (e.g., number), convert to string first
        plaintext_bytes = str(plaintext).encode('utf-8')
        
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return ciphertext, nonce

#  encrypt_db_field for plaintext helper
def decrypt_db_field(ciphertext, key, nonce):
    """Decrypts a single string field from the DB."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')

# Routings

# Dashboard page
@app.route('/')
@login_required 
def dashboard():
    # Get files uploaded by the user
    uploaded_files = File.query.filter_by(uploader_id=current_user.id).all()
    
    # Get files shared with the user
    shared_file_permissions = FilePermission.query.filter_by(shared_with_user_id=current_user.id).all()
    shared_files = [p.file for p in shared_file_permissions]
    
    return render_template('dashboard.html', uploaded_files=uploaded_files, shared_files=shared_files)

# User Registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Add user to database
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # role = request.form['role'] # (Nanti kita tambahkan dropdown role di HTML)
        # Untuk sekarang default 'organization' dulu atau 'consultant' sesuai kebutuhan tes

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        # 1. Hash password (Seperti biasa)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # 2. --- LOGIKA BARU: Generate Kunci RSA ---
        # Buat pasangan kunci baru
        public_key_pem, private_key_obj = generate_rsa_keys()
        
        # Enkripsi kunci privat menggunakan password user (agar aman disimpan di DB)
        enc_priv_key = encrypt_private_key(private_key_obj, password)

        # 3. Buat User baru dengan Kunci
        new_user = User(
            username=username, 
            password_hash=hashed_password,
            role='organization', # Default role (nanti bisa diubah via form)
            public_key=public_key_pem,           # Simpan Gembok (Teks)
            encrypted_private_key=enc_priv_key   # Simpan Kunci Gembok Terenkripsi (Bytes)
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

# User Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Authenticate user
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        # Verify password and log in user
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user, remember=True)
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check username and password.', 'danger')
            
    return render_template('login.html')

# User Profile page
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    # Handle profile picture upload
    if request.method == 'POST':
        # Check if file part is present
        if 'profile_pic' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['profile_pic']

        # Check if user selected a file
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        # Check if file is valid and save
        if file and allowed_file(file.filename):
            # Create a unique filename to avoid conflicts
            filename = secure_filename(file.filename)
            file_ext = filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{uuid.uuid4()}.{file_ext}"
            save_path = os.path.join(app.config['PROFILE_PIC_FOLDER'], unique_filename)

            # Delete old profile picture if not default
            if current_user.profile_image_file != 'default.png': # <-- Adjusted to .png
                try:
                    os.remove(os.path.join(app.config['PROFILE_PIC_FOLDER'], current_user.profile_image_file))
                except OSError as e:
                    print(f"Error deleting old profile pic: {e}")

            # Save new file and update DB
            file.save(save_path)
            current_user.profile_image_file = unique_filename
            db.session.commit()

            flash('Profile picture updated!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid file type. Allowed types: png, jpg, jpeg, gif', 'danger')

    return render_template('profile.html', title='Profile')

# User Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# File Upload and Encryption
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    # Check if file part is present
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if user selected a file
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('dashboard'))
        
    # Read file content 
    plaintext = file.read()
    original_filename = secure_filename(file.filename)
    
    # Prepare the list of algorithms to process
    algorithms_to_process = [
        {'name': 'AES', 'key_size': 32, 'file_record': None}, # AES-256
        {'name': 'DES', 'key_size': 24, 'file_record': None}, # 3DES
        {'name': 'RC4', 'key_size': 16, 'file_record': None}  # RC4-128
    ]
    
    # Encrypt the file with all algorithms
    try:
        for algo_info in algorithms_to_process:
            algo_name = algo_info['name']
            key_size = algo_info['key_size']
            
            # Call encryption function
            ciphertext, key, nonce_or_iv = encrypt_file_data(plaintext, algo_name, key_size)
            
            # Save encrypted file to uploads folder
            file_uuid = str(uuid.uuid4())
            encrypted_filename = f"{file_uuid}.enc"
            encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            
            with open(encrypted_file_path, 'wb') as f:
                f.write(ciphertext)

            # Create database entry for this file
            new_file = File(
                file_uuid=file_uuid,
                original_file_name=original_filename,
                encrypted_file_path=encrypted_file_path,
                uploader_id=current_user.id,
                encryption_algorithm=algo_name, 
                encryption_key=key,
                nonce_or_iv=nonce_or_iv,
                plaintext_size=len(plaintext)
            )
            
            # Save reference to this file_record for next steps
            algo_info['file_record'] = new_file
            
            # Save encrypted file record to DB
            db.session.add(new_file)
        
        # Save all encrypted files to DB at once
        db.session.commit()
        
        # Parsing Logic  
        # (Requirement 2.e) If Excel, parse and store encrypted in DB
        if original_filename.endswith(('.xlsx', '.xls')):
            try:
                # record (we link it to AES only)
                aes_file_record = next(item['file_record'] for item in algorithms_to_process if item['name'] == 'AES')
                db_key = aes_file_record.encryption_key
                
                # still have 'plaintext' in memory
                wb = openpyxl.load_workbook(BytesIO(plaintext))
                sheet = wb.active
                
                #  LOOPING LOGIC (Adjusted for 1x4)
                # Get the first row (max_row=1) and first 4 columns (max_col=4).
                cells_to_add = []
                
                for r_idx, row in enumerate(sheet.iter_rows(min_row=1, max_row=1, min_col=1, max_col=4)): # Adjustable
                    for c_idx, cell in enumerate(row):
                        # Convert cell value (can be number, text, etc) to string
                        # reading numbers only
                        cell_value = str(cell.value) if cell.value is not None else ""
                        
                        # Only save cells that have content
                        if cell_value:
                            # Encrypt cell value
                            encrypted_val, nonce = encrypt_db_field(cell_value, db_key)
                            
                            # Create DB object
                            new_cell_entry = ParsingExcel( # <-- Using new model
                                file_id=aes_file_record.id,
                                row_index=r_idx, # Will always be 0
                                col_index=c_idx, # Will be 0, 1, 2, or 3
                                encrypted_value=encrypted_val,
                                nonce=nonce
                            )
                            cells_to_add.append(new_cell_entry)
                
                # Add all encrypted cells to DB in one batch
                if cells_to_add:
                    db.session.bulk_save_objects(cells_to_add)
                    db.session.commit()
                #  END OF PARSING LOOPING LOGIC
            
            # Except argument if there are any errors
            except Exception as e:
                flash(f'File saved, but failed to parse Excel data: {e}', 'warning')
                # We don't rollback the main commit, only the failed parsing
                db.session.rollback()
            
    except Exception as e:
        db.session.rollback() 
        flash(f'Error processing file: {e}', 'danger')
        return redirect(url_for('dashboard'))
        
    flash(f'File "{original_filename}" uploaded and encrypted with ALL algorithms.', 'success')
    return redirect(url_for('dashboard'))

# File Download and Decryption
@app.route('/download/<file_uuid>')
@login_required
def download_file(file_uuid):
    file_record = File.query.filter_by(file_uuid=file_uuid).first_or_404()
    
    # Check permission (ownership or shared)
    is_owner = file_record.uploader_id == current_user.id
    is_shared = FilePermission.query.filter_by(
        file_id=file_record.id,
        shared_with_user_id=current_user.id
    ).first()
    
    # If no permission, deny access
    if not (is_owner or is_shared):
        flash('You do not have permission to access this file.', 'danger')
        return redirect(url_for('dashboard'))
        
    # Read encrypted file and decrypt
    try:
        with open(file_record.encrypted_file_path, 'rb') as f:
            ciphertext = f.read()

        # Call decryption function
        plaintext = decrypt_file_data(ciphertext, file_record.encryption_algorithm, file_record.encryption_key, file_record.nonce_or_iv)

        # Send decrypted file as download
        return send_file(BytesIO(plaintext), as_attachment=True, download_name=file_record.original_file_name)

    except Exception as e:
        flash(f'File decryption failed: {e}', 'danger')
        return redirect(url_for('dashboard'))

# File Sharing
@app.route('/share', methods=['POST'])
@login_required
def share_file():
    recipient_username = request.form['username']
    file_id = request.form['file_id']
    
    # Validate file and recipient
    file_to_share = File.query.get_or_404(file_id)
    
    # Check if current user is the owner
    if file_to_share.uploader_id != current_user.id:
        flash('You can only share files you own.', 'danger')
        return redirect(url_for('dashboard'))
       
    # Find recipient user 
    recipient = User.query.filter_by(username=recipient_username).first()

    # Recipient not found
    if not recipient:
        flash(f'User "{recipient_username}" not found.', 'danger')
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

# Benchmarking
def run_benchmark(data):
    results = []
    
    # AES-256-CTR
    key = os.urandom(32)
    nonce = os.urandom(16)
    cipher_aes = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())

    # Encryption time
    start = time.perf_counter()
    encryptor_aes = cipher_aes.encryptor()
    ct_aes = encryptor_aes.update(data) + encryptor_aes.finalize()
    enc_time = (time.perf_counter() - start) * 1000 # ms
    
    # Decryption time
    start = time.perf_counter()
    decryptor_aes = cipher_aes.decryptor()
    pt_aes = decryptor_aes.update(ct_aes) + decryptor_aes.finalize()
    dec_time = (time.perf_counter() - start) * 1000 # ms
    
    # Store results
    results.append({
        'algo': 'AES-256-CTR',
        'enc_time_ms': f"{enc_time:.2f}",
        'dec_time_ms': f"{dec_time:.2f}",
        'ciphertext_size': len(ct_aes)
    })
    
    # DES-CBC (with padding)
    key = os.urandom(24)
    iv = os.urandom(8)
    cipher_des = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()

    # Encryption time
    start = time.perf_counter()
    encryptor_des = cipher_des.encryptor()
    padded_data = padder.update(data) + padder.finalize()
    ct_des = encryptor_des.update(padded_data) + encryptor_des.finalize()
    enc_time = (time.perf_counter() - start) * 1000 # ms
    
    # Decryption time
    start = time.perf_counter()
    decryptor_des = cipher_des.decryptor()
    pt_padded = decryptor_des.update(ct_des) + decryptor_des.finalize()
    unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
    pt_des = unpadder.update(pt_padded) + unpadder.finalize()
    dec_time = (time.perf_counter() - start) * 1000 # ms

    # Store results
    results.append({
        'algo': '3DES-CBC',
        'enc_time_ms': f"{enc_time:.2f}",
        'dec_time_ms': f"{dec_time:.2f}",
        'ciphertext_size': len(ct_des)
    })
    
    # RC4-128
    key = os.urandom(16)
    cipher_rc4 = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())

    # Encryption time
    start = time.perf_counter()
    encryptor_rc4 = cipher_rc4.encryptor()
    ct_rc4 = encryptor_rc4.update(data) + encryptor_rc4.finalize()
    enc_time = (time.perf_counter() - start) * 1000 # ms
    
    # Decryption time
    start = time.perf_counter()
    decryptor_rc4 = cipher_rc4.decryptor()
    pt_rc4 = decryptor_rc4.update(ct_rc4) + decryptor_rc4.finalize()
    dec_time = (time.perf_counter() - start) * 1000 # ms

    # Store results
    results.append({
        'algo': 'RC4-128',
        'enc_time_ms': f"{enc_time:.2f}",
        'dec_time_ms': f"{dec_time:.2f}",
        'ciphertext_size': len(ct_rc4)
    })
    
    return results

# Benchmarking Page
@app.route('/benchmark_file/<file_uuid>')
@login_required
def benchmark_file(file_uuid):
    # Get file record from DB
    file_record = File.query.filter_by(file_uuid=file_uuid).first_or_404()
    
    # Check permission
    if file_record.uploader_id != current_user.id:
        flash('You do not have permission to benchmark this file.', 'danger')
        return redirect(url_for('dashboard'))

    # Check whether benchmark results already exist in DB
    existing_results = file_record.benchmark_results
    
    # If they exist, render them directly
    if existing_results:
        flash('Benchmark results loaded from cache.', 'info')
        return render_template(
            'benchmark_result.html', 
            results=existing_results,
            filename=file_record.original_file_name,
            filesize=file_record.plaintext_size
        )

    # If not, show loading page and trigger benchmark
    return render_template(
        'benchmark_loading.html',
        file_uuid=file_uuid 
    )

# Execute Benchmarking
@app.route('/_run_benchmark/<file_uuid>')
@login_required
def execute_benchmark(file_uuid):
    # Get file record from DB
    file_record = File.query.filter_by(file_uuid=file_uuid).first_or_404()

    # Check permission
    if file_record.uploader_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    # Run benchmark
    try:
        # Read encrypted file from disk
        with open(file_record.encrypted_file_path, 'rb') as f:
            ciphertext = f.read()

        # Decrypt file to obtain raw data
        plaintext = decrypt_file_data(
            ciphertext,
            file_record.encryption_algorithm,
            file_record.encryption_key,
            file_record.nonce_or_iv
        )

        # Run benchmark 
        new_results_list = run_benchmark(plaintext)

        # Save new results to DB
        for res_dict in new_results_list:
            new_db_entry = BenchmarkResult(
                file_id=file_record.id,
                algo=res_dict['algo'],
                enc_time_ms=float(res_dict['enc_time_ms']),
                dec_time_ms=float(res_dict['dec_time_ms']),
                ciphertext_size=res_dict['ciphertext_size']
            )
            db.session.add(new_db_entry)
        
        db.session.commit()

        # Render new results
        return render_template(
            'benchmark_result.html', 
            results=file_record.benchmark_results, # Get from DB
            filename=file_record.original_file_name,
            filesize=file_record.plaintext_size
        )

    except Exception as e:
        flash(f'An error occurred during benchmark: {e}', 'danger')
        return redirect(url_for('dashboard'))
    
# Init and Run
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=8888)