from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# --- BAGIAN 1: ENKRIPSI ASIMETRIS (RSA) ---

def generate_rsa_keys():
    """
    Membuat pasangan kunci RSA baru (2048 bit).
    Mengembalikan: (public_key_pem, private_key_object)
    """
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey().export_key().decode('utf-8') # Format PEM (teks)
    return public_key, private_key

def encrypt_private_key(private_key_obj, password):
    """
    Mengenkripsi kunci privat menggunakan password user (AES-GCM).
    Ini agar kunci privat aman disimpan di database.
    """
    # 1. Turunkan kunci simetris dari password (scrypt)
    salt = get_random_bytes(16)
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
    
    # 2. Enkripsi kunci privat
    cipher = AES.new(key, AES.MODE_GCM)
    # Export kunci privat ke format bytes dulu
    private_key_bytes = private_key_obj.export_key(format='DER')
    ciphertext, tag = cipher.encrypt_and_digest(private_key_bytes)
    
    # 3. Gabungkan semuanya (salt + nonce + tag + ciphertext) untuk disimpan
    return salt + cipher.nonce + tag + ciphertext

def decrypt_private_key(encrypted_private_key_blob, password):
    """
    Mendekripsi blob database kembali menjadi Objek Kunci Privat RSA.
    """
    try:
        # 1. Pisahkan komponen (salt, nonce, tag, ciphertext)
        salt = encrypted_private_key_blob[:16]
        nonce = encrypted_private_key_blob[16:32]
        tag = encrypted_private_key_blob[32:48]
        ciphertext = encrypted_private_key_blob[48:]
        
        # 2. Turunkan kunci lagi dari password yang sama
        key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
        
        # 3. Dekripsi
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        private_key_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        
        # 4. Import kembali menjadi objek RSA
        return RSA.import_key(private_key_bytes)
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

def rsa_encrypt(data, public_key_pem):
    """
    Mengenkripsi data (misal: kunci file AES) menggunakan Kunci Publik penerima.
    Menggunakan RSA-OAEP (standar aman).
    """
    recipient_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return cipher_rsa.encrypt(data)

def rsa_decrypt(encrypted_data, private_key_obj):
    """
    Mendekripsi data menggunakan Kunci Privat pemilik.
    """
    cipher_rsa = PKCS1_OAEP.new(private_key_obj)
    return cipher_rsa.decrypt(encrypted_data)


# --- BAGIAN 2: ENKRIPSI SIMETRIS (Dipindahkan dari app.py) ---
# Kita tetap pakai 'cryptography' library untuk ini karena sudah bagus.

def encrypt_file_data(plaintext, algorithm, key_size):
    # Kita paksa pakai AES saja sesuai rencana
    if algorithm != 'AES':
        raise ValueError("Only AES is supported in this secure version.")
        
    key = os.urandom(key_size)  
    nonce_or_iv = os.urandom(16) # CTR nonce
    
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce_or_iv), backend=default_backend())
    encryptor = cipher.encryptor() 
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return ciphertext, key, nonce_or_iv

def decrypt_file_data(ciphertext, algorithm, key, nonce_or_iv):    
    if algorithm != 'AES':
        raise ValueError("Only AES is supported.")

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce_or_iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# Helper untuk Parsing Excel (jika masih dipakai)
def encrypt_db_field(plaintext, key):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode('utf-8')
    else:
        plaintext_bytes = str(plaintext).encode('utf-8')
        
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return ciphertext, nonce

def decrypt_db_field(ciphertext, key, nonce):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')