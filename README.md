<div align="center">
    
# FARO-ASSIGNMENT-2
### Secure File Sharing & Cryptography Benchmark System

<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white" alt="HTML5">
  <img src="https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white" alt="CSS3">
  <img src="https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite">
</p>

<em>Built with Python, Flask, and Cryptography Library</em>

</div>

---

## Table of Contents

* [Overview](#overview)
* [Key Features](#key-features)
* [Cryptography Implementation](#cryptography-implementation)
* [Tech Stack](#tech-stack)
* [Project Structure](#project-structure)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
  * [Usage](#usage)
* [Benchmark Module](#benchmark-module)
* [License](#license)

---

## Overview

This project is a secure web application developed for the FARO Assignment 2. It implements a **Hybrid Encryption Scheme** to secure file uploads and facilitate secure file sharing between two distinct user roles: **Organizations** (File Owners) and **Consultants** (Access Requesters).

Additionally, the application includes a **Cryptography Benchmark Module** that evaluates and compares the performance of symmetric encryption algorithms (AES, 3DES, RC4) in real-time.

---

## Key Features

* 🔐 **Secure Authentication:** User registration and login with hashed passwords (`bcrypt`).
* 👥 **Role-Based Access Control (RBAC):**
    * **Organization:** Can upload files, view requests, and approve access.
    * **Consultant:** Can view available files, request access, and download shared files.
* 📂 **Secure File Storage:** Files are encrypted upon upload using **AES-GCM**.
* 🔑 **Hybrid Key Management:**
    * **AES Keys** are encrypted using the owner's **RSA Public Key** and stored in SQLite.
    * **RSA Private Keys** are encrypted with the user's password and stored in a simulated NoSQL store (`JSON`).
* 🤝 **Secure File Sharing:**
    * Implements a secure key exchange mechanism.
    * When a request is approved, the file's AES key is decrypted and re-encrypted with the *Consultant's* Public Key.
* 📊 **Crypto Benchmarking:** Built-in tool to measure encryption/decryption speed and ciphertext size.

---

## Cryptography Implementation

The system uses the `cryptography` Python library to implement the following standards:

1.  **Symmetric Encryption (File Data):**
    * Algorithm: `AES-256-GCM`
    * Purpose: High-speed encryption of large files.
2.  **Asymmetric Encryption (Key Exchange):**
    * Algorithm: `RSA` (2048-bit)
    * Padding: `OAEP` with `SHA-256`
    * Purpose: Securing the symmetric keys for storage and sharing.
3.  **Key Storage:**
    * **Public Keys:** Stored plainly in the SQL Database.
    * **Private Keys:** Encrypted (AES) via user password and stored in a JSON file (Simulating NoSQL).

---

## Tech Stack

* **Backend:** Python 3.x, Flask
* **Database:** SQLite (Relational), JSON (Simulated NoSQL for Keys)
* **Security:** `cryptography` (hazmat primitives), `flask-bcrypt`
* **Frontend:** HTML5, CSS3 (Bootstrap)
* **ORM:** Flask-SQLAlchemy

---

## Project Structure

```bash
FARO-Assignment-2-Private/
├── app.py                  # Main application logic & routes
├── requirements.txt        # Python dependencies
├── instance/
│   ├── app.db              # SQLite Database (Users, File Metadata)
│   └── keystore/
│       └── private_keys.json # Simulated NoSQL for Encrypted Private Keys
├── uploads/                # Encrypted file storage
├── templates/              # HTML Templates (Login, Dashboard, Benchmark, etc.)
└── static/                 # CSS, Images, Profile Pics
```
# Getting Started

## Prerequisites
- Python 3.8 or higher
- pip (Python Package Installer)

## Installation

### Clone the repository:
```bash
git clone https://github.com/qyqystilllearning/FARO-Assignment-2-Private.git
cd FARO-Assignment-2-Private
```

### Create a Virtual Environment (Optional but recommended):
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Mac/Linux
source venv/bin/activate
```

### Install Dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Run the Application:
```bash
python app.py
```

The app will run on http://127.0.0.1:8888 (debug mode enabled).

### Workflow:
1. Register a new account (Select Role: Organization).
2. Upload a file (it will be auto-encrypted).
3. Register another account (Select Role: Consultant).
4. Request access to the organization's file.
5. Log back in as Organization to approve the request (requires password for key decryption).
6. Log back in as Consultant to download and decrypt the file.

## Benchmark Module

The project includes a benchmarking feature accessible via the file dashboard. It compares the following algorithms on the uploaded file:

| Algorithm | Mode   | Key Size | Metric Measured     |
|-----------|--------|----------|---------------------|
| AES       | CTR    | 256-bit  | Speed (ms) & Size   |
| 3DES      | CBC    | 192-bit  | Speed (ms) & Size   |
| RC4       | Stream | 128-bit  | Speed (ms) & Size   |

**Note:** Results are cached in the database to avoid redundant processing.

## License

This project is licensed under the MIT License.
