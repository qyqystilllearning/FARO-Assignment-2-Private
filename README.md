# Secure Financial Report Sharing Assignment 2
**Group 5 - FARO**
| Name | NRP |
| :--- | :--- |
| Anindya Diany Putri | 5025231007 |
| Nathaniel Christine Martauli Simanullang | 5025231010 |
| Fazle Robby Pratama | 5025231011 |
| Muhammad Rizqy Hidayat | 5025231161 |

## Installation and Setup
1. Clone this repository
    ```
    git clone https://github.com/NETICS-Laboratory/secure-financial-report-sharing-faro.git
    cd secure-financial-report-sharing-faro
    ```

2. Create and activate a virtual environment
    
    Mac:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
    
    Windows:
    ```bash
    python3 -m venv .venv
    .\.venv\Scripts\activate
    ```

3. Upgrade `pip`:
    ```
    python3 -m pip install --upgrade pip
    ```

4. Install dependencies:
    ```
    pip install -r requirements.txt
    ```

5. Run the application:
    ```
    python3 app.py
    ```

6. Open the link provided by the application.

## Project Structure
```
/ project root
├── app.py                     # Main Flask application
├── README.md                  # Project readme
├── requirements.txt           # Python dependencies
├── instance/
│   └── app.db                 # SQLite database file
├── static/
│   ├── style.css              # Site CSS
│   └── profile_pics/
│       └── default.jpg        # Default profile image
├── templates/
│   ├── layout.html
│   ├── dashboard.html
│   ├── login.html
│   ├── register.html
│   ├── profile.html
│   ├── benchmark_loading.html
│   └── benchmark_result.html
└── uploads/
    ├── 037921f4-... .enc      # encrypted upload files (many .enc files)
    ├── 09b09770-... .enc
    ├── 13bc60c0-... .enc
    └── ... (more .enc files)
```

