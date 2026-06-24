"""
WGU Construction Equipment Rental - Flask API Application (Task 2 Student Starter)

Scenario:
You have joined a development team responsible for securing an internal API that
retrieves user data and interacts with a backend service. The API is experiencing
unauthorized access attempts, suspicious input patterns, and malfunctioning authorization
logic.

The security team has provided you with:
- This Python web service (review it for security issues)
- A flake8 static analysis report (task_2_flake8_report.txt)
- A bandit security scan report (task_2_bandit_report.txt)
- Logs showing suspicious traffic (network_security_log.txt)

Your Task:
1. Review task_2_flake8_report.txt to identify GENERAL security vulnerabilities (Section A)
2. Review task_2_bandit_report.txt to identify API security vulnerabilities (Section B)
3. Remediate the vulnerabilities and write test cases (Section C)
4. Write a Security Mitigation Report (Section D)

INSTRUCTIONS:
- Complete all TODO items marked throughout this file
- Save your completed work as app_solution.py
- Document your changes in your Security Mitigation Report
- Reference the flake8 and bandit reports for vulnerability identification

RUBRIC SECTIONS:
  Section A — General Security Vulnerabilities (from flake8 report)
    A1: Provide screenshot of insecure code with line numbers (pick 2 vulnerabilities)
    A2: Implement secure replacement code for each vulnerability
    A3: Comment out the original insecure code after remediation
  Section B — API Security Vulnerabilities (from bandit report)
    B1: Provide screenshot of insecure API code with line numbers (pick 2 vulnerabilities)
    B2: Implement secure replacement code for each vulnerability
    B3: Comment out the original insecure API code after remediation
  Section C — Test Cases
    C1: Use pytest framework with test_ naming convention
    C2: Include assert statements in each test
    C3: Execute tests successfully (all pass)
    C4: Add descriptive print() statements explaining test outcomes
    C5: Provide 4 screenshots (2 general + 2 API test pass results)
  Section D — Written Security Mitigation Report
    D1: Describe 2 mitigation strategies for each of the 4 vulnerabilities
    D2: Describe 2 input validation techniques
    D3: Describe 2 exception handling improvements
    D4: Describe 1 encryption method for REST/API security
"""
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
import sqlite3
import os
import secrets
from werkzeug.security import check_password_hash, generate_password_hash
app = Flask(__name__)

# =============================================================================
# SECTION A: GENERAL SECURITY VULNERABILITY #1 — Hardcoded Secrets
# Identified in: task_2_flake8_report.txt (lines 79-84, severity S105)
# =============================================================================
# TODO (Section A — Vulnerability #1): HARDCODED SECRETS
#
# The flake8 report flags hardcoded credentials on lines 79-84.
# This is a GENERAL security vulnerability because:
#   - Secrets in source code are exposed in version control
#   - Cannot rotate credentials without code changes
#   - Violates secure configuration management best practices
#
# YOUR TASKS:
#   A1: Take a screenshot of this insecure code with line numbers visible
#   A2: Implement a secure replacement using environment variables or secrets management
#       Example: app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
#   A3: Comment out the original insecure code (do NOT delete it) — leave it
#       visible so evaluators can see what was replaced
#
# For your Section D report:
#   D1: Describe 2 mitigation strategies for this vulnerability
# =============================================================================


# app.secret_key = 'supersecretkeyforflasksessions'
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))  # Secure replacement using environment variable
# API_KEY = "sk_live_abc123xyz789secretkey"
API_KEY = os.environ.get('API_KEY','')

DB_USER = "admin"
# DB_PASSWORD = "password123"
DB_PASSWORD = os.environ.get('DB_PASSWORD','')

# Equipment Pricing Data
EQUIPMENT_PRICES = {
    "Bulldozer": 500,
    "Excavator": 450,
    "Crane": 800
}

# =============================================================================
# SECTION A: GENERAL SECURITY VULNERABILITY #2 — Plaintext Password Storage
# Identified in: task_2_flake8_report.txt (lines 114-119, severity S105)
# =============================================================================
# TODO (Section A — Vulnerability #2): PLAINTEXT PASSWORDS
#
# The flake8 report flags plaintext passwords stored in the user database.
# This is a GENERAL security vulnerability because:
#   - If the database is compromised, all passwords are immediately exposed
#   - Passwords should be hashed using bcrypt, scrypt, argon2, or PBKDF2
#   - Plaintext storage violates CWE-256 (Plaintext Storage of a Password)
#
# YOUR TASKS:
#   A1: Take a screenshot of this insecure code with line numbers visible
#   A2: Implement password hashing (e.g., hashlib.pbkdf2_hmac or bcrypt)
#   A3: Comment out the original plaintext passwords after remediation
#
# For your Section D report:
#   D1: Describe 2 mitigation strategies for this vulnerability
# =============================================================================

USERS_DB = {
    "admin": {"password": "admin123", "role": "admin", "api_key": "sk_admin_key123"},
    "alice": {"password": "alice456", "role": "user", "api_key": "sk_alice_key456"},
    "bob": {"password": "bob789", "role": "user", "api_key": "sk_bob_key789"},
    "charlie": {"password": "charlie000", "role": "guest", "api_key": "sk_charlie_key000"}
}

# =============================================================================
# Additional General Vulnerabilities (from flake8 report)
# You may also choose from these for Section A:
#   - Missing input validation (lines 584-586, no type/boundary checks)
#   - Unsafe exception handling exposing internals (lines 346-347, CWE-209)
#   - XSS: unsanitized input reflected in response (line 498)
#   - Sensitive data exposure / PII in records (lines 131-133, SSN fields)
# =============================================================================

RENTAL_RECORDS = [
    {"id": 1, "user": "alice", "equipment": "Bulldozer", "days": 3, "total": 1500, "ssn": "123-45-6789"},
    {"id": 2, "user": "bob", "equipment": "Crane", "days": 2, "total": 1600, "ssn": "987-65-4321"},
    {"id": 3, "user": "admin", "equipment": "Excavator", "days": 5, "total": 2250, "ssn": "555-12-3456"},
]


# =============================================================================
# Database Helper Functions
# =============================================================================

def get_db_connection():
    """Create a database connection."""
    conn = sqlite3.connect('rental_api.db')
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """Initialize the database with sample data."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            api_key TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rentals (
            id INTEGER PRIMARY KEY,
            username TEXT,
            equipment TEXT,
            days INTEGER,
            total REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


# =============================================================================
# SECTION B: API SECURITY VULNERABILITY #1 — Missing API Authentication
# Related bandit findings: B105 (hardcoded credentials in USERS_DB, lines 115-118)
# Code review finding: require_api_key() always returns None (CWE-306)
# =============================================================================
# TODO (Section B — Vulnerability #1): MISSING API AUTHENTICATION
#
# The bandit report flags hardcoded credentials (B105) in USERS_DB.
# Code review reveals that require_api_key() always returns None —
# meaning NO API endpoint is ever authenticated. Anyone can call any endpoint.
#
# This is an API security vulnerability because:
#   - CWE-306: Missing Authentication for Critical Function
#   - All protected resources are exposed to unauthenticated users
#   - Combined with broken admin endpoints, this allows full data access
#
# YOUR TASKS:
#   B1: Take a screenshot of this insecure code with line numbers visible
#   B2: Implement proper API key validation:
#       - Extract API key from Authorization header (Bearer token)
#       - Validate against USERS_DB
#       - Return username if valid, None if invalid
#   B3: Comment out the original insecure code after remediation
#
# For your Section D report:
#   D1: Describe 2 mitigation strategies for this vulnerability
# =============================================================================

def require_api_key():
    """
    TODO (Section B): Implement API Key Authentication

    This function should:
    1. Extract the API key from the Authorization header
       - Expected format: "Bearer <api_key>"
    2. Validate the API key against USERS_DB
    3. Return the username if valid, None if invalid

    SECURITY NOTE: API keys should be transmitted in headers, NOT URL parameters.
    See CWE-598 (Use of GET Request Method With Sensitive Query Strings).
    """
    # INSECURE: Currently returns None (no authentication)
    # TODO: Implement proper API key validation
    return None


# =============================================================================
# SECTION B: API SECURITY VULNERABILITY #2 — Broken Authorization
# Related bandit findings: B201 (debug=True exposes Werkzeug debugger, line 652)
# Code review finding: require_role() always returns True (CWE-862)
# =============================================================================
# TODO (Section B — Vulnerability #2): BROKEN AUTHORIZATION / LEAST PRIVILEGE
#
# Code review reveals that require_role() always returns True.
# This means ANY user can access ANY endpoint, including admin functions.
#
# This is an API security vulnerability because:
#   - CWE-862: Missing Authorization
#   - Violates the Principle of Least Privilege
#   - Regular users can delete other users, view all data, etc.
#
# YOUR TASKS:
#   B1: Take a screenshot of this insecure code with line numbers visible
#   B2: Implement proper role-based authorization checking
#   B3: Comment out the original insecure code after remediation
#
# For your Section D report:
#   D1: Describe 2 mitigation strategies for this vulnerability
# =============================================================================

def require_role(username, required_role):
    """
    TODO (Section B): Implement Role-Based Authorization (Least Privilege)

    This function should:
    1. Look up the user's role from USERS_DB
    2. Check if the user's role meets the required permission level
    3. Return True if authorized, False otherwise

    Role hierarchy (suggestion):
    - admin: can access everything
    - user: can access user-level endpoints
    - guest: limited read-only access
    """
    # INSECURE: Currently always returns True (no authorization)
    # TODO: Implement proper role checking
    return True


# =============================================================================
# Additional API Vulnerabilities (from bandit report + code review)
# You may also choose from these for Section B:
#   - Broken access control on admin endpoints (CWE-306, lines 432-467)
#   - Missing rate limiting / DoS vulnerable (CWE-307, lines 280-292)
#   - Insecure API key transmission in URL params (CWE-598)
#   - Unrestricted data exposure via REST APIs / SSN (CWE-359)
#   - Missing least privilege — all users see all data (CWE-285)
#   - SQL injection in API endpoint (B608, CWE-89, line 319)
#   - Flask debug mode exposing Werkzeug debugger (B201, CWE-94, line 652)
# =============================================================================

# =============================================================================
# Rate Limiting (Defense in Depth)
# =============================================================================
# TODO: Implement rate limiting to prevent brute force and DoS attacks
# See CWE-307 (Improper Restriction of Excessive Authentication Attempts)

def check_rate_limit(identifier):
    """
    TODO: Implement rate limit checking

    Parameters:
        identifier: IP address or API key to track

    Returns:
        True if request is allowed, False if rate limited
    """
    # INSECURE: Currently no rate limiting implemented
    # TODO: Implement rate limiting logic
    return True


# =============================================================================
# API Endpoints
# =============================================================================

@app.route('/api/v1/user', methods=['GET'])
def get_user_data():
    """
    Retrieve user information.

    VULNERABILITIES PRESENT (see flake8 and bandit reports):
    - SQL Injection via string concatenation (line 319)
    - Unsafe exception handling exposing internals (lines 346-347)
    - No authentication required
    - Sensitive data returned in response

    TODO (Section A — if chosen): Fix SQL injection and/or exception handling
    TODO (Section B — if chosen): Add API authentication
    TODO (Section D — D2): Describe input validation techniques
    TODO (Section D — D3): Describe exception handling improvements
    """
    username = request.args.get('username', '')

    # VULNERABLE: SQL Injection - string concatenation with user input
    # TODO: Replace with parameterized query
    query = "SELECT * FROM users WHERE username = '" + username + "'"

    # TODO: Add input validation for username

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            return jsonify({
                "status": "success",
                "data": dict(user)
            })
        else:
            if username in USERS_DB:
                # VULNERABLE: Returns all user data including password
                return jsonify({
                    "status": "success",
                    "data": USERS_DB[username]
                })
            return jsonify({"status": "error", "message": "User not found"}), 404

    # VULNERABLE: Exposes internal error details to client (CWE-209)
    # TODO (Section D — D3): Describe how to improve exception handling
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/v1/rentals', methods=['GET'])
def get_rentals():
    """
    Retrieve rental records.

    VULNERABILITIES PRESENT (see bandit report + code review):
    - No authentication (CWE-306)
    - No authorization / least privilege violation (CWE-285)
    - SSN/PII exposed in response (CWE-359)

    TODO (Section B — if chosen): Add authentication and authorization
    TODO: Filter sensitive fields (SSN) from response
    """
    # TODO: Add authentication check
    # user = require_api_key()
    # if not user:
    #     return jsonify({"status": "error", "message": "Authentication required"}), 401

    user_filter = request.args.get('user', '')

    if user_filter:
        filtered = [r for r in RENTAL_RECORDS if r['user'] == user_filter]
        return jsonify({"status": "success", "data": filtered})

    # INSECURE: Returns ALL rental records with SSN to any requester
    return jsonify({
        "status": "success",
        "data": RENTAL_RECORDS,
        "total_records": len(RENTAL_RECORDS)
    })


@app.route('/api/v1/rentals', methods=['POST'])
def create_rental():
    """
    Create a new rental record.

    VULNERABILITIES PRESENT (see flake8 report):
    - No input validation (lines 584-586)
    - No type checking or boundary checks
    - SSN field included in new records

    TODO (Section A — if chosen): Add input validation
    TODO (Section D — D2): Describe 2 input validation techniques used
    """
    # TODO: Add authentication check
    # TODO: Add rate limiting check

    data = request.get_json()

    equipment = data.get('equipment')
    days = data.get('days')
    username = data.get('username')

    # VULNERABLE: No validation - accepts any input
    if equipment in EQUIPMENT_PRICES:
        # VULNERABLE: No type checking - days could be negative or non-numeric
        total = EQUIPMENT_PRICES[equipment] * days

        new_rental = {
            "id": len(RENTAL_RECORDS) + 1,
            "user": username,
            "equipment": equipment,
            "days": days,
            "total": total,
            "ssn": "000-00-0000"  # VULNERABLE: SSN should not be stored
        }
        RENTAL_RECORDS.append(new_rental)

        return jsonify({
            "status": "success",
            "message": "Rental created",
            "data": new_rental
        }), 201
    else:
        return jsonify({"status": "error", "message": "Invalid equipment"}), 400


# =============================================================================
# Broken Access Control — Admin Endpoints
# Code review finding: CWE-306 — Missing Authentication for Critical Function
# =============================================================================
@app.route('/api/v1/admin/users', methods=['GET'])
def admin_get_all_users():
    """
    Administrative endpoint to list all users.

    VULNERABILITY (CWE-306): No authentication or authorization!
    Anyone can access the full list of users.

    TODO (Section B — if chosen): Require API key + admin role
    """
    # INSECURE: No authentication or authorization check!
    return jsonify({
        "status": "success",
        "data": list(USERS_DB.keys()),
        "message": "Admin access granted"
    })


@app.route('/api/v1/admin/delete_user', methods=['DELETE'])
def admin_delete_user():
    """
    Administrative endpoint to delete a user.

    VULNERABILITY (CWE-306): No authentication on destructive endpoint!
    Anyone can delete any user without authentication.

    TODO (Section B — if chosen): Require API key + admin role
    """
    # INSECURE: No authentication check on destructive operation!
    username = request.args.get('username', '')

    if username in USERS_DB:
        del USERS_DB[username]
        return jsonify({"status": "success", "message": f"User {username} deleted"})

    return jsonify({"status": "error", "message": "User not found"}), 404


# =============================================================================
# XSS Vulnerability — Unsanitized Input Reflected in Response
# Code review finding: XSS — unsanitized user input reflected in API response
# =============================================================================
@app.route('/api/v1/search', methods=['GET'])
def search_equipment():
    """
    Search for equipment by name.

    VULNERABILITY: Search query reflected directly in response without sanitization.
    This enables Cross-Site Scripting (XSS) attacks.
    See network_security_log.txt for XSS evidence.

    TODO (Section A — if chosen): Sanitize input before reflecting in response
    TODO (Section D — D2): Describe input sanitization as a validation technique
    """
    query = request.args.get('q', '')

    # TODO: Sanitize the query parameter (escape HTML, limit length, validate)

    results = []
    for equipment, price in EQUIPMENT_PRICES.items():
        if query.lower() in equipment.lower():
            results.append({"name": equipment, "price": price})

    # VULNERABLE: Reflects unsanitized input in response (XSS)
    return jsonify({
        "status": "success",
        "search_term": query,  # Unsanitized user input
        "results": results
    })


# =============================================================================
# Authentication Endpoint
# =============================================================================
@app.route('/api/v1/authenticate', methods=['POST'])
def authenticate():
    """
    Authenticate a user and return API credentials.

    VULNERABILITIES:
    - No rate limiting (CWE-307)
    - Plaintext password comparison
    - No account lockout

    TODO (Section B — if chosen): Implement rate limiting
    TODO: Use hashed password comparison
    """
    # TODO: Check rate limit before processing

    data = request.get_json()

    if not data:
        return jsonify({"status": "error", "message": "Request body required"}), 400

    username = data.get('username', '')
    password = data.get('password', '')

    if username in USERS_DB:
        # INSECURE: Plain text password comparison
        if USERS_DB[username]['password'] == password:
            return jsonify({
                "status": "success",
                "message": "Authentication successful",
                "api_key": USERS_DB[username]['api_key']
            })

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# =============================================================================
# Web Interface Routes
# =============================================================================

@app.route('/')
def home():
    print("Home page accessed")
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")

        if username in USERS_DB and USERS_DB[username]['password'] == password:
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid credentials.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/rent', methods=['GET', 'POST'])
def rent_equipment():
    """
    Equipment rental form endpoint.

    VULNERABILITY: Missing input validation (flake8 lines 584-586)
    - No type checking on 'days' input
    - No boundary validation
    - Could crash or produce negative charges
    """
    rental_result = None

    if request.method == 'POST':
        equipment_type = request.form.get("equipment_type")
        days_str = request.form.get("days")

        # VULNERABLE: No input validation - could crash or behave unexpectedly
        daily_rate = EQUIPMENT_PRICES[equipment_type]  # Could raise KeyError
        days = int(days_str)  # Could raise ValueError
        total_cost = daily_rate * days  # Could produce negative values

        print(f"Calculated cost: {total_cost}")

        rental_result = {
            "equipment": equipment_type,
            "days": days,
            "total_cost": total_cost
        }
        flash("Rental calculated successfully!", "success")

    return render_template('rent.html', rental_result=rental_result)


@app.route('/api/docs')
def api_documentation():
    """API Documentation page."""
    return render_template('api_docs.html')


# =============================================================================
# SECTION D: WRITTEN REPORT GUIDANCE
# =============================================================================
"""
TODO (Section D): Security Mitigation Report

Write a report covering the following rubric items:

D1 — Mitigation Strategies (for all 4 vulnerabilities you identified in A and B):
    For EACH of the 4 vulnerabilities (2 general + 2 API), describe:
    - What the vulnerability is and why it is dangerous
    - 2 specific mitigation strategies to address it
    Example: For hardcoded secrets — (1) use environment variables,
             (2) use a secrets management service like AWS Secrets Manager

D2 — Input Validation Techniques:
    Describe 2 input validation techniques you implemented or would implement:
    - Example: Type checking (verify data types before processing)
    - Example: Boundary checking (enforce min/max values)
    - Example: Whitelist validation (only allow known-good values)
    - Example: Sanitization (remove/escape dangerous characters)

D3 — Exception Handling Improvements:
    Describe 2 ways to improve exception handling:
    - Example: Return generic error messages to clients (not str(e))
    - Example: Log detailed errors server-side for debugging
    - Example: Use specific exception types instead of bare except
    - Example: Implement graceful degradation

D4 — Encryption Method:
    Describe 1 encryption method used for REST/API security:
    - Example: TLS/HTTPS for encrypting data in transit
    - Example: PBKDF2/bcrypt for password hashing at rest
    - Example: JWT signing for token integrity
"""


# =============================================================================
# Application Entry Point
# =============================================================================

if __name__ == '__main__':
    init_database()
    print("Starting application...")
    # VULNERABLE: Prints secret API key to console!
    print(f"WARNING: Using hardcoded API key: {API_KEY}")
    app.run(debug=True, port=5000)
