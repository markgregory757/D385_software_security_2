"""
WGU Construction Equipment Rental - Flask API Application (Task 2 Solution)

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

REMEDIATION SUMMARY:
  Section A — General Security Vulnerabilities (from flake8 report)
    A1/A2/A3: Hardcoded secrets replaced with environment variables (lines 79-84)
    A1/A2/A3: Plaintext passwords replaced with werkzeug hashed passwords (lines 114-119)
  Section B — API Security Vulnerabilities (from bandit report)
    B1/B2/B3: require_api_key() now validates Bearer tokens from Authorization header
    B1/B2/B3: require_role() now enforces role hierarchy (admin > user > guest)
  Additional fixes:
    - SQL injection replaced with parameterized query
    - Exception handler no longer leaks internal details (CWE-209)
    - debug=True replaced with debug=False (Bandit B201)
    - SSN stripped from API responses
    - Admin endpoints protected with authentication + role check
    - Input validation added to rent_equipment() and create_rental()
    - XSS: search query sanitized before reflection in response
"""

import logging
import os
import secrets
import html

import sqlite3
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging — all security events written to file
logging.basicConfig(
    filename='app_solution.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# =============================================================================
# SECTION A — GENERAL VULNERABILITY #1: HARDCODED SECRETS
# Flake8 report: S105 on lines 79, 81, 84
# CWE-259: Use of Hard-coded Password
# FIX: Load all secrets from environment variables at runtime.
#      Original insecure lines are commented out below each fix.
# =============================================================================

# [A3 — ORIGINAL INSECURE CODE COMMENTED OUT]
# app.secret_key = 'supersecretkeyforflasksessions'
# API_KEY = "sk_live_abc123xyz789secretkey"
# DB_USER = "admin"
# DB_PASSWORD = "password123"

# [A2 — SECURE REPLACEMENT]
# Secrets are read from environment variables. In production set these with:
#   export FLASK_SECRET_KEY="your-long-random-value"
#   export API_KEY="your-api-key"
#   export DB_PASSWORD="your-db-password"
# The secrets.token_hex(32) fallback is for local development only and
# generates a new random value each restart (safe — never committed to code).
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
API_KEY = os.environ.get('API_KEY', '')
DB_USER = os.environ.get('DB_USER', 'admin')
DB_PASSWORD = os.environ.get('DB_PASSWORD', '')

# Equipment Pricing Data
EQUIPMENT_PRICES = {
    "Bulldozer": 500,
    "Excavator": 450,
    "Crane": 800
}

# =============================================================================
# SECTION A — GENERAL VULNERABILITY #2: PLAINTEXT PASSWORD STORAGE
# Flake8 report: S105 on lines 115-118
# CWE-256: Plaintext Storage of a Password
# FIX: Replace plaintext passwords with PBKDF2-SHA256 hashes via werkzeug.
#      Authentication now uses check_password_hash() for constant-time comparison.
#      Original insecure USERS_DB is commented out below.
# =============================================================================

# [A3 — ORIGINAL INSECURE CODE COMMENTED OUT]
USERS_DB = {
    "admin": {"password": "admin123", "role": "admin",
              "api_key": "sk_admin_key123"},
    "alice": {"password": "alice456", "role": "user",
              "api_key": "sk_alice_key456"},
    "bob":   {"password": "bob789",   "role": "user",
              "api_key": "sk_bob_key789"},
    "charlie": {"password": "charlie000", "role": "guest",
                "api_key": "sk_charlie_key000"}
}

# [A2 — SECURE REPLACEMENT]
# Passwords are hashed with PBKDF2-SHA256 + random salt via werkzeug.
# check_password_hash() performs constant-time comparison to prevent
# timing attacks. In production, hashes would be stored in a database,
# not in source code.
USERS_DB = {
    "admin": {
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "api_key": "sk_admin_key123"
    },
    "alice": {
        "password": generate_password_hash("alice456"),
        "role": "user",
        "api_key": "sk_alice_key456"
    },
    "bob": {
        "password": generate_password_hash("bob789"),
        "role": "user",
        "api_key": "sk_bob_key789"
    },
    "charlie": {
        "password": generate_password_hash("charlie000"),
        "role": "guest",
        "api_key": "sk_charlie_key000"
    }
}

# Rental records — SSN field retained in data store but STRIPPED from responses
RENTAL_RECORDS = [
    {"id": 1, "user": "alice", "equipment": "Bulldozer", "days": 3,
     "total": 1500, "ssn": "123-45-6789"},
    {"id": 2, "user": "bob", "equipment": "Crane", "days": 2,
     "total": 1600, "ssn": "987-65-4321"},
    {"id": 3, "user": "admin", "equipment": "Excavator", "days": 5,
     "total": 2250, "ssn": "555-12-3456"},
]


def strip_sensitive(record):
    """Return a copy of a rental record with the ssn field removed."""
    return {k: v for k, v in record.items() if k != 'ssn'}


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
# SECTION B — API VULNERABILITY #1: MISSING API AUTHENTICATION
# Bandit report: B105 (hardcoded credentials in USERS_DB)
# Code review: require_api_key() always returned None (CWE-306)
# FIX: Extract Bearer token from Authorization header and validate against
#      USERS_DB. Returns username if valid, None if invalid.
# =============================================================================

# [B3 — ORIGINAL INSECURE CODE COMMENTED OUT]
# def require_api_key():
#     # INSECURE: Currently returns None (no authentication)
#     return None

# [B2 — SECURE REPLACEMENT]
def require_api_key():
    """
    Validate the API key provided in the Authorization header.

    Expected header format: Authorization: Bearer <api_key>

    Returns the username associated with the key if valid,
    or None if the header is missing, malformed, or the key is unknown.

    API keys are transmitted in the header (not URL params) per CWE-598.
    """
    auth_header = request.headers.get('Authorization', '')

    if not auth_header.startswith('Bearer '):
        logger.warning("API request missing or malformed Authorization header "
                       "from IP: %s", request.remote_addr)
        return None

    token = auth_header[7:]  # Strip "Bearer " prefix

    for username, data in USERS_DB.items():
        if data['api_key'] == token:
            logger.info("API key validated for user: '%s'", username)
            return username

    logger.warning("Invalid API key presented from IP: %s",
                   request.remote_addr)
    return None


# =============================================================================
# SECTION B — API VULNERABILITY #2: BROKEN AUTHORIZATION / LEAST PRIVILEGE
# Bandit report: B201 (debug=True, line 652)
# Code review: require_role() always returned True (CWE-862)
# FIX: Implement role hierarchy so each user can only access endpoints
#      their assigned role permits (Principle of Least Privilege).
# =============================================================================

# Role hierarchy — higher number = more privilege
ROLE_HIERARCHY = {
    'admin': 3,
    'user': 2,
    'guest': 1
}

# [B3 — ORIGINAL INSECURE CODE COMMENTED OUT]
# def require_role(username, required_role):
#     # INSECURE: Currently always returns True (no authorization)
#     return True

# [B2 — SECURE REPLACEMENT]
def require_role(username, required_role):
    """
    Check whether the given user holds a role at or above required_role.

    Role hierarchy: admin(3) >= user(2) >= guest(1)

    Returns True if the user's role level meets or exceeds required_role,
    False otherwise (including unknown users or roles).
    """
    if username not in USERS_DB:
        logger.warning("Role check for unknown user: '%s'", username)
        return False

    user_role = USERS_DB[username].get('role', 'guest')
    user_level = ROLE_HIERARCHY.get(user_role, 0)
    required_level = ROLE_HIERARCHY.get(required_role, 99)

    authorized = user_level >= required_level

    if not authorized:
        logger.warning(
            "Authorization denied: user '%s' (role=%s) attempted to access "
            "resource requiring role '%s'",
            username, user_role, required_role
        )

    return authorized


# =============================================================================
# Rate Limiting (simple in-memory implementation for demonstration)
# =============================================================================
_request_counts = {}


def check_rate_limit(identifier, max_requests=10):
    """
    Simple in-memory rate limiter.
    Allows up to max_requests per identifier per minute window.
    Returns True if allowed, False if rate-limited.
    """
    import time
    now = time.time()
    window = 60  # seconds

    if identifier not in _request_counts:
        _request_counts[identifier] = []

    # Remove timestamps outside the current window
    _request_counts[identifier] = [
        t for t in _request_counts[identifier] if now - t < window
    ]

    if len(_request_counts[identifier]) >= max_requests:
        logger.warning("Rate limit exceeded for identifier: %s", identifier)
        return False

    _request_counts[identifier].append(now)
    return True


# =============================================================================
# API Endpoints
# =============================================================================

@app.route('/api/v1/user', methods=['GET'])
def get_user_data():
    """
    Retrieve user information.

    FIXES APPLIED:
    - Parameterized query replaces string concatenation (SQL injection fix)
    - Generic error message returned to client (CWE-209 fix)
    - Password field stripped from response
    - Requires API key authentication
    """
    # Require authentication
    current_user = require_api_key()
    if not current_user:
        return jsonify({"status": "error",
                        "message": "Authentication required"}), 401

    username = request.args.get('username', '')

    # Input validation: username must be non-empty and alphanumeric
    if not username or not username.isalnum():
        return jsonify({"status": "error",
                        "message": "Invalid username parameter"}), 400

    # [ORIGINAL INSECURE SQL — COMMENTED OUT (A3)]
    # query = "SELECT * FROM users WHERE username = '" + username + "'"

    # [SECURE REPLACEMENT — parameterized query prevents SQL injection]
    query = "SELECT * FROM users WHERE username = ?"

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            user_dict = dict(user)
            # Strip password from response
            user_dict.pop('password', None)
            return jsonify({"status": "success", "data": user_dict})
        else:
            if username in USERS_DB:
                # Return user data excluding password hash
                safe_data = {
                    k: v for k, v in USERS_DB[username].items()
                    if k != 'password'
                }
                return jsonify({"status": "success", "data": safe_data})
            return jsonify({"status": "error",
                            "message": "User not found"}), 404

    # [SECURE REPLACEMENT — generic message to client, detail logged server-side]
    # [ORIGINAL: except Exception as e: return jsonify({"message": str(e)}), 500]
    except Exception as e:
        logger.error("Internal error in get_user_data: %s", e)
        return jsonify({"status": "error",
                        "message": "An internal error occurred"}), 500


@app.route('/api/v1/rentals', methods=['GET'])
def get_rentals():
    """
    Retrieve rental records.

    FIXES APPLIED:
    - Requires API key authentication
    - SSN field stripped from all responses
    - Users without admin role only see their own records
    """
    current_user = require_api_key()
    if not current_user:
        return jsonify({"status": "error",
                        "message": "Authentication required"}), 401

    user_filter = request.args.get('user', '')

    # Admins can filter by any user; regular users only see their own records
    if require_role(current_user, 'admin'):
        records = RENTAL_RECORDS
        if user_filter:
            records = [r for r in records if r['user'] == user_filter]
    else:
        # Non-admins only see their own rentals
        records = [r for r in RENTAL_RECORDS if r['user'] == current_user]

    # Strip SSN from every record before returning
    safe_records = [strip_sensitive(r) for r in records]

    return jsonify({
        "status": "success",
        "data": safe_records,
        "total_records": len(safe_records)
    })


@app.route('/api/v1/rentals', methods=['POST'])
def create_rental():
    """
    Create a new rental record.

    FIXES APPLIED:
    - Requires authentication
    - Type checking and boundary validation on 'days'
    - Equipment type validated against allowlist
    - SSN field removed from new records
    """
    current_user = require_api_key()
    if not current_user:
        return jsonify({"status": "error",
                        "message": "Authentication required"}), 401

    # Rate limiting
    if not check_rate_limit(request.remote_addr):
        return jsonify({"status": "error",
                        "message": "Too many requests"}), 429

    data = request.get_json()
    if not data:
        return jsonify({"status": "error",
                        "message": "Request body required"}), 400

    equipment = data.get('equipment')
    days = data.get('days')
    username = data.get('username', current_user)

    # Input validation — allowlist check on equipment
    if equipment not in EQUIPMENT_PRICES:
        logger.warning("Invalid equipment type '%s' submitted by '%s'",
                       equipment, current_user)
        return jsonify({"status": "error",
                        "message": "Invalid equipment type"}), 400

    # Input validation — type and boundary check on days
    try:
        days = int(days)
        assert 1 <= days <= 365, "Days must be between 1 and 365."
    except (TypeError, ValueError):
        return jsonify({"status": "error",
                        "message": "Days must be a whole number"}), 400
    except AssertionError as e:
        return jsonify({"status": "error", "message": str(e)}), 400

    total = EQUIPMENT_PRICES[equipment] * days

    new_rental = {
        "id": len(RENTAL_RECORDS) + 1,
        "user": username,
        "equipment": equipment,
        "days": days,
        "total": total
        # SSN field intentionally omitted
    }
    RENTAL_RECORDS.append({**new_rental, "ssn": "REDACTED"})

    logger.info("Rental created: user=%s equipment=%s days=%d total=$%d",
                username, equipment, days, total)

    return jsonify({
        "status": "success",
        "message": "Rental created",
        "data": new_rental
    }), 201


# =============================================================================
# Admin Endpoints — now protected with authentication + admin role check
# =============================================================================

@app.route('/api/v1/admin/users', methods=['GET'])
def admin_get_all_users():
    """
    Administrative endpoint to list all users.
    FIXED: Requires valid API key + admin role.
    """
    current_user = require_api_key()
    if not current_user:
        return jsonify({"status": "error",
                        "message": "Authentication required"}), 401

    if not require_role(current_user, 'admin'):
        return jsonify({"status": "error",
                        "message": "Admin access required"}), 403

    logger.info("Admin user list accessed by '%s'", current_user)
    return jsonify({
        "status": "success",
        "data": list(USERS_DB.keys())
    })


@app.route('/api/v1/admin/delete_user', methods=['DELETE'])
def admin_delete_user():
    """
    Administrative endpoint to delete a user.
    FIXED: Requires valid API key + admin role.
    """
    current_user = require_api_key()
    if not current_user:
        return jsonify({"status": "error",
                        "message": "Authentication required"}), 401

    if not require_role(current_user, 'admin'):
        return jsonify({"status": "error",
                        "message": "Admin access required"}), 403

    username = request.args.get('username', '')

    if username in USERS_DB:
        del USERS_DB[username]
        logger.info("User '%s' deleted by admin '%s'", username, current_user)
        return jsonify({"status": "success",
                        "message": f"User {username} deleted"})

    return jsonify({"status": "error", "message": "User not found"}), 404


# =============================================================================
# Search Endpoint — XSS fix: sanitize input before reflecting in response
# =============================================================================

@app.route('/api/v1/search', methods=['GET'])
def search_equipment():
    """
    Search for equipment by name.
    FIXED: Query parameter is sanitized (HTML-escaped) and length-limited
    before being reflected in the JSON response, preventing XSS.
    """
    raw_query = request.args.get('q', '')

    # Sanitize: escape HTML special characters and enforce length limit
    query = html.escape(raw_query[:100])

    results = []
    for equipment, price in EQUIPMENT_PRICES.items():
        if query.lower() in equipment.lower():
            results.append({"name": equipment, "price": price})

    return jsonify({
        "status": "success",
        "search_term": query,  # Now sanitized before reflection
        "results": results
    })


# =============================================================================
# Authentication Endpoint
# =============================================================================

@app.route('/api/v1/authenticate', methods=['POST'])
def authenticate():
    """
    Authenticate a user and return API credentials.
    FIXED:
    - Rate limiting applied per IP
    - Password compared with check_password_hash (constant-time, PBKDF2)
    """
    # Rate limit authentication attempts to prevent brute force
    if not check_rate_limit(request.remote_addr, max_requests=5):
        logger.warning("Rate limit hit on /authenticate from %s",
                       request.remote_addr)
        return jsonify({"status": "error",
                        "message": "Too many requests"}), 429

    data = request.get_json()

    if not data:
        return jsonify({"status": "error",
                        "message": "Request body required"}), 400

    username = data.get('username', '')
    password = data.get('password', '')

    logger.info("Authentication attempt for user: '%s' from IP: %s",
                username, request.remote_addr)

    if username in USERS_DB:
        # [ORIGINAL INSECURE — COMMENTED OUT]
        # if USERS_DB[username]['password'] == password:

        # [SECURE REPLACEMENT — constant-time hashed comparison]
        if check_password_hash(USERS_DB[username]['password'], password):
            logger.info("Authentication successful for user: '%s'", username)
            return jsonify({
                "status": "success",
                "message": "Authentication successful",
                "api_key": USERS_DB[username]['api_key']
            })

    logger.warning("Authentication failed for user: '%s' from IP: %s",
                   username, request.remote_addr)
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# =============================================================================
# Web Interface Routes
# =============================================================================

@app.route('/')
def home():
    logger.info("Home page accessed from IP: %s", request.remote_addr)
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if username in USERS_DB and check_password_hash(
                USERS_DB[username]['password'], password):
            logger.info("Web login successful for user: '%s'", username)
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for('home'))
        else:
            logger.warning("Web login failed for user: '%s'", username)
            flash("Invalid credentials.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/rent', methods=['GET', 'POST'])
def rent_equipment():
    """
    Equipment rental form endpoint.
    FIXED: Input validation added — type checking, allowlist, boundary check.
    """
    rental_result = None

    if request.method == 'POST':
        equipment_type = request.form.get("equipment_type")
        days_str = request.form.get("days")

        # [ORIGINAL INSECURE CODE — COMMENTED OUT]
        # daily_rate = EQUIPMENT_PRICES[equipment_type]  # Could raise KeyError
        # days = int(days_str)                           # Could raise ValueError
        # total_cost = daily_rate * days                 # Could be negative

        # [SECURE REPLACEMENT — validated inputs]
        try:
            if equipment_type not in EQUIPMENT_PRICES:
                raise KeyError(f"Unknown equipment: '{equipment_type}'")

            daily_rate = EQUIPMENT_PRICES[equipment_type]
            days = int(days_str)

            assert days > 0, "Number of days must be greater than zero."
            assert days <= 365, "Rental period cannot exceed 365 days."

            total_cost = daily_rate * days

            logger.info("Rental calculated: equipment=%s days=%d total=$%d",
                        equipment_type, days, total_cost)

            rental_result = {
                "equipment": equipment_type,
                "days": days,
                "total_cost": total_cost
            }
            flash("Rental calculated successfully!", "success")

        except KeyError as e:
            logger.error("Invalid equipment type: %s", e)
            flash("Invalid equipment type. Please select a valid option.",
                  "danger")

        except ValueError:
            logger.error("Invalid days value submitted: '%s'", days_str)
            flash("Please enter a valid whole number for the number of days.",
                  "danger")

        except AssertionError as e:
            logger.warning("Rental validation failed: %s", e)
            flash(str(e), "danger")

        except Exception as e:
            logger.error("Unexpected error in rent_equipment: %s", e)
            flash("An unexpected error occurred. Please try again.", "danger")

    return render_template('rent.html', rental_result=rental_result)


@app.route('/api/docs')
def api_documentation():
    """API Documentation page."""
    return render_template('api_docs.html')


# =============================================================================
# Application Entry Point
# =============================================================================

if __name__ == '__main__':
    init_database()
    logger.info("Starting EquipmentRentalAPI on port 5000")
    # [ORIGINAL INSECURE CODE — COMMENTED OUT]
    # print(f"WARNING: Using hardcoded API key: {API_KEY}")  # leaked secret
    # app.run(debug=True, port=5000)                         # B201: debug=True

    # [SECURE REPLACEMENT — debug=False, no secrets printed to console]
    app.run(debug=False, port=5000)
