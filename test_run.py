"""
WGU Construction Equipment Rental - API Test Suite (Task 2 Student Starter)

SECTION C: Test Cases

Your Task:
Write test cases that demonstrate your security remediations work correctly.

Requirements (Rubric Section C):
  C1: Use the pytest framework with test_ naming convention (all test functions
      must start with "test_")
  C2: Each test must contain at least one assert statement
  C3: All tests must execute successfully (pass when run with pytest)
  C4: Include descriptive print() statements explaining what each test verifies
      and its outcome — these provide console output for your screenshots
  C5: Provide 4 screenshots of passing test results:
      - 2 screenshots for general security vulnerability tests (Section A fixes)
      - 2 screenshots for API security vulnerability tests (Section B fixes)

You need at least 4 test functions:
  - 2 tests verifying your Section A (general security) remediations
  - 2 tests verifying your Section B (API security) remediations

Run with: pytest test_run.py -v

Hint: Import from your solution file like this:
    from app_solution import app, EQUIPMENT_PRICES, USERS_DB
"""

import pytest
import json

# TODO: Import your Flask app and any functions you want to test
# from app_solution import app, EQUIPMENT_PRICES, USERS_DB


# ------------------------------------------------------------
# Test Fixture (Provided for you)
# Uncomment once you import your app
# ------------------------------------------------------------

# @pytest.fixture
# def client():
#     """Create a test client for the Flask application."""
#     app.config['TESTING'] = True
#     with app.test_client() as client:
#         yield client


# ============================================================
# GENERAL SECURITY VULNERABILITY TESTS (Section A remediations)
# These 2 tests verify your Section A fixes work correctly.
# Each needs: test_ prefix (C1), assert (C2), print() (C4)
# ============================================================

# ------------------------------------------------------------
# Test 1 of 2 (General Security): Hardcoded Secrets Remediation
# This test should verify that secrets are no longer hardcoded.
# ------------------------------------------------------------

def test_general_vuln_1_hardcoded_secrets_remediated():
    """
    TODO: Test that hardcoded secrets have been replaced with secure alternatives.

    Section A Vulnerability #1: Hardcoded Secrets
    Verify that app.secret_key is NOT the original hardcoded value.

    Example:
        from app_solution import app
        assert app.secret_key != 'supersecretkeyforflasksessions', \
            "Secret key should not be hardcoded"
        print("PASS: Secret key is no longer hardcoded — "
              "now using environment variable or generated token")
    """
    # TODO: Write your test with assert and print()
    pass  # Remove this line when you add your test


# ------------------------------------------------------------
# Test 2 of 2 (General Security): Plaintext Password Remediation
# This test should verify that passwords are hashed, not plaintext.
# ------------------------------------------------------------

def test_general_vuln_2_plaintext_passwords_remediated():
    """
    TODO: Test that passwords are stored as hashes, not plaintext.

    Section A Vulnerability #2: Plaintext Password Storage
    Verify that USERS_DB no longer contains plaintext "password" fields.

    Example:
        from app_solution import USERS_DB
        for username, data in USERS_DB.items():
            assert 'password' not in data, \
                f"User {username} still has plaintext password"
            assert 'password_hash' in data, \
                f"User {username} missing password_hash"
        print("PASS: All passwords are now stored as hashes — "
              "plaintext passwords have been removed from the database")
    """
    # TODO: Write your test with assert and print()
    pass  # Remove this line when you add your test


# ============================================================
# API SECURITY VULNERABILITY TESTS (Section B remediations)
# These 2 tests verify your Section B fixes work correctly.
# Each needs: test_ prefix (C1), assert (C2), print() (C4)
# ============================================================

# ------------------------------------------------------------
# Test 3 of 4 (API Security): API Authentication Remediation
# This test should verify that endpoints now require authentication.
# ------------------------------------------------------------

def test_api_vuln_1_authentication_required():
    """
    TODO: Test that API endpoints require authentication.

    Section B Vulnerability #1: Missing API Authentication
    Verify that accessing a protected endpoint without an API key returns 401.

    Example:
        from app_solution import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            response = client.get('/api/v1/rentals')
            assert response.status_code == 401, \
                f"Expected 401 Unauthorized, got {response.status_code}"
        print("PASS: API endpoint correctly requires authentication — "
              "unauthenticated requests receive 401 Unauthorized")
    """
    # TODO: Write your test with assert and print()
    pass  # Remove this line when you add your test


# ------------------------------------------------------------
# Test 4 of 4 (API Security): Authorization / Least Privilege Remediation
# This test should verify that role-based access control works.
# ------------------------------------------------------------

def test_api_vuln_2_authorization_enforced():
    """
    TODO: Test that authorization and least privilege are enforced.

    Section B Vulnerability #2: Broken Authorization
    Verify that non-admin users cannot access admin endpoints.

    Example:
        from app_solution import app, USERS_DB
        app.config['TESTING'] = True
        user_api_key = USERS_DB['alice']['api_key']
        with app.test_client() as client:
            response = client.get('/api/v1/admin/users',
                headers={'Authorization': f'Bearer {user_api_key}'}
            )
            assert response.status_code == 403, \
                f"Expected 403 Forbidden, got {response.status_code}"
        print("PASS: Authorization correctly enforced — "
              "regular user denied access to admin endpoint with 403 Forbidden")
    """
    # TODO: Write your test with assert and print()
    pass  # Remove this line when you add your test


# ============================================================
# ADDITIONAL TESTS (Optional)
# You may add more tests to thoroughly validate your solution.
# Consider testing: rate limiting, data exposure, XSS prevention,
# input validation, SQL injection prevention, etc.
# ============================================================
