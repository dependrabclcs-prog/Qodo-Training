"""Minimal reproducible example for password hashing that avoids hashlib.scrypt.

This script uses werkzeug.generate_password_hash with PBKDF2 (sha256) explicitly
and verifies with check_password_hash. It should work even when hashlib.scrypt
is not available in the Python build.
"""
from werkzeug.security import generate_password_hash, check_password_hash


def demo():
    password = 'correcthorsebatterystaple'
    # Explicitly request PBKDF2 with sha256
    hashed = generate_password_hash(password, method='pbkdf2:sha256')
    print('Password:', password)
    print('Hash:', hashed)

    # Verify
    OK = check_password_hash(hashed, password)
    print('Verified:', OK)


if __name__ == '__main__':
    demo()
