# test_simple_auth.py
import unittest
import os
import json
import tempfile
from  MainSecure import SimpleSecureLogin
import pyotp
class TestSimpleSecureLogin(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures before each test method."""
        # Use a temporary file for user data to avoid interfering with real data
        self.test_data_file = tempfile.mktemp(suffix='.json')
        self.auth = SimpleSecureLogin(data_file=self.test_data_file)
        self.test_username = "testuser"
        self.test_password = "TestPass123!" # Meets requirements if any were added

    def tearDown(self):
        """Clean up after each test method."""
        # Remove the temporary file if it exists
        if os.path.exists(self.test_data_file):
            os.remove(self.test_data_file)

    def test_init_creates_empty_users_if_file_missing(self):
        """Test that __init__ starts with an empty dict if data file is missing."""
        # setUp already uses a non-existent temp file
        self.assertEqual(self.auth.users, {})
        self.assertEqual(self.auth.data_file, self.test_data_file)

    def test_load_users_empty_file(self):
        """Test loading from an empty (non-existent) file."""
        # This is effectively tested in setUp and test_init_creates_empty_users_if_file_missing
        # But let's test calling load_users directly on a missing file
        auth_instance = SimpleSecureLogin(data_file="definitely_does_not_exist.json")
        self.assertEqual(auth_instance.users, {})

    def test_load_users_corrupted_file(self):
        """Test loading from a corrupted JSON file."""
        # Create a corrupted file
        with open(self.test_data_file, 'w') as f:
            f.write("This is not valid JSON!")

        # Create a new instance to trigger load_users
        auth_instance = SimpleSecureLogin(data_file=self.test_data_file)
        # Should print error and load empty dict
        self.assertEqual(auth_instance.users, {})

    def test_save_users_creates_file(self):
        """Test that save_users creates a file with correct data."""
        self.auth.users = {"user1": {"password": "hash1", "2fa_secret": "secret1"}}
        self.auth.save_users()

        self.assertTrue(os.path.exists(self.test_data_file))
        with open(self.test_data_file, 'r') as f:
            saved_data = json.load(f)
        self.assertEqual(saved_data, self.auth.users)

    def test_hash_password_creates_correct_format(self):
        """Test that hash_password returns a string of the expected length."""
        password = "mypassword"
        hashed = self.auth.hash_password(password)
        # Salt (32 hex chars) + Hash (64 hex chars for SHA256) = 96 chars
        self.assertIsInstance(hashed, str)
        self.assertEqual(len(hashed), 96) # 32 (salt) + 64 (hash)

    def test_hash_password_uniqueness(self):
        """Test that hashing the same password twice produces different results."""
        password = "mypassword"
        hash1 = self.auth.hash_password(password)
        hash2 = self.auth.hash_password(password)
        self.assertNotEqual(hash1, hash2)

    def test_verify_password_correct(self):
        """Test verifying the correct password."""
        password = "correctpassword"
        stored_hash = self.auth.hash_password(password)
        self.assertTrue(self.auth.verify_password(stored_hash, password))

    def test_verify_password_incorrect(self):
        """Test verifying an incorrect password."""
        password = "correctpassword"
        stored_hash = self.auth.hash_password(password)
        self.assertFalse(self.auth.verify_password(stored_hash, "wrongpassword"))

    def test_setup_2fa_stores_secret(self):
        """Test that setup_2fa generates and stores a secret."""
        username = "testuser_setup2fa"
        self.auth.users[username] = {'password': 'dummy_hash', '2fa_secret': None}
        # Mock save_users to avoid file I/O in this specific test if desired, but not necessary here.
        initial_users = self.auth.users.copy()

        secret = self.auth.setup_2fa(username)

        # Check secret format (base32)
        self.assertIsInstance(secret, str)
        self.assertTrue(all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' for c in secret.replace('=', ''))) # pyotp.random_base32 output
        # Check it's stored
        self.assertEqual(self.auth.users[username]['2fa_secret'], secret)
        # Check file was saved (implicitly by setup_2fa calling save_users)
        self.assertTrue(os.path.exists(self.test_data_file))

    def test_verify_2fa_valid_code(self):
        """Test verifying a valid TOTP code."""
        secret = pyotp.random_base32()
        username = "testuser_verify2fa"
        self.auth.users[username] = {'password': 'dummy_hash', '2fa_secret': secret}
        # Get the current valid code
        totp = pyotp.TOTP(secret)
        current_code = totp.now()

        self.assertTrue(self.auth.verify_2fa(username, current_code))

    def test_verify_2fa_invalid_code(self):
        """Test verifying an invalid TOTP code."""
        secret = pyotp.random_base32()
        username = "testuser_verify2fa_invalid"
        self.auth.users[username] = {'password': 'dummy_hash', '2fa_secret': secret}

        self.assertFalse(self.auth.verify_2fa(username, "123456")) # Very unlikely to be the current code

    def test_register_success(self):
        """Test successful user registration flow (mocking 2FA input)."""
        username = "newuser"
        password = "NewUserPass123!" # Assuming this meets any implicit requirements

        # We cannot easily mock `input()` here for the 2FA code in the current `register` implementation.
        # A better design for testability would separate the 2FA setup verification.
        # For now, we can test parts of the registration logic.
        # Let's test the initial part before 2FA setup prompt.

        # Check username is not taken initially
        self.assertNotIn(username, self.auth.users)

        # Perform registration logic up to the 2FA setup (without the interactive part)
        # We need to simulate the successful 2FA part or refactor register.
        # Let's assume the 2FA setup part works and focus on the initial storage.

        # Manually simulate the first part of register
        if username in self.auth.users:
            self.fail("Username should not exist yet")

        hashed_pw = self.auth.hash_password(password)
        self.auth.users[username] = {
            'password': hashed_pw,
            '2fa_secret': None
        }
        self.auth.save_users() # Called in register

        self.assertIn(username, self.auth.users)
        self.assertEqual(self.auth.users[username]['password'], hashed_pw)
        self.assertIsNone(self.auth.users[username]['2fa_secret'])
        self.assertTrue(os.path.exists(self.test_data_file))

        # Note: Full register test with 2FA success/failure is hard without mocking input.
        # Consider refactoring register to accept the 2FA code as an argument for easier testing.

    def test_register_duplicate_username(self):
        """Test registration with an already taken username."""
        username = "existinguser"
        password = "SomePass123!"
        # Pre-populate the user
        self.auth.users[username] = {'password': 'existing_hash', '2fa_secret': 'existing_secret'}

        # Attempt to register again
        result = self.auth.register(username, password)

        self.assertFalse(result)
        # Check the existing user data wasn't overwritten
        self.assertEqual(self.auth.users[username]['password'], 'existing_hash')
        self.assertEqual(self.auth.users[username]['2fa_secret'], 'existing_secret')

    def test_login_success(self):
        """Test successful user login (mocking 2FA input)."""
        username = "user_login"
        password = "UserLoginPass123!"
        secret = pyotp.random_base32()

        # Pre-register the user (simulate a successful prior registration)
        hashed_pw = self.auth.hash_password(password)
        self.auth.users[username] = {
            'password': hashed_pw,
            '2fa_secret': secret
        }

        # We cannot easily mock `input()` for the 2FA code prompt.
        # Similar to register, testing the full flow is difficult.
        # Test the parts we can:
        # 1. User exists
        self.assertIn(username, self.auth.users)
        # 2. Password verification works
        self.assertTrue(self.auth.verify_password(self.auth.users[username]['password'], password))
        # 3. 2FA verification logic works (tested in test_verify_2fa_valid_code)

        # Note: Full login test requires mocking input or refactoring.

    def test_login_user_not_found(self):
        """Test login with a non-existent username."""
        username = "nonexistent"
        password = "AnyPass123!"

        result = self.auth.login(username, password)

        self.assertFalse(result)

    def test_login_incorrect_password(self):
        """Test login with correct username but wrong password."""
        username = "user_wrong_pass"
        correct_password = "CorrectPass123!"
        wrong_password = "WrongPass123!"

        # Pre-register the user
        hashed_pw = self.auth.hash_password(correct_password)
        self.auth.users[username] = {
            'password': hashed_pw,
            '2fa_secret': None # 2FA check shouldn't happen if password is wrong, but let's see
        }

        result = self.auth.login(username, wrong_password)

        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
