import unittest      # Import unittest for writing test cases
import os            # For file operations (delete temporary file after each test)
import tempfile      # To create a temporary users.json for testing
import pyotp         # To generate TOTP codes for 2FA
from MainSecure import SimpleSecureLogin  # Import the class from MainSecure.py


class TestSimpleSecureLogin(unittest.TestCase):  # Define the test class

    def setUp(self):
        # This runs before every test to set up a temporary environment
        self.test_file = tempfile.NamedTemporaryFile(delete=False)
        self.test_file.close()  # Close file handle to avoid Windows errors
        self.auth = SimpleSecureLogin(data_file=self.test_file.name)  # Use a temp users.json

    def tearDown(self):
        # This runs after every test to remove the temporary file
        os.remove(self.test_file.name)

    def test_register_new_user(self):
        # Test registering a new user
        result = self.auth.register("Aris", "NMG123456")  # Will ask for manual 2FA input
        self.assertTrue(result)  # Expect True if registration successful
        self.assertIn("Aris", self.auth.users)  # Verify user exists

    def test_register_existing_user(self):
        # Test registering a user that already exists
        self.auth.register("user1", "Pass1234")  # Register once
        result = self.auth.register("user1", "New45678")  # Try again with same username
        self.assertFalse(result)  # Should return False

    def test_register_short_password(self):
        # Test registering with a too-short password
        result = self.auth.register("short", "123")  # Too short
        self.assertFalse(result)  # Should fail

    def test_register_password_contains_username(self):
        # Test registering where password contains the username
        result = self.auth.register("ArisG", "ArisG12345")  # Password contains username
        self.assertFalse(result)  # Should fail

    def test_login_wrong_password(self):
        # Test login with wrong password
        self.auth.register("test", "Password123")  # Register
        result = self.auth.login("test", "WrongPass123")  # Try wrong password
        self.assertFalse(result)

    def test_login_non_existing_user(self):
        # Test login with a non-existing username
        result = self.auth.login("no_such_user", "Password123")
        self.assertFalse(result)

    def test_hash_password_differs_each_time(self):
        # Test that hashing the same password twice gives different hashes
        hash1 = self.auth.hash_password("mypassword")
        hash2 = self.auth.hash_password("mypassword")
        self.assertNotEqual(hash1, hash2)

    def test_verify_correct_password(self):
        # Test that verify_password returns True for the correct password
        password = "mypassword"
        hashed = self.auth.hash_password(password)
        self.assertTrue(self.auth.verify_password(hashed, password))

    def test_verify_wrong_password(self):
        # Test that verify_password returns False for the wrong password
        password = "mypassword"
        hashed = self.auth.hash_password(password)
        self.assertFalse(self.auth.verify_password(hashed, "wrongpass"))


if __name__ == "__main__":
    unittest.main()  # Run all tests
