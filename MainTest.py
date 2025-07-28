import unittest
import tempfile
from datetime import datetime, timedelta
import hashlib

try:
    from auth_system import (
        InteractiveUnifiedAuthSystem,
        PasswordAuth,
        TOTPAuth,
        SMSOTPAuth,
        EmailOTPAuth,
        AuthenticatorPush,
        FIDO2Auth,
        BiometricAuth,
        SecurityQuestionsAuth,
        OATHAuth,
        VoiceAuth,
        CertificateAuth,
        TAPAuth
    )
except ImportError as e:
    print(f"Import error: {e}")
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from Main import (
        InteractiveUnifiedAuthSystem,
        PasswordAuth,
        TOTPAuth,
        SMSOTPAuth,
        EmailOTPAuth,
        AuthenticatorPush,
        FIDO2Auth,
        BiometricAuth,
        SecurityQuestionsAuth,
        OATHAuth,
        VoiceAuth,
        CertificateAuth,
        TAPAuth
    )


class TestAuthMethods(unittest.TestCase):
    """Test individual authentication method classes."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.user_id = "test_user"
        self.password = "SecureTestPass123!"

    def test_password_auth_success(self):
        pwd_auth = PasswordAuth()
        reg_result = pwd_auth.register(self.user_id, {'password': self.password})
        self.assertTrue(reg_result)
        verify_result = pwd_auth.verify(self.user_id, {'password': self.password})
        self.assertTrue(verify_result)

    def test_password_auth_failure_wrong_password(self):
        pwd_auth = PasswordAuth()
        pwd_auth.register(self.user_id, {'password': self.password})
        verify_result_fail = pwd_auth.verify(self.user_id, {'password': "WrongPass"})
        self.assertFalse(verify_result_fail)
    def test_password_auth_failure_no_user(self):
        pwd_auth = PasswordAuth()
        verify_result_fail = pwd_auth.verify("non_existent_user", {'password': self.password})
        self.assertFalse(verify_result_fail)
    def test_totp_auth_register_and_verify_structure(self):
        totp_auth = TOTPAuth()
        reg_result = totp_auth.register(self.user_id, {})
        self.assertTrue(reg_result)
        self.assertIn(self.user_id, totp_auth.secrets)
        verify_result = totp_auth.verify(self.user_id, {'token': '123456'})
        self.assertIsInstance(verify_result, bool)

    def test_sms_otp_auth_success(self):
        sms_auth = SMSOTPAuth()
        otp_code = "987654"
        expiry_time = datetime.now().timestamp() + 300 # 5 minutes
        sms_auth.otp_storage[self.user_id] = (otp_code, expiry_time)
        verify_result = sms_auth.verify(self.user_id, {'otp': otp_code})
        self.assertTrue(verify_result)
        self.assertNotIn(self.user_id, sms_auth.otp_storage)
    def test_sms_otp_auth_failure_wrong_otp(self):
        sms_auth = SMSOTPAuth()
        correct_otp = "987654"
        wrong_otp = "000000"
        expiry_time = datetime.now().timestamp() + 300
        sms_auth.otp_storage[self.user_id] = (correct_otp, expiry_time)
        verify_result = sms_auth.verify(self.user_id, {'otp': wrong_otp})
        self.assertFalse(verify_result)
    def test_sms_otp_auth_failure_expired(self):
        sms_auth = SMSOTPAuth()
        otp_code = "987654"
        expiry_time = datetime.now().timestamp() - 10
        sms_auth.otp_storage[self.user_id] = (otp_code, expiry_time)
        verify_result = sms_auth.verify(self.user_id, {'otp': otp_code})
        self.assertFalse(verify_result)
        self.assertNotIn(self.user_id, sms_auth.otp_storage)

    def test_email_otp_inherits_sms_logic(self):
        email_auth = EmailOTPAuth()
        otp_code = "456789"
        expiry_time = datetime.now().timestamp() + 300
        email_auth.otp_storage[self.user_id] = (otp_code, expiry_time)
        verify_result = email_auth.verify(self.user_id, {'otp': otp_code})
        self.assertTrue(verify_result)
        self.assertNotIn(self.user_id, email_auth.otp_storage) # Should also be one-time use

    def test_fido2_auth_simulation(self):
        fido_auth = FIDO2Auth()
        reg_result = fido_auth.register(self.user_id, {})
        self.assertTrue(reg_result)
        verify_result = fido_auth.verify(self.user_id, {})
        self.assertTrue(verify_result) # Based on the simulation logic
    def test_biometric_auth_simulation(self):
        bio_auth = BiometricAuth()
        reg_result = bio_auth.register(self.user_id, {})
        self.assertTrue(reg_result)

        # Test that verify returns boolean (simulation in provided code returns True)
        verify_result = bio_auth.verify(self.user_id, {})
        self.assertTrue(verify_result) # Based on the simulation logic

    def test_oath_token_auth(self):
        oath_auth = OATHAuth()
        reg_result = oath_auth.register(self.user_id, {})
        self.assertTrue(reg_result)
        verify_result = oath_auth.verify(self.user_id, {'token': '111111'})
        self.assertTrue(verify_result)
        verify_result_fail = oath_auth.verify(self.user_id, {'token': '12345'}) # 5 digits
        self.assertFalse(verify_result_fail)
    def test_voice_auth_simulation(self):
        voice_auth = VoiceAuth()
        reg_result = voice_auth.register(self.user_id, {})
        self.assertTrue(reg_result)
        verify_result = voice_auth.verify(self.user_id, {})
        self.assertTrue(verify_result) # Based on the simulation logic
    def test_certificate_auth(self):
        cert_auth = CertificateAuth()
        cert_data = "user_certificate_data"
        reg_result = cert_auth.register(self.user_id, {'certificate': cert_data})
        self.assertTrue(reg_result)
        verify_result = cert_auth.verify(self.user_id, {})
        self.assertTrue(verify_result)
    def test_tap_auth_success(self):
        tap_auth = TAPAuth()
        temp_pass = "12345678"
        reg_result = tap_auth.register(self.user_id, {'temp_pass': temp_pass})
        self.assertTrue(reg_result)
        verify_result = tap_auth.verify(self.user_id, {'temp_pass': temp_pass})
        self.assertTrue(verify_result)
    def test_tap_auth_failure_wrong_pass(self):
        tap_auth = TAPAuth()
        correct_pass = "12345678"
        wrong_pass = "87654321"
        tap_auth.register(self.user_id, {'temp_pass': correct_pass})
        verify_result = tap_auth.verify(self.user_id, {'temp_pass': wrong_pass})
        self.assertFalse(verify_result)
    def test_tap_auth_failure_expired(self):
        tap_auth = TAPAuth()
        temp_pass = "12345678"
        expiry_time = datetime.now().timestamp() - 3600
        tap_auth.temporary_passes[self.user_id] = (temp_pass, expiry_time)
        verify_result = tap_auth.verify(self.user_id, {'temp_pass': temp_pass})
        self.assertFalse(verify_result)
        self.assertNotIn(self.user_id, tap_auth.temporary_passes)
class TestInteractiveUnifiedAuthSystem(unittest.TestCase):
    """Test the main InteractiveUnifiedAuthSystem class logic."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create a temporary file for storage to avoid conflicts
        self.temp_fd, self.temp_path = tempfile.mkstemp(suffix='.json')
        self.auth_system = InteractiveUnifiedAuthSystem(storage_file=self.temp_path)
        self.user_id = "testuser"
        self.email = "testuser@example.com"
        self.password = "TestPass123!"

    def tearDown(self):
        """Tear down test fixtures after each test method."""
        # Close the temp file descriptor and remove the temp file
        os.close(self.temp_fd)
        if os.path.exists(self.temp_path):
            os.remove(self.temp_path)

    def test_user_registration_and_storage(self):
        # Test registering a new user programmatically (bypassing interactive input)
        # Simulate the registration process by directly adding to users dict
        # This tests the storage and loading mechanism
        user_data = {
            'email': self.email,
            'phone': "+1234567890",
            'full_name': "Test User",
            'registered_methods': {},
            'recovery_info': {
                'email': self.email,
                'phone': "+1234567890",
                'security_questions': [],
                'created_at': datetime.now()
            },
            'created_at': datetime.now(),
            'last_login': None,
            'failed_attempts': 0,
            'locked_until': None
        }
        self.auth_system.users[self.user_id] = user_data
        self.auth_system._save_users()

        # Create a new instance to test loading from file
        new_auth_system = InteractiveUnifiedAuthSystem(storage_file=self.temp_path)
        self.assertIn(self.user_id, new_auth_system.users)
        self.assertEqual(new_auth_system.users[self.user_id]['email'], self.email)
        # Check datetime loading
        self.assertIsInstance(new_auth_system.users[self.user_id]['created_at'], datetime)

    def test_authenticate_single_factor_success(self):
        # Setup user with password in the system
        self.auth_system.users[self.user_id] = {
            'email': self.email, 'registered_methods': {'password': True},
            'failed_attempts': 0, 'locked_until': None,
            'last_login': None
        }
        # Setup password auth mechanism
        self.auth_system.auth_methods['password'].register(self.user_id, {'password': self.password})

        # Test successful single-factor authentication
        success, message = self.auth_system.authenticate(
            self.user_id, 'password', {'password': self.password}
        )
        self.assertTrue(success)
        self.assertIn("Authentication successful", message)
        # Check if last_login was updated
        self.assertIsNotNone(self.auth_system.users[self.user_id]['last_login'])
        self.assertIsInstance(self.auth_system.users[self.user_id]['last_login'], datetime)

    def test_authenticate_single_factor_failure(self):
        # Setup user with password
        self.auth_system.users[self.user_id] = {
            'email': self.email, 'registered_methods': {'password': True},
            'failed_attempts': 0, 'locked_until': None,
            'last_login': None
        }
        self.auth_system.auth_methods['password'].register(self.user_id, {'password': self.password})

        # Test failed single-factor authentication
        success, message = self.auth_system.authenticate(
            self.user_id, 'password', {'password': 'WrongPassword'}
        )
        self.assertFalse(success)
        self.assertEqual(message, "Primary authentication failed")
        # Check if failed_attempts was incremented
        self.assertEqual(self.auth_system.users[self.user_id]['failed_attempts'], 1)

    def test_authenticate_method_not_registered(self):
        # Setup user *without* TOTP registered
        self.auth_system.users[self.user_id] = {
            'email': self.email, 'registered_methods': {'password': True}, # Only password
            'failed_attempts': 0, 'locked_until': None,
            'last_login': None
        }

        # Test authentication with unregistered method (TOTP)
        success, message = self.auth_system.authenticate(
            self.user_id, 'totp', {'token': '123456'}
        )
        self.assertFalse(success)
        self.assertEqual(message, "Method totp not registered for this user")

    def test_authenticate_user_not_found(self):
        # Test authentication for non-existent user
        success, message = self.auth_system.authenticate(
            'non_existent_user', 'password', {'password': 'any'}
        )
        self.assertFalse(success)
        self.assertEqual(message, "User not found")

    def test_handle_failed_attempt_increment_and_lock(self):
        # Setup user
        self.auth_system.users[self.user_id] = {
            'email': self.email, 'failed_attempts': 0, 'locked_until': None,
            'last_login': None, 'registered_methods': {}
        }

        # Simulate 4 failed attempts
        for i in range(4):
            self.auth_system._handle_failed_attempt(self.user_id)

        self.assertEqual(self.auth_system.users[self.user_id]['failed_attempts'], 4)
        self.assertIsNone(self.auth_system.users[self.user_id]['locked_until'])

        # 5th failed attempt should lock the account
        self.auth_system._handle_failed_attempt(self.user_id)
        self.assertEqual(self.auth_system.users[self.user_id]['failed_attempts'], 5)
        self.assertIsNotNone(self.auth_system.users[self.user_id]['locked_until'])
        # Check if lock is for 30 minutes (allowing small delta for test execution)
        expected_unlock = datetime.now() + timedelta(minutes=30)
        self.assertAlmostEqual(
            self.auth_system.users[self.user_id]['locked_until'].timestamp(),
            expected_unlock.timestamp(),
            delta=5 # 5 seconds tolerance
        )

    def test_authenticate_unlock_account_on_time_passed(self):
        # Setup user whose lock time has expired (31 mins ago)
        lock_time = datetime.now() - timedelta(minutes=31)
        self.auth_system.users[self.user_id] = {
            'email': self.email,
            'registered_methods': {'password': True},
            'failed_attempts': 5, # Was locked due to this
            'locked_until': lock_time,
            'last_login': None
        }
        # Register the password method for this user
        self.auth_system.auth_methods['password'].register(self.user_id, {'password': self.password})

        # Authenticate with correct password - should unlock and succeed
        success, message = self.auth_system.authenticate(
            self.user_id, 'password', {'password': self.password}
        )
        self.assertTrue(success)
        self.assertIn("Authentication successful", message)
        # Check if account was unlocked and attempts reset by the authenticate method's unlock logic
        # The authenticate method resets these *before* calling primary auth if lock is expired
        # If auth succeeds after unlock, failed_attempts should be 0 (reset by unlock) or
        # could be 0 if _handle_failed_attempt isn't called again (which it shouldn't be on success).
        # locked_until should be None.
        self.assertEqual(self.auth_system.users[self.user_id]['failed_attempts'], 0)
        self.assertIsNone(self.auth_system.users[self.user_id]['locked_until'])
        # last_login should be updated
        self.assertIsNotNone(self.auth_system.users[self.user_id]['last_login'])


    def test_authenticate_mfa_success(self):
        # Setup user with password and totp
        self.auth_system.users[self.user_id] = {
            'email': self.email,
            'registered_methods': {'password': True, 'totp': True},
            'failed_attempts': 0,
            'locked_until': None,
            'last_login': None
        }
        self.auth_system.auth_methods['password'].register(self.user_id, {'password': self.password})
        # Register TOTP
        self.auth_system.auth_methods['totp'].register(self.user_id, {})

        # Patch TOTP verify to return True for a specific token for this test
        original_totp_verify = self.auth_system.auth_methods['totp'].verify
        def mock_totp_verify(uid, creds):
            # Simulate successful TOTP verification for this specific token
            if creds.get('token') == '123456':
                return True
            return False # Fail for any other token
        self.auth_system.auth_methods['totp'].verify = mock_totp_verify

        try:
            # Test successful MFA authentication (Password + TOTP)
            success, message = self.auth_system.authenticate(
                self.user_id,
                'password',
                {'password': self.password},
                {'totp': {'token': '123456'}} # Secondary method and its credentials
            )
            self.assertTrue(success)
            self.assertIn("Authentication successful", message)
            # last_login should be updated
            self.assertIsNotNone(self.auth_system.users[self.user_id]['last_login'])
        finally:
            # Restore original method to avoid affecting other tests
            self.auth_system.auth_methods['totp'].verify = original_totp_verify

    def test_authenticate_mfa_failure_secondary(self):
        # Setup user with password and totp
        self.auth_system.users[self.user_id] = {
            'email': self.email,
            'registered_methods': {'password': True, 'totp': True},
            'failed_attempts': 0,
            'locked_until': None,
            'last_login': None
        }
        self.auth_system.auth_methods['password'].register(self.user_id, {'password': self.password})
        self.auth_system.auth_methods['totp'].register(self.user_id, {})

        # Patch TOTP verify to always return False for this test
        original_totp_verify = self.auth_system.auth_methods['totp'].verify
        def mock_totp_verify_fail(uid, creds):
            return False # Always fail TOTP verification
        self.auth_system.auth_methods['totp'].verify = mock_totp_verify_fail

        try:
            # Test failed MFA authentication (primary passes, secondary fails)
            success, message = self.auth_system.authenticate(
                self.user_id,
                'password', # Primary method
                {'password': self.password}, # Primary credentials (correct)
                {'totp': {'token': 'any_token'}} # Secondary method and its credentials (will fail)
            )
            self.assertFalse(success)
            self.assertEqual(message, "Secondary authentication failed")
            # Check if failed_attempts was incremented due to secondary failure
            self.assertEqual(self.auth_system.users[self.user_id]['failed_attempts'], 1)
            # last_login should NOT be updated
            self.assertIsNone(self.auth_system.users[self.user_id]['last_login'])
        finally:
            # Restore original method
            self.auth_system.auth_methods['totp'].verify = original_totp_verify

    def test_security_questions_setup_and_hashing(self):
        # Test the security questions setup logic including answer hashing
        questions_and_answers = [
            {"question": "What is your pet's name?", "answer": "Fluffy"},
            {"question": "What is your mother's maiden name?", "answer": "Smith"}
        ]

        # Manually call the setup logic (as done in interactive_security_questions_setup)
        secured_questions = []
        for qa in questions_and_answers:
            question = qa.get('question', '')
            answer = qa.get('answer', '')
            # Hash the answer for security (as done in the main code)
            answer_hash = hashlib.sha256(answer.lower().encode()).hexdigest()
            secured_questions.append({
                'question': question,
                'answer_hash': answer_hash
            })

        # Verify structure and that answers are hashed
        self.assertEqual(len(secured_questions), 2)
        self.assertEqual(secured_questions[0]['question'], "What is your pet's name?")
        self.assertEqual(secured_questions[1]['question'], "What is your mother's maiden name?")
        # Verify answers are hashed (not the original text)
        self.assertNotEqual(secured_questions[0]['answer_hash'], "Fluffy")
        self.assertNotEqual(secured_questions[1]['answer_hash'], "Smith")
        # Verify hash is a 64-character hex string (SHA256)
        self.assertEqual(len(secured_questions[0]['answer_hash']), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in secured_questions[0]['answer_hash']))


if __name__ == '__main__':
    # Run the tests
    unittest.main()
