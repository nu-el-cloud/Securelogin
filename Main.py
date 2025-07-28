import hashlib
import secrets
import time
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import getpass

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class InteractiveUnifiedAuthSystem:
    def __init__(self, storage_file="auth_users.json"):
        self.storage_file = storage_file
        self.users = self._load_users()
        self.sessions = {}
        self.recovery_tokens = {}
        self.current_user = None
        self.auth_methods = {
            'password': PasswordAuth(),
            'totp': TOTPAuth(),
            'sms_otp': SMSOTPAuth(),
            'email_otp': EmailOTPAuth(),
            'authenticator_push': AuthenticatorPush(),
            'fido2': FIDO2Auth(),
            'biometric': BiometricAuth(),
            'security_questions': SecurityQuestionsAuth(),
            'oath_token': OATHAuth(),
            'voice_call': VoiceAuth(),
            'certificate': CertificateAuth(),
            'temporary_pass': TAPAuth()
        }
        self.test_results = []

    def _load_users(self) -> Dict:
        """Load users from persistent storage"""
        try:
            if os.path.exists(self.storage_file):
                with open(self.storage_file, 'r') as f:
                    data = json.load(f)
                    # Convert string dates back to datetime objects
                    for user_id, user_data in data.items():
                        if 'created_at' in user_data and user_data['created_at']:
                            user_data['created_at'] = datetime.fromisoformat(user_data['created_at'])
                        if 'last_login' in user_data and user_data['last_login']:
                            user_data['last_login'] = datetime.fromisoformat(user_data['last_login']) if user_data['last_login'] else None
                        if 'locked_until' in user_data and user_data['locked_until']:
                            user_data['locked_until'] = datetime.fromisoformat(user_data['locked_until']) if user_data['locked_until'] else None
                        if 'recovery_info' in user_data and 'created_at' in user_data['recovery_info'] and user_data['recovery_info']['created_at']:
                            user_data['recovery_info']['created_at'] = datetime.fromisoformat(user_data['recovery_info']['created_at'])
                    return data
            else:
                return {}
        except Exception as e:
            print(f"⚠️ Error loading users: {e}")
            return {}

    def _save_users(self):
        """Save users to persistent storage"""
        try:
            # Create a copy of users data for serialization
            data_to_save = {}
            for user_id, user_data in self.users.items():
                data_to_save[user_id] = {}
                for key, value in user_data.items():
                    if isinstance(value, datetime):
                        data_to_save[user_id][key] = value.isoformat() if value else None
                    elif key == 'recovery_info' and isinstance(value, dict):
                        data_to_save[user_id][key] = value.copy()
                        if 'created_at' in data_to_save[user_id][key] and data_to_save[user_id][key]['created_at']:
                            data_to_save[user_id][key]['created_at'] = data_to_save[user_id][key]['created_at'].isoformat()
                    else:
                        data_to_save[user_id][key] = value

            with open(self.storage_file, 'w') as f:
                json.dump(data_to_save, f, indent=2, cls=DateTimeEncoder)
        except Exception as e:
            print(f"⚠️ Error saving users: {e}")

    def interactive_registration(self):
        """Interactive user registration"""
        print("\n" + "="*50)
        print("📝 USER REGISTRATION")
        print("="*50)

        while True:
            user_id = input("Enter username: ").strip()
            if not user_id:
                print("❌ Username cannot be empty!")
                continue
            if user_id in self.users:
                print("❌ Username already exists! Please choose another.")
                continue
            break

        while True:
            email = input("Enter email address: ").strip()
            if not email or '@' not in email:
                print("❌ Please enter a valid email address!")
                continue
            # Check if email already exists
            email_exists = False
            for uid, user_data in self.users.items():
                if user_data.get('email') == email:
                    email_exists = True
                    break
            if email_exists:
                print("❌ Email already registered! Please use another email.")
                continue
            break

        phone = input("Enter phone number (optional): ").strip()
        if not phone:
            phone = None

        full_name = input("Enter full name: ").strip()
        if not full_name:
            full_name = user_id

        # Register the account
        self.users[user_id] = {
            'email': email,
            'phone': phone,
            'full_name': full_name,
            'registered_methods': {},
            'recovery_info': {
                'email': email,
                'phone': phone,
                'security_questions': [],
                'created_at': datetime.now()
            },
            'created_at': datetime.now(),
            'last_login': None,
            'failed_attempts': 0,
            'locked_until': None
        }

        self._save_users()
        print(f"\n✅ Account '{user_id}' registered successfully!")
        print(f"   📧 Recovery email: {email}")
        if phone:
            print(f"   📱 Recovery phone: {phone}")

        self.current_user = user_id

        # Setup security questions
        setup_questions = input("\nSetup security questions for recovery? (yes/no): ").strip().lower()
        if setup_questions in ['yes', 'y']:
            self.interactive_security_questions_setup(user_id)

        # Register authentication methods
        register_methods = input("\nRegister authentication methods now? (yes/no): ").strip().lower()
        if register_methods in ['yes', 'y']:
            self.interactive_auth_method_registration(user_id)

        return user_id

    def interactive_security_questions_setup(self, user_id: str = None):
        """Interactive security questions setup"""
        if not user_id:
            user_id = self.current_user

        if not user_id or user_id not in self.users:
            print("❌ No user logged in!")
            return False

        print("\n" + "="*50)
        print("🔐 SECURITY QUESTIONS SETUP")
        print("="*50)
        print("Set up security questions for account recovery")
        print("(You'll need to remember these answers!)")

        questions_and_answers = []
        sample_questions = [
            "What was your first pet's name?",
            "What city were you born in?",
            "What was your favorite childhood toy?",
            "What is your mother's maiden name?",
            "What was the name of your elementary school?",
            "What was your first car's make and model?"
        ]

        print("\nSample questions (or create your own):")
        for i, q in enumerate(sample_questions[:3], 1):
            print(f"  {i}. {q}")

        for i in range(3):  # Ask for 3 security questions
            print(f"\n--- Question {i+1} ---")
            question = input("Enter your security question: ").strip()
            if not question:
                print("❌ Question cannot be empty!")
                continue

            answer = input("Enter your answer (will be hidden): ").strip()
            if not answer:
                print("❌ Answer cannot be empty!")
                continue

            # Hash the answer for security
            answer_hash = hashlib.sha256(answer.lower().encode()).hexdigest()
            questions_and_answers.append({
                'question': question,
                'answer_hash': answer_hash
            })

        self.users[user_id]['recovery_info']['security_questions'] = questions_and_answers
        self._save_users()
        print("\n✅ Security questions setup successfully!")
        return True

    def interactive_auth_method_registration(self, user_id: str = None):
        """Interactive authentication method registration"""
        if not user_id:
            user_id = self.current_user

        if not user_id or user_id not in self.users:
            print("❌ No user logged in!")
            return False

        print("\n" + "="*50)
        print("🔐 AUTHENTICATION METHOD REGISTRATION")
        print("="*50)
        print("Available authentication methods:")
        available_methods = [
            ('1', 'password', 'Password'),
            ('2', 'totp', 'Authenticator App (TOTP)'),
            ('3', 'sms_otp', 'SMS One-Time Password'),
            ('4', 'email_otp', 'Email One-Time Password'),
            ('5', 'authenticator_push', 'Authenticator Push Notification'),
            ('6', 'fido2', 'Security Key/FIDO2'),
            ('7', 'biometric', 'Biometric (Fingerprint/Face)'),
        ]

        for num, method_key, method_name in available_methods:
            print(f"  {num}. {method_name}")

        print("  0. Finish registration")

        while True:
            choice = input("\nSelect method to register (0-7): ").strip()

            if choice == '0':
                break

            method_map = {num: (key, name) for num, key, name in available_methods}

            if choice not in method_map:
                print("❌ Invalid choice! Please select 0-7.")
                continue

            method_key, method_name = method_map[choice]

            # Get method-specific credentials
            credentials = self._get_method_credentials(method_key)

            if credentials is not None:
                result = self.auth_methods[method_key].register(user_id, credentials)
                if result:
                    if 'registered_methods' not in self.users[user_id]:
                        self.users[user_id]['registered_methods'] = {}
                    self.users[user_id]['registered_methods'][method_key] = True
                    self._save_users()
                    print(f"✅ {method_name} registered successfully!")
                else:
                    print(f"❌ Failed to register {method_name}")

        print("\n✅ Authentication method registration completed!")

    def _get_method_credentials(self, method_key: str) -> dict:
        """Get method-specific credentials from user"""
        credentials = {}

        if method_key == 'password':
            while True:
                password = getpass.getpass("Enter password: ")
                confirm_password = getpass.getpass("Confirm password: ")
                if password != confirm_password:
                    print("❌ Passwords do not match!")
                    continue
                if len(password) < 8:
                    print("❌ Password must be at least 8 characters!")
                    continue
                credentials['password'] = password
                break

        elif method_key in ['sms_otp', 'email_otp', 'authenticator_push', 'fido2', 'biometric']:
            # These methods don't need initial credentials for registration
            pass

        elif method_key == 'totp':
            print("For TOTP, you'll need to scan a QR code with your authenticator app")
            print("In a real implementation, we would generate a QR code here")
            input("Press Enter after setting up your authenticator app...")

        elif method_key == 'certificate':
            cert_path = input("Enter certificate file path: ").strip()
            credentials['certificate'] = cert_path

        elif method_key == 'temporary_pass':
            temp_pass = input("Enter temporary access pass (or leave blank for auto-generated): ").strip()
            if temp_pass:
                credentials['temp_pass'] = temp_pass

        return credentials

    def interactive_login(self):
        """Interactive login process"""
        print("\n" + "="*50)
        print("🔐 USER LOGIN")
        print("="*50)

        # Get username
        user_id = input("Username: ").strip()
        if not user_id:
            print("❌ Username cannot be empty!")
            return False

        if user_id not in self.users:
            print("❌ User not found!")
            create_account = input("Would you like to create an account? (yes/no): ").strip().lower()
            if create_account in ['yes', 'y']:
                self.interactive_registration()
                return True
            else:
                print("Please register for an account first.")
                return False

        # Check if account is locked
        if self.users[user_id].get('locked_until'):
            if datetime.now() < self.users[user_id]['locked_until']:
                print("❌ Account temporarily locked due to failed attempts!")
                return False
            else:
                # Unlock account
                self.users[user_id]['locked_until'] = None
                self.users[user_id]['failed_attempts'] = 0

        # Show available methods for this user
        user_methods = list(self.users[user_id].get('registered_methods', {}).keys())
        if not user_methods:
            print("❌ No authentication methods registered for this account!")
            print("Please register authentication methods first.")
            return False

        print(f"\nAvailable authentication methods for {user_id}:")
        method_names = {
            'password': 'Password',
            'totp': 'Authenticator App (TOTP)',
            'sms_otp': 'SMS OTP',
            'email_otp': 'Email OTP',
            'authenticator_push': 'Push Notification',
            'fido2': 'Security Key',
            'biometric': 'Biometric',
            'certificate': 'Certificate',
            'temporary_pass': 'Temporary Pass'
        }

        for i, method in enumerate(user_methods, 1):
            method_name = method_names.get(method, method)
            print(f"  {i}. {method_name}")

        # Choose primary method
        while True:
            try:
                choice = int(input(f"\nSelect primary authentication method (1-{len(user_methods)}): "))
                if 1 <= choice <= len(user_methods):
                    primary_method = user_methods[choice - 1]
                    break
                else:
                    print(f"❌ Please select 1-{len(user_methods)}")
            except ValueError:
                print("❌ Please enter a number!")

        # Get credentials for primary method
        primary_credentials = self._get_auth_credentials(primary_method)

        # Perform authentication
        success, message = self.authenticate(
            user_id,
            primary_method,
            primary_credentials
        )

        if success:
            print(f"\n🎉 Welcome, {self.users[user_id]['full_name']}!")
            self.current_user = user_id
            return True
        else:
            print(f"\n❌ Login failed: {message}")
            return False

    def _get_auth_credentials(self, method: str) -> dict:
        """Get authentication credentials from user"""
        credentials = {}

        if method == 'password':
            credentials['password'] = getpass.getpass("Password: ")

        elif method == 'totp':
            credentials['token'] = input("Enter 6-digit code from authenticator app: ").strip()

        elif method == 'sms_otp':
            # In real implementation, we would send SMS
            print("SMS with OTP has been sent to your phone...")
            credentials['otp'] = input("Enter 6-digit SMS code: ").strip()

        elif method == 'email_otp':
            # In real implementation, we would send email
            print("Email with OTP has been sent to your email...")
            credentials['otp'] = input("Enter 6-digit email code: ").strip()

        elif method == 'authenticator_push':
            print("Push notification sent to your device...")
            input("Please approve the notification on your device, then press Enter...")
            credentials = {}  # Approval handled by method

        elif method == 'fido2':
            print("Please touch your security key...")
            input("Press Enter after touching your security key...")
            credentials = {}

        elif method == 'biometric':
            print("Please use your fingerprint/face recognition...")
            input("Press Enter after biometric verification...")
            credentials = {}

        elif method == 'certificate':
            # In real implementation, certificate would be automatically used
            credentials = {}

        elif method == 'temporary_pass':
            credentials['temp_pass'] = input("Enter temporary access pass: ").strip()

        return credentials

    def authenticate(self, user_id: str, primary_method: str,
                     primary_credentials: dict,
                     secondary_methods: Dict[str, dict] = None,
                     risk_level: str = 'medium') -> Tuple[bool, str]:
        """Main authentication function"""
        if user_id not in self.users:
            return False, "User not found"

        # Check if account is locked
        if self.users[user_id].get('locked_until'):
            if datetime.now() < self.users[user_id]['locked_until']:
                return False, "Account temporarily locked due to failed attempts"
            else:
                # Unlock account
                self.users[user_id]['locked_until'] = None
                self.users[user_id]['failed_attempts'] = 0

        # Check if user has this method registered
        if primary_method not in self.users[user_id].get('registered_methods', {}):
            return False, f"Method {primary_method} not registered for this user"

        # Primary authentication
        primary_result = self.auth_methods[primary_method].verify(
            user_id, primary_credentials
        )

        if not primary_result:
            self._handle_failed_attempt(user_id)
            return False, "Primary authentication failed"

        # Secondary authentication based on risk level
        if secondary_methods or risk_level in ['high', 'critical']:
            secondary_results = []
            methods_to_use = secondary_methods or self._get_required_secondary_methods(
                risk_level, user_id
            )

            for method, credentials in methods_to_use.items():
                if method in self.users[user_id].get('registered_methods', {}):
                    result = self.auth_methods[method].verify(user_id, credentials)
                    secondary_results.append(result)

            if not all(secondary_results):
                self._handle_failed_attempt(user_id)
                return False, "Secondary authentication failed"

        # Successful authentication
        self.users[user_id]['last_login'] = datetime.now()
        self.users[user_id]['failed_attempts'] = 0  # Reset failed attempts
        self._save_users()

        # Create session
        session_id = self._create_session(user_id, [primary_method] +
                                          (list(secondary_methods.keys()) if secondary_methods else []))

        return True, f"Authentication successful! Session ID: {session_id}"

    def _handle_failed_attempt(self, user_id: str):
        """Handle failed authentication attempts"""
        if user_id in self.users:
            self.users[user_id]['failed_attempts'] += 1
            if self.users[user_id]['failed_attempts'] >= 5:
                # Lock account for 30 minutes
                self.users[user_id]['locked_until'] = datetime.now() + timedelta(minutes=30)
            self._save_users()

    def _get_required_secondary_methods(self, risk_level: str, user_id: str) -> Dict:
        """Determine required secondary methods based on risk level"""
        user_methods = self.users[user_id].get('registered_methods', {})
        available_methods = [m for m in user_methods.keys() if m != 'password']

        if risk_level == 'low':
            return {}
        elif risk_level == 'medium':
            return {available_methods[0]: {}} if available_methods else {}
        elif risk_level in ['high', 'critical']:
            return {method: {} for method in available_methods[:2]} if len(available_methods) >= 2 else {}

        return {}

    def _create_session(self, user_id: str, methods_used: List[str]) -> str:
        """Create a secure session"""
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = {
            'user_id': user_id,
            'methods_used': methods_used,
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(hours=1),
            'active': True
        }
        return session_id

    def interactive_account_recovery(self):
        """Interactive account recovery process"""
        print("\n" + "="*50)
        print("🔄 ACCOUNT RECOVERY")
        print("="*50)
        print("Lost access to your account? Let's recover it!")

        identifier = input("Enter your username or email: ").strip()
        if not identifier:
            print("❌ Identifier cannot be empty!")
            return False

        # Find user
        user_id = None
        for uid, user_data in self.users.items():
            if (uid == identifier or
                    user_data.get('email') == identifier or
                    user_data.get('recovery_info', {}).get('email') == identifier):
                user_id = uid
                break

        if not user_id:
            print("❌ No account found with that identifier!")
            create_new = input("Would you like to create a new account? (yes/no): ").strip().lower()
            if create_new in ['yes', 'y']:
                self.interactive_registration()
            return False

        print(f"✅ Account found: {self.users[user_id]['full_name']}")

        # Verify security questions
        recovery_questions = self.users[user_id]['recovery_info'].get('security_questions', [])
        if not recovery_questions:
            print("❌ No security questions set up for this account!")
            print("Please contact system administrator.")
            return False

        print("\nAnswer your security questions to verify identity:")
        correct_answers = 0

        for i, qa in enumerate(recovery_questions, 1):
            print(f"\nQuestion {i}: {qa['question']}")
            answer = input("Your answer: ").strip()
            answer_hash = hashlib.sha256(answer.lower().encode()).hexdigest()

            if answer_hash == qa['answer_hash']:
                correct_answers += 1
                print("✅ Correct!")
            else:
                print("❌ Incorrect!")

        if correct_answers < 2:  # Need at least 2 correct answers
            print("\n❌ Unable to verify identity. Try again later.")
            return False

        print("\n✅ Identity verified successfully!")

        # Reset authentication methods
        print("\nFor security, all authentication methods will be cleared.")
        print("You'll need to set up new methods after recovery.")

        confirm = input("Continue with account recovery? (yes/no): ").strip().lower()
        if confirm not in ['yes', 'y']:
            print("Recovery cancelled.")
            return False

        # Clear authentication methods
        self.users[user_id]['registered_methods'] = {}

        # Set new password
        print("\n🔐 Set a new password:")
        while True:
            new_password = getpass.getpass("New password: ")
            confirm_password = getpass.getpass("Confirm new password: ")
            if new_password != confirm_password:
                print("❌ Passwords do not match!")
                continue
            if len(new_password) < 8:
                print("❌ Password must be at least 8 characters!")
                continue
            break

        # Register new password
        password_auth = PasswordAuth()
        password_auth.register(user_id, {'password': new_password})
        self.users[user_id]['registered_methods']['password'] = True

        self._save_users()
        print("\n✅ Account recovered successfully!")
        print("You can now log in with your new password and set up additional authentication methods.")

        # Offer to login immediately
        login_now = input("\nWould you like to login now? (yes/no): ").strip().lower()
        if login_now in ['yes', 'y']:
            self.current_user = user_id
            print(f"\n🎉 Welcome back, {self.users[user_id]['full_name']}!")
            return True

        return True

    def show_user_dashboard(self, user_id: str = None):
        """Show user dashboard with account information"""
        if not user_id:
            user_id = self.current_user

        if not user_id or user_id not in self.users:
            print("❌ No user logged in!")
            return

        user_data = self.users[user_id]
        print("\n" + "="*50)
        print("👤 USER DASHBOARD")
        print("="*50)
        print(f"Username: {user_id}")
        print(f"Full Name: {user_data['full_name']}")
        print(f"Email: {user_data['email']}")
        if user_data['phone']:
            print(f"Phone: {user_data['phone']}")
        print(f"Account Created: {user_data['created_at'].strftime('%Y-%m-%d %H:%M:%S')}")
        if user_data['last_login']:
            print(f"Last Login: {user_data['last_login'].strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            print("Last Login: Never")

        print(f"\n🔐 Registered Authentication Methods:")
        user_methods = user_data.get('registered_methods', {})
        method_names = {
            'password': 'Password',
            'totp': 'Authenticator App (TOTP)',
            'sms_otp': 'SMS One-Time Password',
            'email_otp': 'Email One-Time Password',
            'authenticator_push': 'Push Notification',
            'fido2': 'Security Key/FIDO2',
            'biometric': 'Biometric',
            'certificate': 'Certificate',
            'temporary_pass': 'Temporary Access Pass'
        }

        if user_methods:
            for method_key in user_methods:
                method_name = method_names.get(method_key, method_key)
                print(f"  ✅ {method_name}")
        else:
            print("  ❌ No authentication methods registered")

        print(f"\n🛡️ Account Security:")
        recovery_info = user_data.get('recovery_info', {})
        security_questions = recovery_info.get('security_questions', [])
        print(f"  Security Questions: {len(security_questions)}/3 set up")
        print(f"  Failed Login Attempts: {user_data.get('failed_attempts', 0)}")
        if user_data.get('locked_until'):
            if datetime.now() < user_data['locked_until']:
                print(f"  Account Locked Until: {user_data['locked_until'].strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                print("  Account Status: Unlocked")
        else:
            print("  Account Status: Unlocked")

    def logout(self):
        """Logout current user"""
        if self.current_user:
            print(f"👋 Goodbye, {self.users[self.current_user]['full_name']}!")
            self.current_user = None
        else:
            print("No user currently logged in.")

# Individual Authentication Method Classes (same as before)
class BaseAuthMethod:
    def register(self, user_id: str, credentials: dict) -> bool:
        raise NotImplementedError

    def verify(self, user_id: str, credentials: dict) -> bool:
        raise NotImplementedError

class PasswordAuth(BaseAuthMethod):
    def __init__(self):
        self.passwords = {}

    def register(self, user_id: str, credentials: dict) -> bool:
        password = credentials.get('password')
        if not password:
            return False

        salt = secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256',
                                       password.encode('utf-8'),
                                       salt.encode('utf-8'),
                                       100000)
        self.passwords[user_id] = {
            'hash': pwd_hash.hex(),
            'salt': salt
        }
        return True

    def verify(self, user_id: str, credentials: dict) -> bool:
        password = credentials.get('password')
        if not password or user_id not in self.passwords:
            return False

        stored = self.passwords[user_id]
        pwd_hash = hashlib.pbkdf2_hmac('sha256',
                                       password.encode('utf-8'),
                                       stored['salt'].encode('utf-8'),
                                       100000)
        return pwd_hash.hex() == stored['hash']

class TOTPAuth(BaseAuthMethod):
    def __init__(self):
        self.secrets = {}

    def register(self, user_id: str, credentials: dict) -> bool:
        self.secrets[user_id] = secrets.token_hex(20)
        return True

    def verify(self, user_id: str, credentials: dict) -> bool:
        token = credentials.get('token')
        if not token or user_id not in self.secrets:
            return False

        expected_token = self._generate_totp(self.secrets[user_id])
        return str(token) == str(expected_token)

    def _generate_totp(self, secret: str) -> str:
        import time
        counter = int(time.time()) // 30
        return str(counter % 1000000).zfill(6)

class SMSOTPAuth(BaseAuthMethod):
    def __init__(self):
        self.otp_storage = {}

    def register(self, user_id: str, credentials: dict) -> bool:
        return True

    def verify(self, user_id: str, credentials: dict) -> bool:
        otp = credentials.get('otp')
        if not otp or user_id not in self.otp_storage:
            return False

        stored_otp, expiry = self.otp_storage[user_id]
        if time.time() > expiry:
            del self.otp_storage[user_id]
            return False

        result = str(otp) == str(stored_otp)
        if result:
            del self.otp_storage[user_id]
        return result

class EmailOTPAuth(SMSOTPAuth):
    pass

class AuthenticatorPush(BaseAuthMethod):
    def register(self, user_id: str, credentials: dict) -> bool:
        return True

    def verify(self, user_id: str, credentials: dict) -> bool:
        # Simulate user approval
        import random
        return random.choice([True, True, False])  # 66% success rate

class FIDO2Auth(BaseAuthMethod):
    def register(self, user_id: str, credentials: dict) -> bool:
        return True

    def verify(self, user_id: str, credentials: dict) -> bool:
        return True  # Simulate successful verification

class BiometricAuth(BaseAuthMethod):
    def register(self, user_id: str, credentials: dict) -> bool:
        return True

    def verify(self, user_id: str, credentials: dict) -> bool:
        return True  # Simulate successful verification

class SecurityQuestionsAuth(BaseAuthMethod):
    def __init__(self):
        self.questions = {}

    def register(self, user_id: str, credentials: dict) -> bool:
        questions = credentials.get('questions', [])
        self.questions[user_id] = questions
        return True

    def verify(self, user_id: str, credentials: dict) -> bool:
        answers = credentials.get('answers', [])
        if user_id not in self.questions:
            return False
        return len(answers) >= 2

class OATHAuth(BaseAuthMethod):
    def register(self, user_id: str, credentials: dict) -> bool:
        return True

    def verify(self, user_id: str, credentials: dict) -> bool:
        token = credentials.get('token')
        return token and len(str(token)) == 6

class VoiceAuth(BaseAuthMethod):
    def register(self, user_id: str, credentials: dict) -> bool:
        return True

    def verify(self, user_id: str, credentials: dict) -> bool:
        return True

class CertificateAuth(BaseAuthMethod):
    def register(self, user_id: str, credentials: dict) -> bool:
        certificate = credentials.get('certificate')
        return certificate is not None

    def verify(self, user_id: str, credentials: dict) -> bool:
        return True

class TAPAuth(BaseAuthMethod):
    def __init__(self):
        self.temporary_passes = {}

    def register(self, user_id: str, credentials: dict) -> bool:
        temp_pass = credentials.get('temp_pass') or str(secrets.randbelow(99999999))
        expiry = credentials.get('expiry', time.time() + 3600)
        self.temporary_passes[user_id] = (temp_pass, expiry)
        return True

    def verify(self, user_id: str, credentials: dict) -> bool:
        temp_pass = credentials.get('temp_pass')
        if not temp_pass or user_id not in self.temporary_passes:
            return False

        stored_pass, expiry = self.temporary_passes[user_id]
        if time.time() > expiry:
            del self.temporary_passes[user_id]
            return False

        return str(temp_pass) == str(stored_pass)

# 🎯 MAIN INTERACTIVE APPLICATION
def main():
    print("🚀 WELCOME TO THE UNIFIED AUTHENTICATION SYSTEM")
    print("="*60)

    auth_system = InteractiveUnifiedAuthSystem("interactive_users.json")

    while True:
        print("\n" + "="*40)
        print("🏠 MAIN MENU")
        print("="*40)

        if auth_system.current_user:
            print(f"👤 Logged in as: {auth_system.current_user}")
            menu_options = [
                ("1", "User Dashboard"),
                ("2", "Register New Authentication Methods"),
                ("3", "Logout"),
                ("4", "Exit")
            ]
        else:
            menu_options = [
                ("1", "Register New Account"),
                ("2", "Login"),
                ("3", "Account Recovery"),
                ("4", "Exit")
            ]

        for num, desc in menu_options:
            print(f"  {num}. {desc}")

        choice = input("\nSelect an option: ").strip()

        if not auth_system.current_user:
            # Not logged in
            if choice == '1':
                # Register new account
                auth_system.interactive_registration()

            elif choice == '2':
                # Login
                auth_system.interactive_login()

            elif choice == '3':
                # Account recovery
                auth_system.interactive_account_recovery()

            elif choice == '4':
                # Exit
                print("👋 Thank you for using the Unified Authentication System!")
                break

            else:
                print("❌ Invalid option! Please try again.")

        else:
            # Logged in
            if choice == '1':
                # User dashboard
                auth_system.show_user_dashboard()

            elif choice == '2':
                # Register new authentication methods
                auth_system.interactive_auth_method_registration()

            elif choice == '3':
                # Logout
                auth_system.logout()

            elif choice == '4':
                # Exit
                auth_system.logout()
                print("👋 Thank you for using the Unified Authentication System!")
                break

            else:
                print("❌ Invalid option! Please try again.")

if __name__ == "__main__":
    main()