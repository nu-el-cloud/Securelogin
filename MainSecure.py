import hashlib
import secrets
import pyotp
import json
import os
class SimpleSecureLogin:
    def __init__(self, data_file="users.json"):
        self.data_file = data_file
        self.users = self.load_users()
    def load_users(self):
        """Load user data from JSON file."""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Error loading user data: {e}. Starting fresh.")
                return {}
        else:
            print(f"Data file '{self.data_file}' not found. A new one will be created upon registration.")
            return {}
    def save_users(self):
        """Save user data to JSON file."""
        try:
            with open(self.data_file, 'w') as f:
                json.dump(self.users, f, indent=4)
            print(f"✅ User data saved to '{self.data_file}'.")
        except IOError as e:
            print(f"❌ Error saving user data: {e}")
    def hash_password(self, password):
        """Store password safely using salt."""
        salt = secrets.token_hex(16)
        pwdhash = hashlib.pbkdf2_hmac('sha256',
                                      password.encode('utf-8'),
                                      salt.encode('utf-8'),
                                      100000)
        return salt + pwdhash.hex()
    def verify_password(self, stored_password, provided_password):
        """Check if the entered password is correct."""
        salt = stored_password[:32]
        pwdhash = hashlib.pbkdf2_hmac('sha256',
                                      provided_password.encode('utf-8'),
                                      salt.encode('utf-8'),
                                      100000)
        return secrets.compare_digest(stored_password[32:], pwdhash.hex())
    def setup_2fa(self, username):
        """Set up an authenticator app (Google or Microsoft)."""
        secret = pyotp.random_base32()
        self.users[username]['2fa_secret'] = secret
        self.save_users()
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            username,
            issuer_name="SimpleSecureApp"
        )
        print(f"Scan this QR code with your authenticator app: {uri}")
        print(f"Or enter this secret key manually: {secret}")
        return secret
    def verify_2fa(self, username, code):
        """Check the 6-digit code from the authenticator app."""
        secret = self.users[username]['2fa_secret']
        totp = pyotp.TOTP(secret)
        return totp.verify(code)
    def register(self, username, password):
        """Sign up a new user."""
        if username in self.users:
            print("❌ Username already taken!")
            return False
        self.users[username] = {
            'password': self.hash_password(password),
            '2fa_secret': None
        }
        self.save_users()
        print(f"✅ User '{username}' registered successfully!")
        print("Now setting up 2-Factor Authentication...")
        self.setup_2fa(username)
        test_code = input("Enter the 6-digit code from your app: ")
        if self.verify_2fa(username, test_code):
            print("✅ 2FA setup successful!")
            self.save_users()
            return True
        else:
            print("❌ 2FA setup failed. Please try again.")
            return False
    def login(self, username, password):
        """Log in a user with password and 2FA."""
        if username not in self.users:
            print("❌ User not found!")
            return False
        if not self.verify_password(self.users[username]['password'], password):
            print("❌ Incorrect password!")
            return False
        code = input("Enter 6-digit code from your authenticator app: ")
        if self.verify_2fa(username, code):
            print(f"✅ Welcome back, {username}! Login successful!")
            return True
        else:
            print("❌ Invalid 2FA code!")
            return False
if __name__ == "__main__":
    auth = SimpleSecureLogin()
    print("🔐 Welcome to the Simple Secure Login System")
    print("1. Register")
    print("2. Login")
    choice = input("Choose an option (1 or 2): ")
    if choice == "1":
        print("\n--- REGISTRATION ---")
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        auth.register(username, password)
    elif choice == "2":
        print("\n--- LOGIN ---")
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        auth.login(username, password)
    else:
        print("Invalid choice. Exiting.")
