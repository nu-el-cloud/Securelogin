import hashlib
import secrets
import pyotp
import json
import os

class SimpleSecureLogin:
    # Constructor method that initializes the SimpleSecureLogin class
    # The 'self' parameter refers to the instance of the class and allows access to its attributes and methods
    # data_file: optional parameter specifying the JSON file to store user data (defaults to "users.json")
    def __init__(self, data_file="users.json"): # the self This allows you to access the attributes and methods of the class in Python
        # Store the data file path as an instance attribute for later use
        self.data_file = data_file
        # Load existing users from the json file into  the memory
        # If the file doesn't exist or is corrupted, this will return an empty dictionary
        self.users = self.load_users()

    def load_users(self):
        # This method loads user data from a JSON file into memory
        # It handles various error cases and returns an empty dictionary if loading fails

        if os.path.exists(self.data_file): # Check if the data file exists in the operating system path
            try:
                # Try to open and load user data from the JSON file
                # 'r' mode opens the file in read-only mode
                with open(self.data_file, 'r') as f:
                    # json.load() parses the JSON file and converts it to a Python dictionary
                    return json.load(f)

            except (json.JSONDecodeError, IOError) as e:
                # Handle two types of errors:
                # json.JSONDecodeError: occurs when the file exists but contains invalid JSON format
                # IOError: occurs when there are file system issues (permissions, disk full, etc.)
                # If there's an error reading or parsing the file, print an error and start fresh
                print(f"Error loading user data: {e}. Starting fresh.")
                # Return an empty dictionary so the program can continue without crashing
                return {}
        else:
            # If the file doesn't exist (first time running the program or file was deleted)
            # notify the user and return an empty dictionary
            print(f"Data file '{self.data_file}' not found. A new one will be created upon registration.")
            # Return empty dictionary to initialize with no users
            return {}

    def save_users(self):
        # This method saves the current user data from memory to a JSON file
        # It writes all user information (passwords, 2FA secrets, etc.) to persistent storage
        try:
            # Attempt to open the data file in write mode
            # 'w' mode opens the file for writing (overwrites existing content or creates new file)
            with open(self.data_file, 'w') as f:
                # json.dump() converts the Python dictionary to JSON format and writes it to the file
                # self.users contains all user data currently in memory
                # indent=4 formats the JSON with 4-space indentation for human readability
                json.dump(self.users, f, indent=4)
                # Confirm successful save operation to the user
            print(f"✅ User data saved to '{self.data_file}'.")
        except:
            # Handle errors that may occur during file writing operations
            # Common errors: insufficient permissions, disk full, file locked by another process
            print(f"❌ Error saving user data: ")

    def hash_password(self, password):
        # This method securely hashes a password using salt and PBKDF2 for storage
        # It prevents rainbow table attacks and makes password cracking much harder

        # Generate a cryptographically secure random salt of 16 bytes (32 hex characters)
        # The salt ensures that identical passwords will have different hashes
        salt = secrets.token_hex(16)
        # Hash the password using PBKDF2 (Password-Based Key Derivation Function 2) with SHA256
        # PBKDF2 applies the hash function multiple times to make brute-force attacks slower
        pwdhash = hashlib.pbkdf2_hmac('sha256',   # Hash algorithm: SHA-256 cryptographic hash function
                                      password.encode('utf-8'), # Convert password string to bytes for hashing
                                      salt.encode('utf-8'),   # Convert salt string to bytes for hashing
                                      100000) # Number of iterations: 100,000 rounds to slow down attacks


        # Combine the salt and hashed password into a single string for storage
        # The salt is stored with the hash so it can be used for verification later
        # .hex() converts the binary hash bytes to a readable hexadecimal string
        return salt + pwdhash.hex()

    def verify_password(self, stored_password, provided_password):
        # This method verifies if a provided password matches the stored hashed password
        # It extracts the salt from the stored hash and re-computes the hash to compare securely

        # Extract the salt from the stored password (first 32 characters)
        # The salt was stored as the first 32 hexadecimal characters when the password was hashed
        # Since each byte is represented as 2 hex characters, 16 bytes of salt = 32 hex characters

        salt = stored_password[:32]
        # Hash the provided password using the same salt and parameters as during registration
        # This recreates the hash that should match the stored hash if the password is correct
        pwdhash = hashlib.pbkdf2_hmac('sha256',  # Same hash algorithm used during hashing
                                      provided_password.encode('utf-8'), # Convert the entered password to bytes
                                      salt.encode('utf-8'), # Use the extracted salt (converted to bytes)
                                      100000)   # Same number of iterations used during hashing
        # Extract the stored hash portion (everything after the first 32 characters)
        # This is the actual password hash without the salt that was prepended to it
        # Convert the newly computed hash to hexadecimal string for comparison
        # Compare the stored hash with the newly computed hash using constant-time comparison
        # secrets.compare_digest() prevents timing attacks that could leak information about the hash
        return secrets.compare_digest(stored_password[32:], pwdhash.hex())

    def setup_2fa(self, username):
        # This method sets up Two-Factor Authentication (2FA) for a user using TOTP (Time-based One-Time Password)
        # It generates a secret key, stores it, and provides instructions for authenticator app setup

        # Generate a cryptographically secure random secret key in base32 format
        # Base32 encoding is required by TOTP standards and is compatible with authenticator apps like Google Authenticator
        # This secret key will be used to generate time-based 6-digit codes every 30 seconds
        secret = pyotp.random_base32()
        # Store the generated 2FA secret in the user's record in the users dictionary
        # This associates the secret key with the specific username for future authentication
        # The secret is stored so it can be used later to verify the 6-digit codes entered by the user
        self.users[username]['2fa_secret'] = secret
        # Save the updated user data (including the new 2FA secret) to the JSON file
        # This ensures the secret is persisted to disk and available after the program restarts
        self.save_users()

        # Create a provisioning URI that contains all information needed by authenticator apps
        # This URI can be converted to a QR code or entered manually in apps like Google Authenticator
        # pyotp.totp.TOTP(secret) creates a TOTP object using the generated secret key
        # provisioning_uri() generates a standardized URI containing the secret, username, and issuer
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            username,   # The account name that will appear in the authenticator app
            issuer_name="SimpleSecureApp"    # The application name that will appear in the authenticator app
        )
        print(f"Scan this QR code with your authenticator app: {uri}")
        print(f"Or enter this secret key manually: {secret}")
        return secret

    def verify_2fa(self, username, code):
        # This method verifies the 6-digit 2FA code entered by the user during login
        # It checks if the provided code matches the current time-based token generated from the user's secret

        # Retrieve the stored 2FA secret for the user from the users dictionary
        # This secret was generated during 2FA setup and is unique to each user
        # It's used to generate the same time-based codes that the authenticator app generates
        secret = self.users[username]['2fa_secret']

        # Create a TOTP (Time-based One-Time Password) object using the user's stored secret
        # This object can generate and verify time-based 6-digit codes using the TOTP algorithm
        # The TOTP object uses the same algorithm as Google Authenticator and other authenticator apps
        totp = pyotp.TOTP(secret)
        # Verify the provided 6-digit code against the current time-based token
        # totp.verify() generates the expected code for the current time window and compares it with the user's input
        # It typically allows for a small time window (usually ±1 time step) to account for clock differences
        # Returns True if the code is valid and recent, False otherwise
        return totp.verify(code)

    def register(self, username, password):
        # This method registers a new user by creating an account with a hashed password and setting up 2FA
        # It performs validation, stores user data, and initiates the 2FA setup process

        # Check if the username already exists in the users dictionary to prevent duplicate accounts
        # This ensures each username is unique and avoids overwriting existing user data
        if username in self.users:
            print("❌ Username already taken!")
            return False
        # Validate password requirements
        if len(password) < 8:
            print("❌ Password must be at least 8 characters long!")
            return False
        if username in password:
            print("❌ Password cannot contain your username!")
            return False

        # Add the new user to the users dictionary with their account information
        # The user's data is stored as a dictionary containing:
        # - 'password': the securely hashed password (using PBKDF2 with salt)
        # - '2fa_secret': initialized as None (will be set during 2FA setup)
        # self.hash_password() securely hashes the provided password before storage
        self.users[username] = {
            'password': self.hash_password(password),
            '2fa_secret': None
        }
        # Save the updated user list
        self.save_users()
        print(f"✅ User '{username}' registered successfully!")
        print("Now setting up 2-Factor Authentication...")
        # Set up 2FA for the new user
        self.setup_2fa(username)
        # Prompt the user to enter a 2FA code to confirm setup
        test_code = input("Enter the 6-digit code from your app: ")
        if self.verify_2fa(username, test_code):
            print("✅ 2FA setup successful!")
            self.save_users()
            return True
        else:
            print("❌ 2FA setup failed. Please try again.")
            return False

    def login(self, username, password):
        # This method authenticates a user by verifying their username, password, and 2FA code
        # It performs a three-step verification process for secure login


        # Check if the username exists in the users database to ensure the account is registered
        # This prevents login attempts with non-existent usernames
        if username not in self.users:
            print("❌ User not found!")
            return False

        # Verify the entered password against the stored hash using secure comparison
        # self.verify_password() hashes the provided password with the stored salt and compares the results
        # This ensures the plaintext password is never stored and comparison is timing-attack resistant
        if not self.verify_password(self.users[username]['password'], password):
            print("❌ Incorrect password!")
            return False

        # Prompt the user to enter the 6-digit code from their authenticator app for 2FA verification
        # This adds an additional security layer beyond just username and password
        # The code is time-based and changes every 30 seconds in the authenticator app
        code = input("Enter 6-digit code from your authenticator app: ")


        # Validate the 2FA code by comparing it with the expected code generated from the user's secret
        # self.verify_2fa() uses the stored secret to generate the expected TOTP code and verify the user's input
        # This ensures the user has access to their authenticator device
        if self.verify_2fa(username, code):
            print(f"✅ Welcome back, {username}! Login successful!")
            return True
        else:
            print("❌ Invalid 2FA code!")
            return False

if __name__ == "__main__":
    # This conditional ensures the following code only runs when the script is executed directly
    # It prevents this code from running when the file is imported as a module in another script
    # This is a Python best practice for making files both importable and executable

    # Create an instance of the SimpleSecureLogin class to manage user authentication
    # This initializes the system and loads any existing user data from the JSON file
    auth = SimpleSecureLogin()
    # Display welcome message and menu options to the user
    # The emoji adds visual appeal and indicates security focus
    print("🔐 Welcome to the Simple Secure Login System")
    print("1. Register")
    print("2. Login")
    # Get user input for registration or login choice
    # The input function waits for the user to type and press Enter
    choice = input("Choose an option (1 or 2): ")
    # Process the user's menu choice using conditional logic
    if choice == "1":
        print("\n--- REGISTRATION ---")
        username = input("Enter your username: ")

        password = input("Enter your password: ")
        # Call the register method
        auth.register(username, password)
    elif choice == "2":
        print("\n--- LOGIN ---")
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        # Call the login method
        auth.login(username, password)
    else:
        print("Invalid choice. Exiting.")