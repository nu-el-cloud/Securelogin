class AuthenticatorAccount:
    def __init__(self, account_name: str, username: str, otp_generator: OTPGenerator):
        self.account_name = account_name
        self.username = username
        self._otp_generator = otp_generator  # Composition

    def current_code(self) -> str:
        return self._otp_generator.generate_code()

    # Builder Pattern
    class Builder:
        def __init__(self):
            self._account_name = None
            self._username = None
            self._otp_type = None
            self._secret_key = None
            self._code_length = 6

        def account_name(self, name: str):
            self._account_name = name
            return self

        def username(self, username: str):
            self._username = username
            return self

        def type(self, otp_type: OTPType):
            self._otp_type = otp_type
            return self

        def secret(self, secret_key: str):
            self._secret_key = secret_key
            return self

        def code_length(self, length: int):
            self._code_length = length
            return self

        def build(self) -> 'AuthenticatorAccount':
            if not self._account_name or not self._secret_key or not self._otp_type:
                raise ValueError("Account name, secret, and type are required.")
            otp_gen = OTPFactory.create_otp(self._otp_type, self._secret_key, self._code_length)
            return AuthenticatorAccount(self._account_name, self._username, otp_gen)