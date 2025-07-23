class OTPFactory:
    @staticmethod
    def create_otp(otp_type: OTPType, secret_key: str, code_length: int = 6) -> OTPGenerator:
        if otp_type == OTPType.TOTP:
            return TOTPOtp(secret_key, code_length)
        elif otp_type == OTPType.HOTP:
            return HOTPOtp(secret_key, code_length)
        else:
            raise ValueError(f"Unsupported OTP type: {otp_type}")