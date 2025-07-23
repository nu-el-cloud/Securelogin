from enum import Enum

class OTPType(Enum):
    TOTP = "totp"
    HOTP = "hotp"