import hashlib
import struct
import hmac

from BaseOTP import BaseOTP


class HOTPOtp(BaseOTP):
    def __init__(self, secret_key: str, code_length: int = 6):
        super().__init__(code_length)
        self.secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key
        self.counter = 0

    def generate_code(self) -> str:
        code = self._generate_otp(self.counter)
        self.counter += 1  # Increment after use
        return code

    def _generate_otp(self, counter: int) -> str:
        counter_bytes = struct.pack(">Q", counter)
        h = hmac.new(self.secret_key, counter_bytes, hashlib.sha1).digest()

        offset = h[-1] & 0x0F
        binary = ((h[offset] & 0x7F) << 24 |
                  (h[offset + 1] << 16) |
                  (h[offset + 2] << 8) |
                  h[offset + 3])
        otp = binary % (10 ** self.code_length)
        return self._format_code(otp)