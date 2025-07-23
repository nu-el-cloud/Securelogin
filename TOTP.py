import time
import hashlib
import hmac
import struct

from BaseOTP import BaseOTP


class TOTPOtp(BaseOTP):
    def __init__(self, secret_key: str, code_length: int = 6, time_step: int = 30):
        super().__init__(code_length)
        self.secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key
        self.time_step = time_step

    def generate_code(self) -> str:
        # Current Unix time
        counter = int(time.time()) // self.time_step
        return self._generate_otp(counter)

    def _generate_otp(self, counter: int) -> str:
        # HMAC-SHA1
        counter_bytes = struct.pack(">Q", counter)
        h = hmac.new(self.secret_key, counter_bytes, hashlib.sha1).digest()

        # Dynamic truncation
        offset = h[-1] & 0x0F
        binary = ((h[offset] & 0x7F) << 24 |
                  (h[offset + 1] << 16) |
                  (h[offset + 2] << 8) |
                  h[offset + 3])
        otp = binary % (10 ** self.code_length)
        return self._format_code(otp)