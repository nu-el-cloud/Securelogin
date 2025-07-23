from OTPGenerator import OTPGenerator


class BaseOTP(OTPGenerator):
    def __init__(self, code_length: int = 6):
        self.code_length = code_length

    def _format_code(self, num: int) -> str:
        return f"{num:0{self.code_length}d}"
