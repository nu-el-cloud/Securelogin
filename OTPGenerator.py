from abc import ABC, abstractmethod

class OTPGenerator(ABC):
    @abstractmethod
    def generate_code(self) -> str:
        pass