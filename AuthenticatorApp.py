class AuthenticatorApp:
    _instance = None
    _accounts: dict

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._accounts = {}
        return cls._instance

    def add_account(self, account: AuthenticatorAccount):
        self._accounts[account.account_name] = account

    def get_code(self, account_name: str) -> str:
        account = self._accounts.get(account_name)
        return account.current_code() if account else "Account not found"

    def list_accounts(self) -> list:
        return list(self._accounts.keys())