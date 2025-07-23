if __name__ == "__main__":
    # Use Builder to create accounts
    google_account = (AuthenticatorAccount.Builder()
                      .account_name("Google")
                      .username("user@gmail.com")
                      .type(OTPType.TOTP)
                      .secret("JBSWY3DPEHPK3PXP")  # Base32 secret
                      .build())

    github_account = (AuthenticatorAccount.Builder()
                      .account_name("GitHub")
                      .username("dev_user")
                      .type(OTPType.HOTP)
                      .secret("I3AUI5OJGEZDMMRP")
                      .build())

    # Singleton app instance
    app = AuthenticatorApp()
    app.add_account(google_account)
    app.add_account(github_account)

    # Generate codes
    print("🔐 Authenticator App Demo")
    print("-" * 40)
    for _ in range(2):
        print(f"Google:  {app.get_code('Google')}")
        print(f"GitHub:  {app.get_code('GitHub')}")
        print(f"GitHub:  {app.get_code('GitHub')} (counter incremented)")
        print("Waiting 30s for TOTP change...\n")
        time.sleep(30)  # Wait to see TOTP change