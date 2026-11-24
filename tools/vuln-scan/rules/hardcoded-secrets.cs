// Semgrep rule test fixture (run: semgrep --test tools/vuln-scan/rules). Not compiled.
public class Settings
{
    // ruleid: hardcoded-credential-literal
    private const string ApiSecret = "Q7f2Lr9vX1mZ8pK4";

    public void Configure(SmtpClient client, Options options)
    {
        // ruleid: hardcoded-credential-literal
        options.ClientSecret = "aZ3kP9qR7tW2xY5b";

        // ok: hardcoded-credential-literal
        options.Password = "";

        // ok: hardcoded-credential-literal
        var passwordResourceKey = "Account.Fields.Password";

        // ok: hardcoded-credential-literal
        options.ApiKey = _settings.ApiKey;

        // ok: hardcoded-credential-literal
        const string RefreshToken = "refresh_token";

        // ok: hardcoded-credential-literal
        options.Secret = "your-secret-here-123";

        // ruleid: hardcoded-secret-token-format
        var awsKey = "AKIAIOSFODNN7EXAMPLE";

        // ruleid: connection-string-with-password
        var cs = "Server=db.internal;Database=nop;User Id=nop;Password=Pr0dPassw0rd!;";

        // ok: connection-string-with-password
        var cs2 = "Server=db.internal;Database=nop;User Id=nop;Password={0};";
    }
}

public class EmailAccounts
{
    public void Normalize(EmailAccount emailAccount)
    {
        emailAccount.Host = CommonHelper.EnsureNotNull(emailAccount.Host);
        // ok: connection-string-with-password
        emailAccount.Password = CommonHelper.EnsureNotNull(emailAccount.Password);
    }
}
