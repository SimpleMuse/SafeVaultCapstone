# SafeVault

A .NET 10 Blazor Web App that registers user accounts and authenticates them against MySQL using short-lived JWT access tokens and rotating refresh tokens.

## Requirements

- .NET 10 SDK
- MySQL

## Set up the database

Run `database.sql` from a MySQL client with an account that can create databases and tables:

```powershell
mysql -u root -p
```

At the MySQL prompt, run `SOURCE database.sql;` from the project directory.

For an existing database created before authentication, add the password and role columns, resolving duplicate usernames before creating the unique index:

```sql
ALTER TABLE Users ADD COLUMN PasswordHash VARCHAR(255) NULL;
ALTER TABLE Users ADD COLUMN Role VARCHAR(20) NOT NULL DEFAULT 'user';
CREATE UNIQUE INDEX UX_Users_Username ON Users (Username);
```

Existing accounts without password hashes cannot sign in. Promote the initial administrator from a trusted database session after creating their account:

```sql
UPDATE Users SET Role = 'admin' WHERE Username = 'YourUsername';
```

If you already migrated the database to the password-and-role schema, do not repeat the `ALTER TABLE` statements. Create the refresh-token store:

```sql
CREATE TABLE IF NOT EXISTS RefreshTokens (
    TokenHash CHAR(64) NOT NULL PRIMARY KEY,
    FamilyId CHAR(32) NOT NULL,
    UserID INT NOT NULL,
    CreatedAtUtc DATETIME(6) NOT NULL,
    ExpiresAtUtc DATETIME(6) NOT NULL,
    RevokedAtUtc DATETIME(6) NULL,
    ReplacedByTokenHash CHAR(64) NULL,
    INDEX IX_RefreshTokens_FamilyId (FamilyId),
    CONSTRAINT FK_RefreshTokens_Users
        FOREIGN KEY (UserID) REFERENCES Users (UserID) ON DELETE CASCADE
);
```

## Configure and run

Set the connection string and a private JWT signing key in the shell. Generate at least 32 random bytes and keep the signing key stable across app restarts. Do not commit credentials:

```powershell
$env:ConnectionStrings__DefaultConnection = "Server=localhost;Database=SafeVault;User ID=root;******"
$jwtBytes = New-Object byte[] 48
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($jwtBytes)
$env:Jwt__SigningKey = [Convert]::ToBase64String($jwtBytes)
$rng.Dispose()
dotnet run --launch-profile https
```

The app requires `Jwt:Issuer`, `Jwt:Audience`, and `Jwt:SigningKey` configuration and fails at startup if the signing key is missing or shorter than 32 bytes. Keep the key in a managed secret store or environment configuration in production.

Both development launch profiles bind HTTPS on port 7196 and HTTP on port 5114; HTTP requests redirect to HTTPS, and any request that remains HTTP is rejected. HSTS is sent on HTTPS responses in every environment. Install and trust the local development certificate if needed:

```powershell
dotnet dev-certs https --trust
```

In deployments, configure an HTTPS listener and set `ASPNETCORE_HTTPS_PORT` for redirects. If TLS terminates at a reverse proxy, configure forwarded headers for that specific trusted proxy before HTTPS redirection and the HTTPS-only guard; do not trust arbitrary forwarded headers.

## Authentication

Create an account with an ASCII alphanumeric username, valid email, and a password between 12 and 128 characters. Passwords are hashed with ASP.NET Core Identity's salted password hasher.

- `POST /account/login` accepts JSON `{ "username": "...", "password": "..." }`, returns a signed five-minute JWT access token, and sets a refresh token in a `Secure`, `HttpOnly`, `SameSite=Strict` cookie.
- `POST /account/refresh` rotates the refresh token and returns a new access token. Refresh tokens are opaque, stored only as SHA-256 hashes, and expire after seven days. Reuse of a rotated token revokes its token family.
- `POST /account/logout` revokes the refresh token.
- `GET /account/me` requires `Authorization: Bearer <access-token>`.
- Admin account data and role changes require the admin role. `/admin` is a public UI shell; sensitive account data is returned only by protected APIs.

Send the rendered `RequestVerificationToken` as the same-named header for login, refresh, and logout requests. The browser stores only the short-lived access token in session storage; the refresh token is inaccessible to JavaScript.
Role changes take effect when the user's current access token expires and a new one is issued (at most five minutes). Signing out revokes future refreshes; already-issued access tokens remain valid until expiry.

## Project structure

```text
Components/Pages/       Razor pages and browser authentication modules
Models/                 Form, account, and token data models
Services/               Database, authorization, and token operations
Utilities/              Shared validation helpers
SafeVault.Tests/         NUnit test project
database.sql            MySQL schema setup
```

Login, refresh, logout, and registration use antiforgery protection. SQL statements are parameterized. Access tokens are self-contained and cannot be revoked before expiry, so keep their lifetime short. Add rate limiting, account recovery, and broader authorization rules before production use.

## Run tests

```powershell
dotnet test .\SafeVault.Tests\SafeVault.Tests.csproj
```

Authentication tests cover valid and invalid passwords, unknown accounts, JWT claims and expiry, refresh-token randomness, and admin-policy access for admins, regular users, and anonymous principals. They run without a MySQL instance.
