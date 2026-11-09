using System.ComponentModel.DataAnnotations;
using System.Data;
using Microsoft.AspNetCore.Identity;
using MySqlConnector;
using SafeVault.Models;

namespace SafeVault.Services;

/// <summary>
/// Persists user accounts and refresh tokens in the configured MySQL database.
/// </summary>
public sealed class UserRepository(
    IConfiguration configuration,
    IPasswordHasher<UserAccount> passwordHasher,
    PasswordCredentialVerifier credentialVerifier)
{
    private readonly string? connectionString =
        configuration.GetConnectionString("DefaultConnection");

    /// <summary>
    /// Creates a user account with a securely hashed password.
    /// </summary>
    public async Task RegisterAsync(
        RegistrationInput input,
        CancellationToken cancellationToken = default)
    {
        Validator.ValidateObject(input, new ValidationContext(input), validateAllProperties: true);

        var user = new UserAccount { Username = input.Username };
        var passwordHash = passwordHasher.HashPassword(user, input.Password);
        var connection = await OpenConnectionAsync(cancellationToken);
        await using (connection)
        await using (var command = new MySqlCommand(
            "INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES (@username, @email, @passwordHash, @role)",
            connection))
        {
            command.Parameters.Add("@username", MySqlDbType.VarChar, 100).Value = input.Username;
            command.Parameters.Add("@email", MySqlDbType.VarChar, 100).Value = input.Email;
            command.Parameters.Add("@passwordHash", MySqlDbType.VarChar, 255).Value = passwordHash;
            command.Parameters.Add("@role", MySqlDbType.VarChar, 20).Value = UserRoles.User;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    /// <summary>
    /// Returns an account only when the submitted password matches its stored password hash.
    /// </summary>
    public async Task<UserAccount?> AuthenticateAsync(
        LoginInput input,
        CancellationToken cancellationToken = default)
    {
        Validator.ValidateObject(input, new ValidationContext(input), validateAllProperties: true);

        var connection = await OpenConnectionAsync(cancellationToken);
        await using (connection)
        await using (var command = CreateAuthenticationCommand(connection, input.Username))
        {
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                credentialVerifier.Verify(null, input.Password, null);
                return null;
            }

            var account = new UserAccount
            {
                UserId = reader.GetInt32(0),
                Username = reader.GetString(1),
                PasswordHash = reader.IsDBNull(2) ? null : reader.GetString(2),
                Role = reader.IsDBNull(3) ? UserRoles.User : reader.GetString(3)
            };
            var verification = credentialVerifier.Verify(account, input.Password, account.PasswordHash);
            if (account.PasswordHash is null || verification == PasswordVerificationResult.Failed)
            {
                return null;
            }

            if (verification == PasswordVerificationResult.SuccessRehashNeeded)
            {
                await reader.DisposeAsync();
                await using var updateCommand = new MySqlCommand(
                    "UPDATE Users SET PasswordHash = @passwordHash WHERE UserID = @userId",
                    connection);
                updateCommand.Parameters.Add("@passwordHash", MySqlDbType.VarChar, 255)
                    .Value = passwordHasher.HashPassword(account, input.Password);
                updateCommand.Parameters.Add("@userId", MySqlDbType.Int32).Value = account.UserId;
                await updateCommand.ExecuteNonQueryAsync(cancellationToken);
            }

            account.PasswordHash = null;
            return account;
        }
    }

    /// <summary>
    /// Lists accounts without exposing password hashes.
    /// </summary>
    public async Task<IReadOnlyList<UserAccount>> GetAccountsAsync(
        CancellationToken cancellationToken = default)
    {
        var connection = await OpenConnectionAsync(cancellationToken);
        await using (connection)
        await using (var command = new MySqlCommand(
            "SELECT UserID, Username, Role FROM Users ORDER BY Username",
            connection))
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            var accounts = new List<UserAccount>();
            while (await reader.ReadAsync(cancellationToken))
            {
                accounts.Add(new UserAccount
                {
                    UserId = reader.GetInt32(0),
                    Username = reader.GetString(1),
                    Role = reader.IsDBNull(2) ? UserRoles.User : reader.GetString(2)
                });
            }

            return accounts;
        }
    }

    /// <summary>
    /// Changes an account role. Callers must authorize the administrator before invoking this method.
    /// </summary>
    public async Task<bool> SetRoleAsync(
        int userId,
        string role,
        CancellationToken cancellationToken = default)
    {
        if (role is not UserRoles.Admin and not UserRoles.User)
        {
            throw new ArgumentOutOfRangeException(nameof(role), "The requested role is not supported.");
        }

        var connection = await OpenConnectionAsync(cancellationToken);
        await using (connection)
        await using (var command = new MySqlCommand(
            "UPDATE Users SET Role = @role WHERE UserID = @userId",
            connection))
        {
            command.Parameters.Add("@role", MySqlDbType.VarChar, 20).Value = role;
            command.Parameters.Add("@userId", MySqlDbType.Int32).Value = userId;
            return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
        }
    }

    /// <summary>
    /// Stores only the hash of an opaque refresh token.
    /// </summary>
    public async Task AddRefreshTokenAsync(
        int userId,
        string tokenHash,
        string familyId,
        DateTime expiresAtUtc,
        CancellationToken cancellationToken = default)
    {
        var connection = await OpenConnectionAsync(cancellationToken);
        await using (connection)
        await using (var command = new MySqlCommand(
            """
            INSERT INTO RefreshTokens (TokenHash, FamilyId, UserID, CreatedAtUtc, ExpiresAtUtc)
            VALUES (@tokenHash, @familyId, @userId, @createdAtUtc, @expiresAtUtc)
            """,
            connection))
        {
            command.Parameters.Add("@tokenHash", MySqlDbType.VarChar, 64).Value = tokenHash;
            command.Parameters.Add("@familyId", MySqlDbType.VarChar, 32).Value = familyId;
            command.Parameters.Add("@userId", MySqlDbType.Int32).Value = userId;
            command.Parameters.Add("@createdAtUtc", MySqlDbType.DateTime).Value = DateTime.UtcNow;
            command.Parameters.Add("@expiresAtUtc", MySqlDbType.DateTime).Value = expiresAtUtc;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    /// <summary>
    /// Rotates a refresh token atomically and invalidates its family on token reuse.
    /// </summary>
    public async Task<UserAccount?> RotateRefreshTokenAsync(
        string currentTokenHash,
        string replacementTokenHash,
        DateTime replacementExpiresAtUtc,
        CancellationToken cancellationToken = default)
    {
        var connection = await OpenConnectionAsync(cancellationToken);
        await using (connection)
        await using (var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted,
            cancellationToken))
        {
            string familyId;
            DateTime expiresAtUtc;
            bool isRevoked;
            UserAccount account;

            await using (var selectCommand = new MySqlCommand(
                """
                SELECT token.FamilyId, token.UserID, token.ExpiresAtUtc, token.RevokedAtUtc,
                       account.Username, account.Role
                FROM RefreshTokens AS token
                INNER JOIN Users AS account ON account.UserID = token.UserID
                WHERE token.TokenHash = @tokenHash
                FOR UPDATE
                """,
                connection,
                transaction))
            {
                selectCommand.Parameters.Add("@tokenHash", MySqlDbType.VarChar, 64).Value = currentTokenHash;
                await using var reader = await selectCommand.ExecuteReaderAsync(cancellationToken);
                if (!await reader.ReadAsync(cancellationToken))
                {
                    return null;
                }

                familyId = reader.GetString(0);
                account = new UserAccount
                {
                    UserId = reader.GetInt32(1),
                    Username = reader.GetString(4),
                    Role = reader.IsDBNull(5) ? UserRoles.User : reader.GetString(5)
                };
                expiresAtUtc = DateTime.SpecifyKind(reader.GetDateTime(2), DateTimeKind.Utc);
                isRevoked = !reader.IsDBNull(3);
            }

            if (isRevoked || expiresAtUtc <= DateTime.UtcNow)
            {
                await RevokeTokenFamilyAsync(connection, transaction, familyId, cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return null;
            }

            await using (var revokeCommand = new MySqlCommand(
                """
                UPDATE RefreshTokens
                SET RevokedAtUtc = @revokedAtUtc, ReplacedByTokenHash = @replacementTokenHash
                WHERE TokenHash = @tokenHash AND RevokedAtUtc IS NULL
                """,
                connection,
                transaction))
            {
                revokeCommand.Parameters.Add("@revokedAtUtc", MySqlDbType.DateTime).Value = DateTime.UtcNow;
                revokeCommand.Parameters.Add("@replacementTokenHash", MySqlDbType.VarChar, 64)
                    .Value = replacementTokenHash;
                revokeCommand.Parameters.Add("@tokenHash", MySqlDbType.VarChar, 64).Value = currentTokenHash;
                await revokeCommand.ExecuteNonQueryAsync(cancellationToken);
            }

            await using (var insertCommand = new MySqlCommand(
                """
                INSERT INTO RefreshTokens (TokenHash, FamilyId, UserID, CreatedAtUtc, ExpiresAtUtc)
                VALUES (@tokenHash, @familyId, @userId, @createdAtUtc, @expiresAtUtc)
                """,
                connection,
                transaction))
            {
                insertCommand.Parameters.Add("@tokenHash", MySqlDbType.VarChar, 64).Value = replacementTokenHash;
                insertCommand.Parameters.Add("@familyId", MySqlDbType.VarChar, 32).Value = familyId;
                insertCommand.Parameters.Add("@userId", MySqlDbType.Int32).Value = account.UserId;
                insertCommand.Parameters.Add("@createdAtUtc", MySqlDbType.DateTime).Value = DateTime.UtcNow;
                insertCommand.Parameters.Add("@expiresAtUtc", MySqlDbType.DateTime).Value = replacementExpiresAtUtc;
                await insertCommand.ExecuteNonQueryAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);
            return account;
        }
    }

    /// <summary>
    /// Revokes an active refresh token.
    /// </summary>
    public async Task RevokeRefreshTokenAsync(
        string tokenHash,
        CancellationToken cancellationToken = default)
    {
        var connection = await OpenConnectionAsync(cancellationToken);
        await using (connection)
        await using (var command = new MySqlCommand(
            "UPDATE RefreshTokens SET RevokedAtUtc = @revokedAtUtc WHERE TokenHash = @tokenHash AND RevokedAtUtc IS NULL",
            connection))
        {
            command.Parameters.Add("@revokedAtUtc", MySqlDbType.DateTime).Value = DateTime.UtcNow;
            command.Parameters.Add("@tokenHash", MySqlDbType.VarChar, 64).Value = tokenHash;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private static async Task RevokeTokenFamilyAsync(
        MySqlConnection connection,
        MySqlTransaction transaction,
        string familyId,
        CancellationToken cancellationToken)
    {
        await using var command = new MySqlCommand(
            "UPDATE RefreshTokens SET RevokedAtUtc = @revokedAtUtc WHERE FamilyId = @familyId AND RevokedAtUtc IS NULL",
            connection,
            transaction);
        command.Parameters.Add("@revokedAtUtc", MySqlDbType.DateTime).Value = DateTime.UtcNow;
        command.Parameters.Add("@familyId", MySqlDbType.VarChar, 32).Value = familyId;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    internal static MySqlCommand CreateAuthenticationCommand(
        MySqlConnection connection,
        string username)
    {
        var command = new MySqlCommand(
            "SELECT UserID, Username, PasswordHash, Role FROM Users WHERE Username = @username LIMIT 1",
            connection);
        command.Parameters.Add("@username", MySqlDbType.VarChar, 100).Value = username;
        return command;
    }

    private async Task<MySqlConnection> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "Set the ConnectionStrings:DefaultConnection configuration value.");
        }

        var connection = new MySqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }
}
