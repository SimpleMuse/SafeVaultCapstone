using Microsoft.AspNetCore.Identity;
using SafeVault.Models;

namespace SafeVault.Services;

/// <summary>
/// Verifies a submitted password against a stored hash without revealing whether an account exists.
/// </summary>
public sealed class PasswordCredentialVerifier(IPasswordHasher<UserAccount> passwordHasher)
{
    private readonly string dummyPasswordHash =
        passwordHasher.HashPassword(new UserAccount(), "SafeVault dummy password");

    /// <summary>
    /// Verifies credentials. Missing accounts and hashes perform a dummy hash verification and fail.
    /// </summary>
    public PasswordVerificationResult Verify(
        UserAccount? account,
        string password,
        string? storedPasswordHash)
    {
        var targetAccount = account ?? new UserAccount();
        var hash = storedPasswordHash ?? dummyPasswordHash;
        var result = passwordHasher.VerifyHashedPassword(targetAccount, hash, password);

        return account is null || storedPasswordHash is null
            ? PasswordVerificationResult.Failed
            : result;
    }
}
