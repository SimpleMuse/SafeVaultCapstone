namespace SafeVault.Models;

/// <summary>
/// Represents an account returned after its credentials have been verified.
/// </summary>
public sealed class UserAccount
{
    /// <summary>Gets or sets the database user identifier.</summary>
    public int UserId { get; set; }

    /// <summary>Gets or sets the account username.</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>Gets or sets the account role.</summary>
    public string Role { get; set; } = UserRoles.User;

    internal string? PasswordHash { get; set; }
}
