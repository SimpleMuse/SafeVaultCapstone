namespace SafeVault.Models;

/// <summary>
/// Safe browser-visible account identity returned by an authenticated API.
/// </summary>
public sealed class UserSession
{
    public string Username { get; set; } = string.Empty;
    public string Role { get; set; } = UserRoles.User;
}
