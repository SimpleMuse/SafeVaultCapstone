namespace SafeVault.Models;

/// <summary>
/// Contains a short-lived access token returned to a successful login or refresh request.
/// </summary>
public sealed class TokenResponse
{
    public string AccessToken { get; init; } = string.Empty;
    public DateTime AccessTokenExpiresAtUtc { get; init; }
    public string TokenType { get; init; } = "Bearer";
}

/// <summary>
/// Contains an access token and the current account identity for the browser UI.
/// </summary>
public sealed class AuthenticatedSession
{
    public string AccessToken { get; init; } = string.Empty;
    public DateTime AccessTokenExpiresAtUtc { get; init; }
    public string Username { get; init; } = string.Empty;
    public string Role { get; init; } = UserRoles.User;
}

/// <summary>
/// Request body for an administrator changing another account's role.
/// </summary>
public sealed class RoleUpdateRequest
{
    public int UserId { get; set; }
    public string Role { get; set; } = string.Empty;
}
