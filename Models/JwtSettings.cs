namespace SafeVault.Models;

/// <summary>
/// Configuration required to issue and validate JWT access tokens.
/// </summary>
public sealed class JwtSettings
{
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public string SigningKey { get; set; } = string.Empty;
    public int AccessTokenMinutes { get; set; } = 5;
    public int RefreshTokenDays { get; set; } = 7;

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer) ||
            string.IsNullOrWhiteSpace(Audience) ||
            System.Text.Encoding.UTF8.GetByteCount(SigningKey) < 32)
        {
            throw new InvalidOperationException(
                "Configure Jwt:Issuer, Jwt:Audience, and a Jwt:SigningKey of at least 32 UTF-8 bytes.");
        }

        if (AccessTokenMinutes is < 1 or > 60 || RefreshTokenDays is < 1 or > 30)
        {
            throw new InvalidOperationException(
                "JWT access-token lifetime must be 1-60 minutes and refresh-token lifetime must be 1-30 days.");
        }
    }
}
