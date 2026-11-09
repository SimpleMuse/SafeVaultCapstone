using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Models;

namespace SafeVault.Services;

/// <summary>
/// Issues JWT access tokens and creates opaque refresh tokens.
/// </summary>
public sealed class JwtTokenService(JwtSettings settings)
{
    private readonly SigningCredentials signingCredentials = new(
        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(settings.SigningKey)),
        SecurityAlgorithms.HmacSha256);

    public TokenResponse CreateAccessToken(UserAccount account)
    {
        var now = DateTime.UtcNow;
        var expiresAt = now.AddMinutes(settings.AccessTokenMinutes);
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, account.UserId.ToString()),
            new Claim(JwtRegisteredClaimNames.UniqueName, account.Username),
            new Claim("role", account.Role),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
        var token = new JwtSecurityToken(
            issuer: settings.Issuer,
            audience: settings.Audience,
            claims: claims,
            notBefore: now,
            expires: expiresAt,
            signingCredentials: signingCredentials);

        return new TokenResponse
        {
            AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
            AccessTokenExpiresAtUtc = expiresAt
        };
    }

    public (string Token, string Hash, string FamilyId) CreateRefreshToken(string? familyId = null)
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
        return (token, hash, familyId ?? Guid.NewGuid().ToString("N"));
    }

    public string HashRefreshToken(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    public DateTime GetRefreshTokenExpiry() =>
        DateTime.UtcNow.AddDays(settings.RefreshTokenDays);
}
