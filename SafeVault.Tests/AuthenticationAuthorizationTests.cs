using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.DependencyInjection;
using SafeVault.Models;
using SafeVault.Services;

[TestFixture]
public sealed class AuthenticationAuthorizationTests
{
    private PasswordHasher<UserAccount> _passwordHasher = null!;
    private PasswordCredentialVerifier _credentialVerifier = null!;

    [SetUp]
    public void SetUp()
    {
        _passwordHasher = new PasswordHasher<UserAccount>();
        _credentialVerifier = new PasswordCredentialVerifier(_passwordHasher);
    }

    [Test]
    public void LoginWithCorrectPasswordAuthenticatesAccount()
    {
        var account = new UserAccount { UserId = 42, Username = "User123" };
        const string password = "correct horse battery staple";
        var passwordHash = _passwordHasher.HashPassword(account, password);

        var result = _credentialVerifier.Verify(account, password, passwordHash);

        Assert.That(result, Is.EqualTo(PasswordVerificationResult.Success));
    }

    [TestCase("incorrect password")]
    [TestCase("")]
    public void LoginWithIncorrectPasswordIsRejected(string submittedPassword)
    {
        var account = new UserAccount { UserId = 42, Username = "User123" };
        var passwordHash = _passwordHasher.HashPassword(account, "correct horse battery staple");

        var result = _credentialVerifier.Verify(account, submittedPassword, passwordHash);

        Assert.That(result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public void LoginForUnknownAccountIsRejected()
    {
        var result = _credentialVerifier.Verify(null, "some submitted password", null);

        Assert.That(result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public async Task AdminPolicyAllowsAdminAndDeniesUserAndAnonymousPrincipal()
    {
        using var services = new ServiceCollection()
            .AddLogging()
            .AddAuthorization(AuthorizationPolicies.Configure)
            .BuildServiceProvider();
        var authorizationService = services.GetRequiredService<IAuthorizationService>();

        var adminResult = await authorizationService.AuthorizeAsync(
            CreatePrincipal(UserRoles.Admin),
            AuthorizationPolicies.AdminOnly);
        var userResult = await authorizationService.AuthorizeAsync(
            CreatePrincipal(UserRoles.User),
            AuthorizationPolicies.AdminOnly);
        var anonymousResult = await authorizationService.AuthorizeAsync(
            new ClaimsPrincipal(new ClaimsIdentity()),
            AuthorizationPolicies.AdminOnly);

        Assert.Multiple(() =>
        {
            Assert.That(adminResult.Succeeded, Is.True);
            Assert.That(userResult.Succeeded, Is.False);
            Assert.That(anonymousResult.Succeeded, Is.False);
        });
    }

    [Test]
    public void AccessTokenContainsAccountRoleAndExpiresWithinConfiguredLifetime()
    {
        var settings = new JwtSettings
        {
            Issuer = "SafeVault.Tests",
            Audience = "SafeVault.Tests",
            SigningKey = "test-only-signing-key-with-at-least-32-bytes",
            AccessTokenMinutes = 5,
            RefreshTokenDays = 7
        };
        var service = new JwtTokenService(settings);
        var account = new UserAccount { UserId = 12, Username = "Admin12", Role = UserRoles.Admin };

        var response = service.CreateAccessToken(account);
        var handler = new JwtSecurityTokenHandler();
        handler.MapInboundClaims = false;
        var jwt = handler.ReadJwtToken(response.AccessToken);
        var principal = handler.ValidateToken(
            response.AccessToken,
            new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = settings.Issuer,
                ValidateAudience = true,
                ValidAudience = settings.Audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(settings.SigningKey)),
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                RoleClaimType = "role"
            },
            out _);

        Assert.Multiple(() =>
        {
            Assert.That(jwt.Issuer, Is.EqualTo(settings.Issuer));
            Assert.That(jwt.Audiences, Does.Contain(settings.Audience));
            Assert.That(jwt.Claims.Single(claim => claim.Type == "sub").Value, Is.EqualTo("12"));
            Assert.That(jwt.Claims.Single(claim => claim.Type == "role").Value, Is.EqualTo(UserRoles.Admin));
            Assert.That(principal.IsInRole(UserRoles.Admin), Is.True);
            Assert.That(response.AccessTokenExpiresAtUtc, Is.EqualTo(jwt.ValidTo).Within(TimeSpan.FromSeconds(1)));
            Assert.That(response.AccessTokenExpiresAtUtc, Is.LessThanOrEqualTo(DateTime.UtcNow.AddMinutes(5)));
        });
    }

    [Test]
    public void RefreshTokensAreRandomAndOnlyTheirHashesAreStored()
    {
        var service = new JwtTokenService(new JwtSettings
        {
            Issuer = "SafeVault.Tests",
            Audience = "SafeVault.Tests",
            SigningKey = "test-only-signing-key-with-at-least-32-bytes"
        });
        var first = service.CreateRefreshToken();
        var second = service.CreateRefreshToken();

        Assert.Multiple(() =>
        {
            Assert.That(first.Token, Is.Not.EqualTo(first.Hash));
            Assert.That(service.HashRefreshToken(first.Token), Is.EqualTo(first.Hash));
            Assert.That(second.Token, Is.Not.EqualTo(first.Token));
            Assert.That(first.FamilyId, Is.Not.EqualTo(second.FamilyId));
        });
    }

    [Test]
    public void JwtSettingsRejectMissingOrWeakSigningKey()
    {
        var settings = new JwtSettings
        {
            Issuer = "SafeVault.Tests",
            Audience = "SafeVault.Tests",
            SigningKey = "too-short"
        };

        Assert.Throws<InvalidOperationException>(settings.Validate);
    }

    private static ClaimsPrincipal CreatePrincipal(string role) =>
        new(new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, "test-account"), new Claim(ClaimTypes.Role, role)],
            authenticationType: "test"));
}
