using Microsoft.AspNetCore.Authorization;
using SafeVault.Models;

namespace SafeVault.Services;

/// <summary>
/// Defines authorization policies shared by routes, endpoints, and tests.
/// </summary>
public static class AuthorizationPolicies
{
    public const string AdminOnly = "AdminOnly";

    public static void Configure(AuthorizationOptions options)
    {
        options.AddPolicy(AdminOnly, policy => policy.RequireRole(UserRoles.Admin));
    }
}
