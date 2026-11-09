using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using MySqlConnector;
using SafeVault.Models;

namespace SafeVault.Services;

/// <summary>
/// Maps account registration and token-based authentication endpoints.
/// </summary>
public static class AccountEndpoints
{
    public static void MapAccountEndpoints(this WebApplication app)
    {
        app.MapPost("/account/register", RegisterAsync);
        app.MapPost("/account/login", LoginAsync);
        app.MapPost("/account/refresh", RefreshAsync);
        app.MapPost("/account/logout", LogoutAsync);
        app.MapGet("/account/me", GetCurrentAccount)
            .RequireAuthorization();
        app.MapGet("/account/admin/accounts", GetAccountsAsync)
            .RequireAuthorization(AuthorizationPolicies.AdminOnly);
        app.MapPost("/account/admin/role", UpdateRoleAsync)
            .RequireAuthorization(AuthorizationPolicies.AdminOnly);
    }

    private static async Task<IResult> RegisterAsync(
        HttpContext context,
        UserRepository userRepository,
        IAntiforgery antiforgery,
        ILoggerFactory loggerFactory)
    {
        if (!await antiforgery.IsRequestValidAsync(context) || !context.Request.HasFormContentType)
        {
            return Results.BadRequest();
        }

        var form = await context.Request.ReadFormAsync(context.RequestAborted);
        var input = new RegistrationInput
        {
            Username = form["Username"].ToString(),
            Email = form["Email"].ToString(),
            Password = form["Password"].ToString()
        };

        try
        {
            await userRepository.RegisterAsync(input, context.RequestAborted);
            return Results.Redirect("/?registration=success");
        }
        catch (ValidationException)
        {
            return Results.Redirect("/?registration=invalid");
        }
        catch (MySqlException exception)
        {
            loggerFactory.CreateLogger("SafeVault.AccountEndpoints")
                .LogError(exception, "Could not register the submitted account.");
            return Results.Redirect("/?registration=failed");
        }
        catch (InvalidOperationException exception)
        {
            loggerFactory.CreateLogger("SafeVault.AccountEndpoints")
                .LogError(exception, "Could not register the submitted account because the database is not configured.");
            return Results.Redirect("/?registration=failed");
        }
    }

    private static async Task<IResult> LoginAsync(
        HttpContext context,
        LoginInput input,
        UserRepository userRepository,
        JwtTokenService tokenService,
        IAntiforgery antiforgery,
        ILoggerFactory loggerFactory)
    {
        if (!await antiforgery.IsRequestValidAsync(context))
        {
            return Results.BadRequest();
        }

        try
        {
            var account = await userRepository.AuthenticateAsync(input, context.RequestAborted);
            if (account is null)
            {
                return Results.Unauthorized();
            }

            var refreshToken = tokenService.CreateRefreshToken();
            var refreshExpiresAtUtc = tokenService.GetRefreshTokenExpiry();
            await userRepository.AddRefreshTokenAsync(
                account.UserId,
                refreshToken.Hash,
                refreshToken.FamilyId,
                refreshExpiresAtUtc,
                context.RequestAborted);

            var accessToken = tokenService.CreateAccessToken(account);
            SetRefreshCookie(context, refreshToken.Token, refreshExpiresAtUtc);
            return Results.Ok(new AuthenticatedSession
            {
                AccessToken = accessToken.AccessToken,
                AccessTokenExpiresAtUtc = accessToken.AccessTokenExpiresAtUtc,
                Username = account.Username,
                Role = account.Role
            });
        }
        catch (ValidationException)
        {
            return Results.BadRequest();
        }
        catch (MySqlException exception)
        {
            loggerFactory.CreateLogger("SafeVault.AccountEndpoints")
                .LogError(exception, "Could not authenticate the submitted account.");
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
        catch (InvalidOperationException exception)
        {
            loggerFactory.CreateLogger("SafeVault.AccountEndpoints")
                .LogError(exception, "Could not authenticate because the database is not configured.");
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }

    private static async Task<IResult> RefreshAsync(
        HttpContext context,
        UserRepository userRepository,
        JwtTokenService tokenService,
        IAntiforgery antiforgery,
        ILoggerFactory loggerFactory)
    {
        if (!await antiforgery.IsRequestValidAsync(context))
        {
            return Results.BadRequest();
        }

        var currentToken = context.Request.Cookies["__Host-SafeVault.Refresh"];
        if (string.IsNullOrWhiteSpace(currentToken))
        {
            return Results.NoContent();
        }

        try
        {
            var replacement = tokenService.CreateRefreshToken();
            var refreshExpiresAtUtc = tokenService.GetRefreshTokenExpiry();
            var account = await userRepository.RotateRefreshTokenAsync(
                tokenService.HashRefreshToken(currentToken),
                replacement.Hash,
                refreshExpiresAtUtc,
                context.RequestAborted);
            if (account is null)
            {
                DeleteRefreshCookie(context);
                return Results.Unauthorized();
            }

            SetRefreshCookie(context, replacement.Token, refreshExpiresAtUtc);
            return Results.Ok(tokenService.CreateAccessToken(account));
        }
        catch (MySqlException exception)
        {
            loggerFactory.CreateLogger("SafeVault.AccountEndpoints")
                .LogError(exception, "Could not rotate a refresh token.");
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
        catch (InvalidOperationException exception)
        {
            loggerFactory.CreateLogger("SafeVault.AccountEndpoints")
                .LogError(exception, "Could not rotate a refresh token because the database is not configured.");
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }

    private static async Task<IResult> LogoutAsync(
        HttpContext context,
        UserRepository userRepository,
        JwtTokenService tokenService,
        IAntiforgery antiforgery,
        ILoggerFactory loggerFactory)
    {
        if (!await antiforgery.IsRequestValidAsync(context))
        {
            return Results.BadRequest();
        }

        var refreshToken = context.Request.Cookies["__Host-SafeVault.Refresh"];
        try
        {
            if (!string.IsNullOrWhiteSpace(refreshToken))
            {
                await userRepository.RevokeRefreshTokenAsync(
                    tokenService.HashRefreshToken(refreshToken),
                    context.RequestAborted);
            }

            DeleteRefreshCookie(context);
            return Results.NoContent();
        }
        catch (MySqlException exception)
        {
            loggerFactory.CreateLogger("SafeVault.AccountEndpoints")
                .LogError(exception, "Could not revoke the refresh token.");
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
        catch (InvalidOperationException exception)
        {
            loggerFactory.CreateLogger("SafeVault.AccountEndpoints")
                .LogError(exception, "Could not revoke the refresh token because the database is not configured.");
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }

    private static async Task<IResult> UpdateRoleAsync(
        HttpContext context,
        RoleUpdateRequest request,
        UserRepository userRepository,
        ILoggerFactory loggerFactory)
    {
        if (request.UserId <= 0 || request.Role is not (UserRoles.Admin or UserRoles.User))
        {
            return Results.BadRequest();
        }

        if (context.User.FindFirstValue("sub") == request.UserId.ToString())
        {
            return Results.Conflict();
        }

        try
        {
            var updated = await userRepository.SetRoleAsync(
                request.UserId,
                request.Role,
                context.RequestAborted);
            return updated ? Results.NoContent() : Results.NotFound();
        }
        catch (MySqlException exception)
        {
            loggerFactory.CreateLogger("SafeVault.AccountEndpoints")
                .LogError(exception, "Could not update the requested account role.");
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
        catch (InvalidOperationException exception)
        {
            loggerFactory.CreateLogger("SafeVault.AccountEndpoints")
                .LogError(exception, "Could not update the requested role because the database is not configured.");
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }

    private static IResult GetCurrentAccount(ClaimsPrincipal principal)
    {
        var userId = principal.FindFirstValue("sub");
        var username = principal.FindFirstValue("unique_name");
        var role = principal.FindFirstValue("role");
        return int.TryParse(userId, out _) && username is not null && role is not null
            ? Results.Ok(new { username, role })
            : Results.Unauthorized();
    }

    private static async Task<IResult> GetAccountsAsync(
        UserRepository userRepository,
        ILoggerFactory loggerFactory)
    {
        try
        {
            var accounts = await userRepository.GetAccountsAsync();
            return Results.Ok(accounts);
        }
        catch (MySqlException exception)
        {
            loggerFactory.CreateLogger("SafeVault.AccountEndpoints")
                .LogError(exception, "Could not load accounts for the admin API.");
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
        catch (InvalidOperationException exception)
        {
            loggerFactory.CreateLogger("SafeVault.AccountEndpoints")
                .LogError(exception, "Could not load admin accounts because the database is not configured.");
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }

    private static void SetRefreshCookie(HttpContext context, string token, DateTime expiresAtUtc)
    {
        context.Response.Cookies.Append(
            "__Host-SafeVault.Refresh",
            token,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                Expires = new DateTimeOffset(expiresAtUtc, TimeSpan.Zero)
            });
    }

    private static void DeleteRefreshCookie(HttpContext context) =>
        context.Response.Cookies.Delete(
            "__Host-SafeVault.Refresh",
            new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Path = "/" });
}
