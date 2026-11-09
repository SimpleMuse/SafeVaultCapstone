using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using SafeVault.Models;

namespace SafeVault.Utilities;

/// <summary>
/// Provides server-side validation rules for user-submitted form data.
/// </summary>
public static class ValidationHelpers
{
    private const int MaxFieldLength = 100;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);
    private static readonly Regex UsernamePattern = new(
        "^[A-Za-z0-9]+$",
        RegexOptions.CultureInvariant,
        RegexTimeout);
    private static readonly Regex EmailPattern = new(
        "^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}$",
        RegexOptions.CultureInvariant,
        RegexTimeout);

    /// <summary>
    /// Validates required fields, maximum lengths, and allowed username and email formats.
    /// </summary>
    /// <param name="input">The submitted user input to validate.</param>
    /// <returns>Validation errors associated with the invalid fields; an empty sequence when valid.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="input"/> is null.</exception>
    public static IEnumerable<ValidationResult> ValidateUserInput(UserInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        foreach (var error in ValidateUsernameAndEmail(input.Username, input.Email))
        {
            yield return error;
        }
    }

    /// <summary>
    /// Validates account registration details, including the password length.
    /// </summary>
    public static IEnumerable<ValidationResult> ValidateRegistrationInput(RegistrationInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        foreach (var error in ValidateUsernameAndEmail(input.Username, input.Email))
        {
            yield return error;
        }

        if (string.IsNullOrWhiteSpace(input.Password))
        {
            yield return Error("Password is required.", nameof(RegistrationInput.Password));
        }
        else if (input.Password.Length < 12 || input.Password.Length > 128)
        {
            yield return Error(
                "Password must be between 12 and 128 characters.",
                nameof(RegistrationInput.Password));
        }
    }

    /// <summary>
    /// Validates the username and password submitted for login.
    /// </summary>
    public static IEnumerable<ValidationResult> ValidateLoginInput(LoginInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        foreach (var error in ValidateUsername(input.Username))
        {
            yield return error;
        }

        if (string.IsNullOrWhiteSpace(input.Password))
        {
            yield return Error("Password is required.", nameof(LoginInput.Password));
        }
        else if (input.Password.Length > 128)
        {
            yield return Error("Password cannot exceed 128 characters.", nameof(LoginInput.Password));
        }
    }

    private static IEnumerable<ValidationResult> ValidateUsernameAndEmail(string username, string email)
    {
        foreach (var error in ValidateUsername(username))
        {
            yield return error;
        }

        foreach (var error in ValidateEmail(email))
        {
            yield return error;
        }
    }

    private static IEnumerable<ValidationResult> ValidateUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            yield return Error("Username is required.", nameof(UserInput.Username));
        }
        else if (username.Length > MaxFieldLength)
        {
            yield return Error("Username cannot exceed 100 characters.", nameof(UserInput.Username));
        }
        else if (!UsernamePattern.IsMatch(username))
        {
            yield return Error("Use letters and numbers only.", nameof(UserInput.Username));
        }
    }

    private static IEnumerable<ValidationResult> ValidateEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            yield return Error("Email is required.", nameof(UserInput.Email));
        }
        else if (email.Length > MaxFieldLength)
        {
            yield return Error("Email cannot exceed 100 characters.", nameof(UserInput.Email));
        }
        else if (!EmailPattern.IsMatch(email) || !new EmailAddressAttribute().IsValid(email))
        {
            yield return Error("Enter a valid email address.", nameof(UserInput.Email));
        }
    }

    private static ValidationResult Error(string message, string memberName) =>
        new(message, [memberName]);
}
