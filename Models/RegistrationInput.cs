using System.ComponentModel.DataAnnotations;
using SafeVault.Utilities;

namespace SafeVault.Models;

/// <summary>
/// Contains the details required to create a user account.
/// </summary>
public sealed class RegistrationInput : IValidatableObject
{
    /// <summary>Gets or sets the submitted username.</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>Gets or sets the submitted email address.</summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>Gets or sets the submitted password.</summary>
    [Required]
    [StringLength(128, MinimumLength = 12)]
    public string Password { get; set; } = string.Empty;

    /// <inheritdoc />
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext) =>
        ValidationHelpers.ValidateRegistrationInput(this);
}
