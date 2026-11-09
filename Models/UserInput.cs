using System.ComponentModel.DataAnnotations;
using SafeVault.Utilities;

namespace SafeVault.Models;

/// <summary>
/// Contains the username and email submitted by the home-page form.
/// Validation rules are centralized in <see cref="ValidationHelpers"/>.
/// </summary>
public sealed class UserInput : IValidatableObject
{
    /// <summary>Gets or sets the submitted username.</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>Gets or sets the submitted email address.</summary>
    public string Email { get; set; } = string.Empty;

    /// <inheritdoc />
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext) =>
        ValidationHelpers.ValidateUserInput(this);
}
