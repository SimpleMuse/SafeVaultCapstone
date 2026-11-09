using System.ComponentModel.DataAnnotations;
using SafeVault.Utilities;

namespace SafeVault.Models;

/// <summary>
/// Contains the username and password submitted to sign in.
/// </summary>
public sealed class LoginInput : IValidatableObject
{
    /// <summary>Gets or sets the submitted username.</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>Gets or sets the submitted password.</summary>
    [Required]
    [StringLength(128)]
    public string Password { get; set; } = string.Empty;

    /// <inheritdoc />
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext) =>
        ValidationHelpers.ValidateLoginInput(this);
}
