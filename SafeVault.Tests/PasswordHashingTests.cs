using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using SafeVault.Models;

[TestFixture]
public class PasswordHashingTests
{
    [Test]
    public void PasswordHasherStoresSaltedHashAndRejectsIncorrectPassword()
    {
        var passwordHasher = new PasswordHasher<UserAccount>();
        var account = new UserAccount { Username = "User123" };
        const string password = "a-long-test-password";

        var firstHash = passwordHasher.HashPassword(account, password);
        var secondHash = passwordHasher.HashPassword(account, password);

        Assert.That(firstHash, Is.Not.EqualTo(password));
        Assert.That(secondHash, Is.Not.EqualTo(firstHash));
        Assert.That(
            passwordHasher.VerifyHashedPassword(account, firstHash, password),
            Is.EqualTo(PasswordVerificationResult.Success));
        Assert.That(
            passwordHasher.VerifyHashedPassword(account, firstHash, "incorrect-password"),
            Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [TestCase("short")]
    [TestCase("             ")]
    public void RegistrationRejectsWeakOrBlankPasswords(string password)
    {
        var input = new RegistrationInput
        {
            Username = "User123",
            Email = "user@example.com",
            Password = password
        };
        var errors = new List<ValidationResult>();

        var isValid = Validator.TryValidateObject(
            input,
            new ValidationContext(input),
            errors,
            validateAllProperties: true);

        Assert.That(isValid, Is.False);
        Assert.That(errors.Any(error => error.MemberNames.Contains(nameof(RegistrationInput.Password))), Is.True);
    }
}
