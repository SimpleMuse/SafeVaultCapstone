using System.ComponentModel.DataAnnotations;
using SafeVault.Models;

[TestFixture]
public class UserInputValidationTests
{
    [TestCase("admin' OR '1'='1")]
    [TestCase("' UNION SELECT username, password FROM Users --")]
    public void RejectsSqlInjectionPayloadInUsername(string payload)
    {
        var input = new UserInput
        {
            Username = payload,
            Email = "admin@example.com"
        };

        Assert.That(IsValid(input), Is.False);
    }

    [TestCase("' OR '1'='1")]
    [TestCase("user@example.com' OR 1=1 --")]
    public void RejectsSqlInjectionPayloadInEmail(string payload)
    {
        var input = new UserInput
        {
            Username = "Admin123",
            Email = payload
        };

        Assert.That(IsValid(input), Is.False);
    }

    [TestCase("<script>alert(1)</script>")]
    [TestCase("<img src=x onerror=alert(1)>")]
    public void RejectsXssPayloadInUsername(string payload)
    {
        var input = new UserInput
        {
            Username = payload,
            Email = "user@example.com"
        };

        Assert.That(IsValid(input), Is.False);
    }

    [TestCase("<script>alert(1)</script>")]
    [TestCase("javascript:alert(1)@example.com")]
    public void RejectsXssPayloadInEmail(string payload)
    {
        var input = new UserInput
        {
            Username = "User123",
            Email = payload
        };

        Assert.That(IsValid(input), Is.False);
    }

    [Test]
    public void AcceptsValidUsernameAndEmail()
    {
        var input = new UserInput
        {
            Username = "User123",
            Email = "user@example.com"
        };

        Assert.That(IsValid(input), Is.True);
    }

    [TestCase("")]
    [TestCase("name with spaces")]
    [TestCase("name!")]
    [TestCase("name<script>")]
    [TestCase("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void RejectsUsernameContainingInvalidCharactersOrLength(string username)
    {
        var input = new UserInput
        {
            Username = username,
            Email = "user@example.com"
        };

        Assert.That(IsValid(input), Is.False);
    }

    [TestCase("not-an-email")]
    [TestCase("<script>alert(1)</script>")]
    [TestCase("' OR '1'='1")]
    [TestCase("user@abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.com")]
    public void RejectsInvalidEmail(string email)
    {
        var input = new UserInput
        {
            Username = "User123",
            Email = email
        };

        Assert.That(IsValid(input), Is.False);
    }

    private static bool IsValid(UserInput input)
    {
        var results = new List<ValidationResult>();
        return Validator.TryValidateObject(
            input,
            new ValidationContext(input),
            results,
            validateAllProperties: true);
    }
}
