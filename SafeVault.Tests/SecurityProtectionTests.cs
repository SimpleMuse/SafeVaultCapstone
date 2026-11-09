using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MySqlConnector;
using SafeVault.Components.Pages;
using SafeVault.Models;
using SafeVault.Services;

[TestFixture]
public sealed class SecurityProtectionTests
{
    [Test]
    public void AuthenticationQueryBindsSqlInjectionPayloadAsUsernameValue()
    {
        const string payload = "Admin123' OR '1'='1";
        using var connection = new MySqlConnection();
        using var command = UserRepository.CreateAuthenticationCommand(connection, payload);

        Assert.Multiple(() =>
        {
            Assert.That(command.CommandText, Does.Contain("Username = @username"));
            Assert.That(command.CommandText, Does.Not.Contain(payload));
            Assert.That(command.Parameters["@username"].Value, Is.EqualTo(payload));
        });
    }

    [Test]
    public async Task AdminAccountRowRendersMaliciousUsernameAsEncodedText()
    {
        const string payload = "<img src=x onerror=alert(1)>";
        using var services = new ServiceCollection()
            .AddLogging()
            .BuildServiceProvider();
        await using var renderer = new HtmlRenderer(
            services,
            services.GetRequiredService<ILoggerFactory>());

        var html = await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var component = await renderer.RenderComponentAsync<AdminAccountRow>(
                ParameterView.FromDictionary(new Dictionary<string, object?>
                {
                    [nameof(AdminAccountRow.Account)] = new UserAccount
                    {
                        UserId = 7,
                        Username = payload,
                        Role = UserRoles.User
                    }
                }));
            return component.ToHtmlString();
        });

        Assert.Multiple(() =>
        {
            Assert.That(html, Does.Contain("&lt;img"));
            Assert.That(html, Does.Not.Contain(payload));
            Assert.That(html, Does.Not.Contain("<img"));
        });
    }
}
