using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;
using SafeVault.Models;

namespace SafeVault.Components.Pages;

/// <summary>
/// Displays account registration and sign-in feedback on the application's home page.
/// </summary>
public partial class Home
{
    [Inject]
    private IJSRuntime JavaScript { get; set; } = default!;

    [Microsoft.AspNetCore.Components.SupplyParameterFromQuery(Name = "registration")]
    public string? RegistrationStatus { get; set; }

    private LoginInput _login = new();
    private UserSession? _session;
    private IJSObjectReference? _authModule;
    private string? _loginError;
    private bool _isSigningIn;

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (!firstRender)
        {
            return;
        }

        _authModule = await JavaScript.InvokeAsync<IJSObjectReference>(
            "import",
            "./Components/Pages/Home.razor.js");
        try
        {
            _session = await _authModule.InvokeAsync<UserSession?>("getCurrentSession");
        }
        catch (JSException)
        {
            _loginError = "Your sign-in status could not be checked. Please try again.";
        }

        StateHasChanged();
    }

    private async Task SignInAsync()
    {
        _isSigningIn = true;
        _loginError = null;
        try
        {
            _session = await _authModule!.InvokeAsync<UserSession?>(
                "login",
                _login.Username,
                _login.Password);
            if (_session is null)
            {
                _loginError = "Invalid username or password.";
            }
            else
            {
                _login = new LoginInput();
            }
        }
        catch (JSException)
        {
            _loginError = "Sign in is temporarily unavailable. Please try again later.";
        }
        finally
        {
            _isSigningIn = false;
        }
    }

    private async Task SignOutAsync()
    {
        try
        {
            await _authModule!.InvokeVoidAsync("logout");
            _session = null;
        }
        catch (JSException)
        {
            _loginError = "Sign out could not be completed. Please try again.";
        }
    }
}
