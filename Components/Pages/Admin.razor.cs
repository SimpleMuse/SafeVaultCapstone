using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;
using SafeVault.Models;

namespace SafeVault.Components.Pages;

/// <summary>
/// Loads account details through the admin-authorized API for the dashboard UI.
/// </summary>
public partial class Admin
{
    [Inject]
    private IJSRuntime JavaScript { get; set; } = default!;

    private IJSObjectReference? _adminModule;

    private IReadOnlyList<UserAccount> _accounts = [];
    private string? _loadError;
    private string? _status;
    private readonly Dictionary<int, string> _selectedRoles = [];

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (firstRender)
        {
            _adminModule = await JavaScript.InvokeAsync<IJSObjectReference>(
                "import",
                "./Components/Pages/Admin.razor.js");
            await LoadAccountsAsync();
        }
    }

    private void SetSelectedRole(int userId, string? role)
    {
        if (role is UserRoles.Admin or UserRoles.User)
        {
            _selectedRoles[userId] = role;
        }
    }

    private async Task LoadAccountsAsync()
    {
        try
        {
            var accounts = await _adminModule!.InvokeAsync<UserAccount[]>("getAccounts");
            _accounts = accounts;
            _loadError = null;
        }
        catch (JSException exception)
        {
            _loadError = exception.Message.Contains("403", StringComparison.Ordinal)
                ? "Access denied. Sign in with an administrator account to view this dashboard."
                : "Unable to load account details. Sign in again or try later.";
        }
    }

    private async Task UpdateRoleAsync(int userId)
    {
        if (!_selectedRoles.TryGetValue(userId, out var role))
        {
            return;
        }

        try
        {
            await _adminModule!.InvokeVoidAsync("updateRole", userId, role);
            _status = "updated";
            await LoadAccountsAsync();
        }
        catch (JSException exception)
        {
            _status = exception.Message.Contains("403", StringComparison.Ordinal)
                ? "Access denied. Sign in with an administrator account to change roles."
                : exception.Message.Contains("409", StringComparison.Ordinal)
                    ? "You cannot change your own role."
                    : "The role change could not be completed. Sign in again or try later.";
        }
    }
}
