using BlazorUI.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Routing;

namespace BlazorUI.Authentication;

internal sealed class AuthenticationService : IAuthenticationService, IDisposable
{
    private readonly NavigationManager _navMan;
    private readonly ICookieService _cookieService;
    private readonly AuthenticationStateProvider _authStateProvider;
    private string? _currentUrl;

    public AuthenticationService(NavigationManager navMan,
                                 ICookieService cookieService,
                                 AuthenticationStateProvider authStateProvider)
    {
        _navMan = navMan;
        _cookieService = cookieService;
        _authStateProvider = authStateProvider;
        _navMan.LocationChanged += OnLocationChanged;
        _currentUrl = _navMan.ToBaseRelativePath(_navMan.Uri);
    }

    private void OnLocationChanged(object? sender, LocationChangedEventArgs e)
    {
        _currentUrl = _navMan.ToBaseRelativePath(e.Location);
    }

    public void Login()
    {
        // Redirect to OIDC login flow
        _navMan.NavigateTo($"authentication/login?returnUrl={_currentUrl}", true);
        return;
    }

    public async Task LogoutAsync()
    {
        // Sign out - Notify ASP.NET Core
        await _cookieService.SignOutAsync();

        // Signout - Notify Blazor
        ((CookieAuthenticationStateProvider)_authStateProvider).NotifyUserLogout();

        // Navigate to OIDC logout flow
        _navMan.NavigateTo("authentication/logout", true);
        return;
    }

    public void Dispose()
    {
        _navMan.LocationChanged -= OnLocationChanged;
    }
}
