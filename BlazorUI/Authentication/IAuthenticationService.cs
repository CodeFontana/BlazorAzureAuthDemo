namespace BlazorUI.Authentication;

internal interface IAuthenticationService
{
    void Login();
    Task LogoutAsync();
}
