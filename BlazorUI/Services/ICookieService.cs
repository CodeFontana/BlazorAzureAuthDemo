using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace BlazorUI.Services;

internal interface ICookieService
{
    T? GetCookie<T>(string key);
    void SetCookie<T>(string key, T value, int daysToExpire = 30);
    void SetCookie<T>(string key, T value, DateTimeOffset? expiry);
    void DeleteCookie(string key);
    Task SignInAsync(ClaimsPrincipal principal, AuthenticationProperties properties);
    Task SignOutAsync();
}
