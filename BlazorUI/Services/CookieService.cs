using System.Text.Json;
using BlazorUI.Interfaces;

namespace BlazorUI.Services;

internal sealed class CookieService : ICookieService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public CookieService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public void SetCookie<T>(string key, T value, DateTimeOffset? expiry)
    {
        CookieOptions options = new()
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = expiry
        };

        string jsonValue = JsonSerializer.Serialize(value);
        _httpContextAccessor?.HttpContext?.Response.Cookies.Append(key, jsonValue, options);
    }

    public void SetCookie<T>(string key, T value, int daysToExpire = 30)
    {
        CookieOptions options = new()
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.Now.AddDays(daysToExpire)
        };

        string jsonValue = JsonSerializer.Serialize(value);
        _httpContextAccessor?.HttpContext?.Response.Cookies.Append(key, jsonValue, options);
    }

    public T? GetCookie<T>(string key)
    {
        if (_httpContextAccessor?.HttpContext?.Request.Cookies.TryGetValue(key, out string? value) == true)
        {
            return JsonSerializer.Deserialize<T>(value);
        }

        return default;
    }

    public void DeleteCookie(string key)
    {
        if (_httpContextAccessor?.HttpContext?.Request.Cookies.TryGetValue(key, out _) == true)
        {
            _httpContextAccessor?.HttpContext?.Response.Cookies.Delete(key);
        }
    }
}

