using System.Text.Json;

namespace BlazorUI.Services;

internal sealed class CookieService : ICookieService
{
    private readonly ILogger<CookieService> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public CookieService(ILogger<CookieService> logger,
                         IHttpContextAccessor httpContextAccessor)
    {
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    public void SetCookie<T>(string key, T value, DateTimeOffset? expiry)
    {
        CookieOptions options = new()
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
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
            SameSite = SameSiteMode.Lax,
            Expires = DateTime.Now.AddDays(daysToExpire)
        };

        string jsonValue = JsonSerializer.Serialize(value);
        _httpContextAccessor?.HttpContext?.Response.Cookies.Append(key, jsonValue, options);
    }

    public T? GetCookie<T>(string key)
    {
        if (_httpContextAccessor?.HttpContext?.Request.Cookies.TryGetValue(key, out string? value) == true)
        {
            try
            {
                return JsonSerializer.Deserialize<T>(value);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Failed to decrypt item with name=[{key}]", key);
                DeleteCookie(key); // If we can't decrypt the cookie value, we should delete the value
            }
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
