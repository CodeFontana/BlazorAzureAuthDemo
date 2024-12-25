using System.Security.Claims;
using System.Text.Json;

namespace BlazorUI.Authentication;

public static class JwtParser
{
    public static IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
    {
        List<Claim> claims = [];
        string payload = jwt.Split('.')[1];
        byte[] jsonBytes = ParseBase64WithoutPadding(payload);
        Dictionary<string, object>? keyValuePairs = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonBytes);

        if (keyValuePairs is null)
        {
            return claims;
        }

        ExtractRolesFromJwt(claims, keyValuePairs);

        claims.AddRange(keyValuePairs
            .Select(kvp => new Claim(
                kvp.Key, kvp.Value?.ToString() ?? "")));

        return claims;
    }

    private static void ExtractRolesFromJwt(List<Claim> claims, Dictionary<string, object> keyValuePairs)
    {
        keyValuePairs.TryGetValue(ClaimTypes.Role, out object? roles);

        if (roles is null)
        {
            keyValuePairs.TryGetValue("roles", out roles);
        }

        if (roles != null)
        {
            string[]? parsedRoles = roles?.ToString()?.Trim().TrimStart('[').TrimEnd(']').Split(',');

            if (parsedRoles?.Length > 1)
            {
                foreach (var parsedRole in parsedRoles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, parsedRole.Trim('"')));
                }
            }
            else
            {
                claims.Add(new Claim(ClaimTypes.Role, parsedRoles?[0] ?? ""));
            }

            keyValuePairs.Remove(ClaimTypes.Role);
        }
    }

    private static byte[] ParseBase64WithoutPadding(string base64)
    {
        switch (base64.Length % 4)
        {
            case 2:
                base64 += "==";
                break;
            case 3:
                base64 += "=";
                break;
        }

        return Convert.FromBase64String(base64);
    }
}
