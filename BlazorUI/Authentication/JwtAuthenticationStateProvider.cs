using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using BlazorUI.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.IdentityModel.Tokens;

namespace BlazorUI.Authentication;

internal sealed class JwtAuthenticationStateProvider : AuthenticationStateProvider
{
    const string CookieName = "Blazor_AccessToken";

    private readonly ILogger<JwtAuthenticationStateProvider> _logger;
    private readonly ICookieService _cookieService;
    private readonly IUserRolesService _userRolesService;
    private readonly AuthenticationState _anonymous;

    public JwtAuthenticationStateProvider(ILogger<JwtAuthenticationStateProvider> logger,
        ICookieService cookieService,
        IUserRolesService userRolesService)
    {
        _logger = logger;
        _cookieService = cookieService;
        _userRolesService = userRolesService;
        _anonymous = new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                string? authToken = _cookieService.GetCookie<string>(CookieName);

                if (string.IsNullOrWhiteSpace(authToken))
                {
                    return _anonymous;
                }

                JwtSecurityTokenHandler tokenHandler = new();
                SecurityToken token = tokenHandler.ReadToken(authToken);
                DateTime tokenExpiryDate = token.ValidTo;

                if (tokenExpiryDate == DateTime.MinValue)
                {
                    _logger.LogWarning("Invalid JWT [Missing 'exp' claim]");
                    return _anonymous;
                }

                if (tokenExpiryDate < DateTime.UtcNow)
                {
                    _logger.LogWarning("Invalid JWT [Token expired on {tokenExpiryDate}]", tokenExpiryDate.ToLocalTime());
                    //_navMan.NavigateTo("sessionexpired");
                    return _anonymous;
                }

                List<Claim> userRoles = JwtParser.ParseClaimsFromJwt(authToken)
                    .Where(c =>
                        c.Type == ClaimTypes.Role
                        || c.Type.Equals("roles", StringComparison.InvariantCultureIgnoreCase))
                    .ToList();

                _userRolesService.SetRoles(userRoles.Select(c => c.Value));

                return new AuthenticationState(
                    new ClaimsPrincipal(
                        new ClaimsIdentity(
                            JwtParser.ParseClaimsFromJwt(authToken), "Cookies")));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error determining the authentication state");
                return _anonymous;
            }
        });
    }

    public async Task NotifyUserAuthenticationAsync(string token)
    {
        await Task.Run(() =>
        {
            try
            {
                ClaimsIdentity identity = new(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    ClaimTypes.Name,
                    ClaimTypes.Role);

                IEnumerable<Claim> userClaims = JwtParser.ParseClaimsFromJwt(token);

                foreach (Claim c in userClaims)
                {
                    identity.AddClaim(new Claim(c.Type, c.Value));
                }

                ClaimsPrincipal authenticatedUser = new(identity);
                Task<AuthenticationState> authState = Task.FromResult(new AuthenticationState(authenticatedUser));
                NotifyAuthenticationStateChanged(authState);

                string jwtExpiryClaim = userClaims.First(c => c.Type == JwtRegisteredClaimNames.Exp).Value;
                DateTimeOffset expiryUtc = DateTimeOffset.FromUnixTimeSeconds(long.Parse(jwtExpiryClaim));

                _cookieService.SetCookie(CookieName, token, expiryUtc);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update authentication state");
                NotifyUserLogout();
                throw;
            }
        });
    }

    public void NotifyUserLogout()
    {
        _cookieService.DeleteCookie(CookieName);
        Task<AuthenticationState> authState = Task.FromResult(_anonymous);
        NotifyAuthenticationStateChanged(authState);
    }
}
