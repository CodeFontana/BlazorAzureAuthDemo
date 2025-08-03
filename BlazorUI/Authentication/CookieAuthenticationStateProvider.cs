using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using BlazorUI.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.IdentityModel.Tokens;

namespace BlazorUI.Authentication;

internal sealed class CookieAuthenticationStateProvider : AuthenticationStateProvider
{
    const string CookieName = "BlazorAzureAuthDemo_AccessToken";

    private readonly ILogger<CookieAuthenticationStateProvider> _logger;
    private readonly ICookieService _cookieService;
    private readonly IUserRolesService _userRolesService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly AuthenticationState _anonymous;

    public CookieAuthenticationStateProvider(ILogger<CookieAuthenticationStateProvider> logger,
                                             ICookieService cookieService,
                                             IUserRolesService userRolesService,
                                             IHttpContextAccessor httpContextAccessor)
    {
        _logger = logger;
        _cookieService = cookieService;
        _userRolesService = userRolesService;
        _httpContextAccessor = httpContextAccessor;
        _anonymous = new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        try
        {
            string? authToken = _cookieService.GetCookie<string>(CookieName);

            if (string.IsNullOrWhiteSpace(authToken))
            {
                return await Task.FromResult(_anonymous);
            }

            JwtSecurityTokenHandler tokenHandler = new();
            SecurityToken token = tokenHandler.ReadToken(authToken);
            DateTime tokenExpiryDate = token.ValidTo;

            if (tokenExpiryDate == DateTime.MinValue)
            {
                _logger.LogWarning("Invalid JWT [Missing 'exp' claim]");
                return await Task.FromResult(_anonymous);
            }

            if (tokenExpiryDate < DateTime.UtcNow)
            {
                _logger.LogWarning("Invalid JWT [Token expired on {tokenExpiryDate}]", tokenExpiryDate.ToLocalTime());
                //_navMan.NavigateTo("sessionexpired");
                return await Task.FromResult(_anonymous);
            }

            IEnumerable<Claim> claims = JwtParser.ParseClaimsFromJwt(authToken);
            ClaimsIdentity identity = new(claims, "Cookies");
            ClaimsPrincipal principal = new(identity);

            if (_httpContextAccessor.HttpContext != null
                && (_httpContextAccessor.HttpContext.User == null
                    || _httpContextAccessor.HttpContext.User.Identity!.IsAuthenticated == false))
            {
                try
                {
                    await _httpContextAccessor.HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        principal,
                        new AuthenticationProperties
                        {
                            IsPersistent = true,
                            ExpiresUtc = tokenExpiryDate
                        });
                }
                catch (Exception)
                {
                    return await Task.FromResult(_anonymous);
                }
            }

            IEnumerable<Claim> roles = claims.Where(c =>
                c.Type == ClaimTypes.Role
                || c.Type.Equals(
                    "roles",
                    StringComparison.InvariantCultureIgnoreCase));
            
            _userRolesService.SetRoles(roles.Select(c => c.Value));

            return await Task.FromResult(new AuthenticationState(principal));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error determining the authentication state");
            return await Task.FromResult(_anonymous);
        }
    }

    public async Task NotifyUserAuthenticationAsync(string token)
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
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update authentication state");
            NotifyUserLogout();
            throw;
        }
    }

    public void NotifyUserLogout()
    {
        _cookieService.DeleteCookie(CookieName);
        NotifyAuthenticationStateChanged(Task.FromResult(_anonymous));
    }
}
