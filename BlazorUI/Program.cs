using System.IdentityModel.Tokens.Jwt;
using BlazorUI.Authentication;
using BlazorUI.Components;
using BlazorUI.Endpoints;
using BlazorUI.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Tokens;
using AuthenticationService = BlazorUI.Authentication.AuthenticationService;
using IAuthenticationService = BlazorUI.Authentication.IAuthenticationService;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Cookie.Name = "BlazorAzureAuthDemo";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.SlidingExpiration = false;
    options.Events = new CookieAuthenticationEvents
    {
        OnRedirectToLogin = ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        },
        OnRedirectToAccessDenied = ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }
    };
})
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    IConfigurationSection entraConfig = builder.Configuration.GetSection("EntraId")
        ?? throw new InvalidOperationException("Missing 'EntraId' in Configuration");

    options.Authority = $"{entraConfig["Instance"]}{entraConfig["TenantId"]}/v2.0";
    options.ClientId = entraConfig["ClientId"];
    options.CallbackPath = entraConfig["CallbackPath"];
    options.ResponseType = "id_token";
    options.SaveTokens = false;
    options.SignedOutRedirectUri = "/";
    options.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = "preferred_username",
    };

    options.Events = new OpenIdConnectEvents
    {
        OnTokenValidated = async ctx =>
        {
            // Align cookie expiration with JWT expiration
            JwtSecurityToken jwtToken = ctx.SecurityToken;
            string? expClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Exp)?.Value;
            DateTimeOffset? expiresUtc = null;

            if (expClaim != null && long.TryParse(expClaim, out long expUnixSeconds))
            {
                expiresUtc = DateTimeOffset.FromUnixTimeSeconds(expUnixSeconds);
            }
            else
            {
                expiresUtc = DateTimeOffset.UtcNow.AddHours(1);
            }

            // Signin - Notify ASP.NET Core
            await ctx.HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                ctx.Principal!,
                new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = expiresUtc,
                    RedirectUri = ctx.Properties?.GetParameter<string>("returnUrl") ?? "/"
                });

            // Signin - Notify Blazor
            string accessToken = ctx.SecurityToken.RawData;
            CookieAuthenticationStateProvider authStateProvider =
                (CookieAuthenticationStateProvider)ctx.HttpContext.RequestServices.GetRequiredService<AuthenticationStateProvider>();
            await authStateProvider.NotifyUserAuthenticationAsync(accessToken);
        }
    };
});

builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
builder.Services.AddScoped<AuthenticationStateProvider, CookieAuthenticationStateProvider>();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents()
    .AddHubOptions(options =>
    {
        options.ClientTimeoutInterval = TimeSpan.FromSeconds(120);
        options.HandshakeTimeout = TimeSpan.FromSeconds(60);
    })
    .AddMicrosoftIdentityConsentHandler();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICookieService, CookieService>();
builder.Services.AddScoped<IUserRolesService, UserRolesService>();
WebApplication app = builder.Build();

if (app.Environment.IsDevelopment() == false)
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

app.AddOidcAuthEndpoints();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    .AllowAnonymous();
app.Run();
