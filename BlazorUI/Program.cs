using BlazorUI;
using BlazorUI.Authentication;
using BlazorUI.Components;
using BlazorUI.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Identity.Web;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie()
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    IConfigurationSection entraConfig = builder.Configuration.GetSection("EntraId")
        ?? throw new InvalidOperationException("Missing 'EntraId' in Configuration");
    options.Authority = $"{entraConfig["Instance"]}{entraConfig["TenantId"]}/v2.0";
    options.ClientId = entraConfig["ClientId"];
    options.CallbackPath = entraConfig["CallbackPath"];
    options.ResponseType = "id_token";
    options.SaveTokens = true;

    options.Events = new OpenIdConnectEvents
    {
        OnTokenValidated = async ctx =>
        {
            string accessToken = ctx.SecurityToken.RawData;
            JwtAuthenticationStateProvider authStateProvider =
                (JwtAuthenticationStateProvider)ctx.HttpContext.RequestServices.GetRequiredService<AuthenticationStateProvider>();
            await authStateProvider.NotifyUserAuthenticationAsync(accessToken);
        },
        OnSignedOutCallbackRedirect = ctx =>
        {
            JwtAuthenticationStateProvider authStateProvider =
                (JwtAuthenticationStateProvider)ctx.HttpContext.RequestServices.GetRequiredService<AuthenticationStateProvider>();
            authStateProvider.NotifyUserLogout();
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents()
    .AddMicrosoftIdentityConsentHandler();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICookieService, CookieService>();
builder.Services.AddScoped<IUserRolesService, UserRolesService>();
builder.Services.AddScoped<AuthenticationStateProvider, JwtAuthenticationStateProvider>();
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
app.MapGroup("/authentication").MapLoginAndLogout();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.Run();
