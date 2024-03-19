using BlazorUI;
using BlazorUI.Components;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(
        builder.Configuration.GetSection("EntraId"));
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents()
    .AddMicrosoftIdentityConsentHandler();
WebApplication app = builder.Build();

if (app.Environment.IsDevelopment() == false)
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAntiforgery();
app.MapGroup("/authentication").MapLoginAndLogout();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.Run();
