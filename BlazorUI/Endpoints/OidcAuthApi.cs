using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

namespace BlazorUI.Endpoints;

internal static class OidcAuthApi
{
    internal static IEndpointConventionBuilder AddOidcAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        RouteGroupBuilder group = endpoints.MapGroup("/authentication");

        group.MapGet("/login", (string? returnUrl) => 
            TypedResults.Challenge(GetAuthProperties(returnUrl))).AllowAnonymous();

        group.MapGet("/logout", () => 
            TypedResults.SignOut(GetAuthProperties(""),
            [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]));

        return group;
    }

    private static AuthenticationProperties GetAuthProperties(string? returnUrl)
    {
        const string PathBase = "/";

        if (string.IsNullOrEmpty(returnUrl))
        {
            returnUrl = PathBase;
        }
        else if (Uri.IsWellFormedUriString(returnUrl, UriKind.Relative) == false)
        {
            returnUrl = new Uri(returnUrl, UriKind.Absolute).PathAndQuery;
        }
        else if (returnUrl[0] != '/')
        {
            returnUrl = $"{PathBase}{returnUrl}";
        }

        return new AuthenticationProperties { RedirectUri = returnUrl };
    }
}
