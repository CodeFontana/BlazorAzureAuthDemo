namespace BlazorUI.Authentication;

internal interface IUserRolesService
{
    IEnumerable<string> Roles { get; }

    bool IsInRole(string role);
    void SetRoles(IEnumerable<string> roles);
}