namespace BlazorUI.Authentication;

internal sealed class UserRolesService : IUserRolesService
{
    public IEnumerable<string> Roles { get; private set; } = [];

    public void SetRoles(IEnumerable<string> roles)
    {
        Roles = roles;
    }

    public bool IsInRole(string role)
    {
        return Roles.Contains(role);
    }
}
