using System.Security.Claims;

namespace DynamicAuthorization.AspNetCore.Tests;

/// <summary>
///   The permission handler learns how a permission was decided, so that super admins can skip the policies assigned to
///   resources, without paying more than the decision alone costs.
/// </summary>
public sealed class PermissionDecisionTests
{
    [Theory]
    [InlineData("root", null, PermissionDecision.SuperAdminUser)]
    [InlineData("ada", "Admins", PermissionDecision.SuperAdminRole)]
    [InlineData("eve", "Editors", PermissionDecision.GrantedByRole)]
    [InlineData("rob", "Readers", PermissionDecision.GrantedByRole)] // orders.read implied by orders.update
    [InlineData("nia", "Nobody", PermissionDecision.NotGranted)]
    [InlineData("tom", null, PermissionDecision.NotGranted)]
    public async Task Decisions_name_how_the_permission_was_granted(string user, string? role, PermissionDecision expected)
    {
        CountingPermissionStore store = new();
        await using ServiceProvider services = BuildServices(store);
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        PermissionChecker checker = Assert.IsType<PermissionChecker>(scope.ServiceProvider.GetRequiredService<IPermissionChecker>());

        string permission = user == "rob" ? "orders.read" : "orders.update";
        PermissionDecision decision = await checker.DecideAsync(Principal(user, role), permission);

        Assert.Equal(expected, decision);
    }

    [Fact]
    public async Task Unauthenticated_users_are_not_authenticated()
    {
        await using ServiceProvider services = BuildServices(new CountingPermissionStore());
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        PermissionChecker checker = (PermissionChecker)scope.ServiceProvider.GetRequiredService<IPermissionChecker>();

        Assert.Equal(PermissionDecision.NotAuthenticated, await checker.DecideAsync(new ClaimsPrincipal(new ClaimsIdentity()), "orders.update"));
    }

    [Fact]
    public async Task Deciding_costs_what_checking_costs()
    {
        CountingPermissionStore store = new();
        await using ServiceProvider services = BuildServices(store);

        await using (AsyncServiceScope scope = services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<IPermissionChecker>().HasPermissionAsync(Principal("eve", "Editors"), "orders.update");
        }

        int checkCost = store.Calls;
        await using (AsyncServiceScope scope = services.CreateAsyncScope())
        {
            await ((PermissionChecker)scope.ServiceProvider.GetRequiredService<IPermissionChecker>()).DecideAsync(Principal("eve", "Editors"), "orders.update");
        }

        Assert.Equal(checkCost, store.Calls - checkCost);
    }

    private static ServiceProvider BuildServices(CountingPermissionStore store)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddDynamicAuthorization(o =>
        {
            o.CacheDuration = TimeSpan.Zero;
            o.SuperAdminUsers.Add("root");
            o.SuperAdminRoles.Add("Admins");
        });
        services.AddSingleton<IUserRoleProvider, ClaimRolesProvider>();
        services.AddSingleton<IPermissionStore>(store);

        return services.BuildServiceProvider();
    }

    private static ClaimsPrincipal Principal(string user, string? role)
    {
        List<Claim> claims = [new(ClaimTypes.NameIdentifier, user), new(ClaimTypes.Name, user)];
        if (role is not null)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));
    }

    /// <summary>
    ///   Reads a user's roles from the principal the test built, so that the user identifier is enough.
    /// </summary>
    private sealed class ClaimRolesProvider : IUserRoleProvider
    {
        private static readonly Dictionary<string, string> s_roles = new(StringComparer.Ordinal)
        {
            ["ada"] = "Admins",
            ["eve"] = "Editors",
            ["rob"] = "Readers",
            ["nia"] = "Nobody",
        };

        public string? GetUserId(ClaimsPrincipal principal) => principal.FindFirstValue(ClaimTypes.NameIdentifier);

        public Task<IReadOnlyList<RoleReference>> GetUserRolesAsync(string userId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<RoleReference>>(
                s_roles.TryGetValue(userId, out string? role) ? [new RoleReference(role, role)] : []);
    }

    private sealed class CountingPermissionStore : IPermissionStore
    {
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public Task<IReadOnlySet<string>> GetPermissionsAsync(string roleId, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _calls);
            HashSet<string> permissions = [with(StringComparer.OrdinalIgnoreCase)];
            if (roleId is "Editors" or "Readers")
            {
                permissions.Add("orders.update");
            }

            return Task.FromResult<IReadOnlySet<string>>(permissions);
        }

        public Task<PermissionChangeSet> SetPermissionsAsync(string roleId, IEnumerable<string> permissions, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }
}
