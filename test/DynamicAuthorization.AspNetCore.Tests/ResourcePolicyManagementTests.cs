using System.Net;
using DynamicAuthorization.AspNetCore.Management;
using DynamicAuthorization.AspNetCore.Tests.Infrastructure;
using Microsoft.AspNetCore.Authorization;

namespace DynamicAuthorization.AspNetCore.Tests;

/// <summary>
///   The management service validates assignments against the catalog and the registered policies, lets admins clean
///   up what no longer exists, and makes a change visible to the next request.
/// </summary>
public sealed class ResourcePolicyManagementTests
{
    [Fact]
    public async Task Resources_list_their_enforced_and_skipped_policies()
    {
        InMemoryResourcePolicyStore store = new();
        await store.SetPoliciesAsync("orders", ["Deny", "Retired"]);
        await store.SetPoliciesAsync("removed", ["Allow"]);
        await using TestApp app = await StartAsync(store, dashboard: true);

        ResourcePolicyAssignments assignments = await app.WithScopeAsync(s => s.GetRequiredService<IResourcePolicyManagementService>().GetAssignmentsAsync());

        Assert.Equal(["Allow", "Deny", "RequireMfa"], assignments.Policies.Select(p => p.Name));
        ResourcePolicySummary orders = Assert.Single(assignments.Resources, r => r.Resource == "orders");
        Assert.Equal("Orders", orders.DisplayName);
        Assert.True(orders.EndpointCount > 1);
        Assert.Equal(["Deny"], orders.Enforced);
        Assert.Equal(["Retired"], orders.Skipped);
        Assert.Contains(assignments.Resources, r => r.Resource == "items" && r.Enforced.Count == 0);
        Assert.DoesNotContain(assignments.Resources, r => r.Resource == "public"); // not permission-checked
        Assert.Equal("removed", Assert.Single(assignments.Orphaned).Resource);
        Assert.True(assignments.Resources.Single(r => r.Resource == "authz.roles").IsDashboard);
    }

    [Fact]
    public async Task Assigning_applies_to_the_next_request()
    {
        await using TestApp app = await StartAsync();
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read");
        HttpClient client = app.CreateClient(user);
        Assert.Equal(HttpStatusCode.OK, await client.GetStatusAsync("/Orders"));

        ManagementResult result = await SetAsync(app, "Orders", "deny", "Deny", " ");

        Assert.True(result.Succeeded, string.Join(" ", result.Errors));
        Assert.Equal(HttpStatusCode.Forbidden, await client.GetStatusAsync("/Orders"));
        Assert.Equal(["deny"], await app.WithScopeAsync(async s => (await s.GetRequiredService<IResourcePolicyStore>().GetAssignmentsAsync())["orders"]));
    }

    [Theory]
    [InlineData("unknown", "Allow", "not a resource")]
    [InlineData("public", "Allow", "not a resource")]
    [InlineData("orders", "Unregistered", "not assignable")]
    [InlineData("orders", "Undefined", "not defined")]
    [InlineData("orders", "WithScheme", "authentication schemes")]
    [InlineData("orders", "Recursive", "dynamic permission")]
    public async Task Invalid_assignments_are_refused(string resource, string policy, string reason)
    {
        await using TestApp app = await StartAsync(assignable: ["Allow", "Undefined", "WithScheme", "Recursive"]);

        ManagementResult result = await SetAsync(app, resource, policy);

        Assert.False(result.Succeeded);
        Assert.Contains(reason, Assert.Single(result.Errors), StringComparison.Ordinal);
        Assert.Empty(await app.WithScopeAsync(s => s.GetRequiredService<IResourcePolicyStore>().GetAssignmentsAsync()));
    }

    [Fact]
    public async Task Orphaned_assignments_can_be_cleared()
    {
        InMemoryResourcePolicyStore store = new();
        await store.SetPoliciesAsync("removed", ["Allow"]);
        await using TestApp app = await StartAsync(store);

        ManagementResult result = await SetAsync(app, "removed");

        Assert.True(result.Succeeded);
        Assert.Empty(await store.GetAssignmentsAsync());
    }

    [Fact]
    public async Task Policies_no_longer_registered_can_be_kept_or_dropped_but_not_added()
    {
        InMemoryResourcePolicyStore store = new();
        await store.SetPoliciesAsync("orders", ["Retired"]);
        await using TestApp app = await StartAsync(store);

        Assert.True((await SetAsync(app, "orders", "Retired", "Allow")).Succeeded);
        Assert.False((await SetAsync(app, "items", "Retired")).Succeeded);
        Assert.True((await SetAsync(app, "orders", "Allow")).Succeeded);
        Assert.Equal(["Allow"], (await store.GetAssignmentsAsync())["orders"]);
        Assert.False((await SetAsync(app, "orders", "Retired")).Succeeded);
    }

    [Fact]
    public async Task Dashboard_resources_take_policies_only_while_a_super_admin_is_configured()
    {
        await using TestApp without = await StartAsync(configure: a => a.SuperAdminUsers.Clear(), dashboard: true);
        await using TestApp with = await StartAsync(dashboard: true);

        ManagementResult refused = await SetAsync(without, "authz.roles", "Allow");
        ManagementResult accepted = await SetAsync(with, "authz.roles", "Allow");

        Assert.False(refused.Succeeded);
        Assert.Contains("super admin", Assert.Single(refused.Errors), StringComparison.Ordinal);
        Assert.True(accepted.Succeeded);
        Assert.True((await SetAsync(without, "authz.roles")).Succeeded); // clearing is always allowed
    }

    /// <summary>
    ///   The change is stored before the caller's token is cancelled; the cache is invalidated anyway, so the next
    ///   request does not keep the old assignments.
    /// </summary>
    [Fact]
    public async Task Cancelling_after_the_change_is_stored_still_invalidates_the_cache()
    {
        using CancellationTokenSource cancellation = new();
        CancellingStore store = new(new InMemoryResourcePolicyStore(), cancellation);
        await using TestApp app = await StartAsync(store);
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read");
        HttpClient client = app.CreateClient(user);
        Assert.Equal(HttpStatusCode.OK, await client.GetStatusAsync("/Orders")); // caches the empty assignments

        ManagementResult result = await app.WithScopeAsync(s =>
            s.GetRequiredService<IResourcePolicyManagementService>().SetPoliciesAsync("orders", ["Deny"], cancellation.Token));

        Assert.True(result.Succeeded);
        Assert.True(cancellation.IsCancellationRequested);
        Assert.Equal(HttpStatusCode.Forbidden, await client.GetStatusAsync("/Orders"));
    }

    [Fact]
    public async Task Custom_stores_get_the_management_service()
    {
        InMemoryResourcePolicyStore store = new();
        await using TestApp app = await StartAsync(store);

        Assert.True((await SetAsync(app, "orders", "Allow")).Succeeded);
        Assert.Equal(1, store.Writes);
    }

    private static Task<ManagementResult> SetAsync(TestApp app, string resource, params string[] policies) =>
        app.WithScopeAsync(s => s.GetRequiredService<IResourcePolicyManagementService>().SetPoliciesAsync(resource, policies));

    private static Task<TestApp> StartAsync(
        IResourcePolicyStore? store = null,
        Action<DynamicAuthorizationOptions>? configure = null,
        string[]? assignable = null,
        bool dashboard = false) =>
        TestApp.StartAsync(o =>
        {
            o.Dashboard = dashboard;
            o.Authorization = a =>
            {
                foreach (string name in assignable ?? ["Allow", "Deny", "RequireMfa"])
                {
                    a.AddAssignablePolicy(name);
                }

                configure?.Invoke(a);
            };
            o.Services = s =>
            {
                s.AddAuthorizationBuilder()
                    .AddPolicy("Allow", p => p.RequireAssertion(_ => true))
                    .AddPolicy("Deny", p => p.RequireAssertion(_ => false))
                    .AddPolicy("RequireMfa", p => p.RequireClaim("amr", "mfa"))
                    .AddPolicy("WithScheme", p => p.AddAuthenticationSchemes(TestAuthHandler.SchemeName).RequireAuthenticatedUser())
                    .AddPolicy("Recursive", p => p.RequireAuthenticatedUser().AddRequirements(new DynamicPermissionRequirement()));
                if (store is not null)
                {
                    s.AddSingleton(store);
                }
            };
        });

    /// <summary>
    ///   Cancels the caller's token once a change is stored.
    /// </summary>
    private sealed class CancellingStore(InMemoryResourcePolicyStore inner, CancellationTokenSource cancellation) : IResourcePolicyStore
    {
        public Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetAssignmentsAsync(CancellationToken cancellationToken = default) =>
            inner.GetAssignmentsAsync(cancellationToken);

        public async Task SetPoliciesAsync(string resource, IEnumerable<string> policyNames, CancellationToken cancellationToken = default)
        {
            await inner.SetPoliciesAsync(resource, policyNames, cancellationToken);
            await cancellation.CancelAsync();
        }
    }
}
