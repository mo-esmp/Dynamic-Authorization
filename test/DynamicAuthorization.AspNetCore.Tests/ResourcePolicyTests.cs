using System.Net;
using System.Security.Claims;
using DynamicAuthorization.AspNetCore.Tests.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace DynamicAuthorization.AspNetCore.Tests;

/// <summary>
///   Requests to a permission-checked endpoint must pass the policies admins assigned to the endpoint's resource, on
///   top of its permission. Super admins skip them; endpoints that are not permission-checked, explicit permissions, the
///   secure-content tag helper and checks in code are not affected.
/// </summary>
public sealed class ResourcePolicyTests
{
    private const string MfaHeader = "X-Test-Mfa";

    private static readonly AuthorizationPolicy s_dynamicPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .AddRequirements(new DynamicPermissionRequirement())
        .Build();

    [Fact]
    public async Task A_passing_policy_allows_and_a_failing_one_denies()
    {
        await using TestApp app = await StartAsync();
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read");
        HttpClient client = app.CreateClient(user);

        await AssignAsync(app, "orders", "Allow");
        Assert.Equal(HttpStatusCode.OK, await client.GetStatusAsync("/Orders"));

        await AssignAsync(app, "orders", "Deny");
        Assert.Equal(HttpStatusCode.Forbidden, await client.GetStatusAsync("/Orders"));
    }

    [Fact]
    public async Task Every_assigned_policy_must_pass()
    {
        await using TestApp app = await StartAsync();
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read");
        HttpClient withMfa = app.CreateClient(user);
        withMfa.DefaultRequestHeaders.Add(MfaHeader, "1");

        await AssignAsync(app, "orders", "Allow", "RequireMfa");

        Assert.Equal(HttpStatusCode.OK, await withMfa.GetStatusAsync("/Orders"));
        Assert.Equal(HttpStatusCode.Forbidden, await app.CreateClient(user).GetStatusAsync("/Orders"));
    }

    [Fact]
    public async Task The_permission_is_still_required()
    {
        await using TestApp app = await StartAsync();
        TestUser user = await app.CreateUserWithPermissionsAsync("bob", "reports.read");
        await AssignAsync(app, "orders", "Allow");

        Assert.Equal(HttpStatusCode.Forbidden, await app.CreateClient(user).GetStatusAsync("/Orders"));
    }

    [Fact]
    public async Task Policies_apply_to_every_endpoint_of_the_resource()
    {
        await using TestApp app = await StartAsync();
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read", "orders.update", "orders.export", "items.read");
        HttpClient client = app.CreateClient(user);
        await AssignAsync(app, "ORDERS", "Deny");

        Assert.Equal(HttpStatusCode.Forbidden, await client.GetStatusAsync("/Orders"));
        Assert.Equal(HttpStatusCode.Forbidden, await client.GetStatusAsync("/Orders/Edit/1"));
        Assert.Equal(HttpStatusCode.Forbidden, await client.GetStatusAsync("/Orders/Download"));
        Assert.Equal(HttpStatusCode.Forbidden, await client.GetStatusAsync("/api/v1/orders"));
        Assert.Equal(HttpStatusCode.Forbidden, await client.GetStatusAsync("/api/legacy-orders"));
        Assert.Equal(HttpStatusCode.OK, await client.GetStatusAsync("/api/items"));
    }

    [Fact]
    public async Task Policies_follow_the_resource_of_the_endpoint_not_of_its_permission()
    {
        await using TestApp app = await StartAsync(e => e.MapGet("/api/orders/audit", () => "audit").RequireAuthorization().RequirePermission("reports.export"));
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "reports.export");
        HttpClient client = app.CreateClient(user);

        await AssignAsync(app, "reports", "Deny");
        Assert.Equal(HttpStatusCode.OK, await client.GetStatusAsync("/api/orders/audit"));

        await AssignAsync(app, "orders", "Deny");
        Assert.Equal(HttpStatusCode.Forbidden, await client.GetStatusAsync("/api/orders/audit"));
    }

    [Fact]
    public async Task Policies_apply_under_the_endpoint_convention()
    {
        await using TestApp app = await StartAsync(configure: a => a.Convention = PermissionConvention.Endpoint);
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "mvc::Orders:Index");
        HttpClient client = app.CreateClient(user);
        Assert.Equal(HttpStatusCode.OK, await client.GetStatusAsync("/Orders"));

        await AssignAsync(app, "orders", "Deny");

        Assert.Equal(HttpStatusCode.Forbidden, await client.GetStatusAsync("/Orders"));
    }

    [Fact]
    public async Task Super_admins_skip_assigned_policies()
    {
        await using TestApp app = await StartAsync(configure: a => a.SuperAdminRoles.Add("Admins"));
        TestUser superAdminUser = await app.CreateSuperAdminAsync();
        TestUser superAdminMember = await app.CreateUserAsync("ada", "Admins");
        await AssignAsync(app, "orders", "Deny");

        Assert.Equal(HttpStatusCode.OK, await app.CreateClient(superAdminUser).GetStatusAsync("/Orders"));
        Assert.Equal(HttpStatusCode.OK, await app.CreateClient(superAdminMember).GetStatusAsync("/Orders"));
    }

    [Fact]
    public async Task Super_admins_skip_assigned_policies_with_an_application_checker()
    {
        await using TestApp app = await StartAsync(services: s => s.AddScoped<IPermissionChecker, WrappingChecker>());
        TestUser superAdmin = await app.CreateSuperAdminAsync();
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read");
        await AssignAsync(app, "orders", "Deny");

        Assert.Equal(HttpStatusCode.OK, await app.CreateClient(superAdmin).GetStatusAsync("/Orders"));
        Assert.Equal(HttpStatusCode.Forbidden, await app.CreateClient(user).GetStatusAsync("/Orders"));
    }

    [Fact]
    public async Task Policies_no_longer_registered_are_skipped()
    {
        await using TestApp app = await StartAsync(assignable: ["Allow"]);
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read");
        await AssignAsync(app, "orders", "Deny", "Allow");

        Assert.Equal(HttpStatusCode.OK, await app.CreateClient(user).GetStatusAsync("/Orders"));
    }

    [Fact]
    public async Task Registering_a_policy_again_reactivates_its_assignments()
    {
        await using TestApp app = await StartAsync(assignable: ["Deny"]);
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read");
        await AssignAsync(app, "orders", "Deny");

        Assert.Equal(HttpStatusCode.Forbidden, await app.CreateClient(user).GetStatusAsync("/Orders"));
    }

    /// <summary>
    ///   With no assignable policy, nothing is read: a store that throws on any call is never called.
    /// </summary>
    [Fact]
    public async Task Removing_every_registration_turns_the_feature_off()
    {
        InMemoryResourcePolicyStore store = new();
        await store.SetPoliciesAsync("orders", ["Deny"]);
        store.Throw = true;
        await using TestApp app = await StartAsync(assignable: [], services: s => s.AddSingleton<IResourcePolicyStore>(store));
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read");

        Assert.Equal(HttpStatusCode.OK, await app.CreateClient(user).GetStatusAsync("/Orders"));
        Assert.Equal(0, store.Reads);
    }

    [Theory]
    [InlineData("Missing")]
    [InlineData("Recursive")]
    [InlineData("WithScheme")]
    public async Task Policies_that_cannot_be_evaluated_deny(string policy)
    {
        await using TestApp app = await StartAsync(assignable: ["Missing", "Recursive", "WithScheme"]);
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read");
        await AssignAsync(app, "orders", policy);

        Assert.Equal(HttpStatusCode.Forbidden, await app.CreateClient(user).GetStatusAsync("/Orders"));
    }

    /// <summary>
    ///   A requirement handler that authorizes a policy with the dynamic permission requirement re-enters the permission
    ///   handler while the assigned policy is evaluated. The nested check checks the permission but not the assigned
    ///   policies again, so the request completes.
    /// </summary>
    [Fact]
    public async Task Indirect_recursion_terminates()
    {
        await using TestApp app = await StartAsync();
        TestUser granted = await app.CreateUserWithPermissionsAsync("alice", "orders.read");
        await AssignAsync(app, "orders", "Nested");

        Task<HttpStatusCode> request = app.CreateClient(granted).GetStatusAsync("/Orders");

        Assert.Same(request, await Task.WhenAny(request, Task.Delay(TimeSpan.FromSeconds(10))));
        Assert.Equal(HttpStatusCode.OK, await request);
    }

    [Fact]
    public async Task A_request_evaluates_its_assigned_policies_once()
    {
        PolicyCounter counter = new();
        await using TestApp app = await StartAsync(
            e => e.MapGet("/api/orders/twice", async (HttpContext context, IAuthorizationService authorization) =>
            {
                AuthorizationResult again = await authorization.AuthorizeAsync(context.User, context, s_dynamicPolicy);
                ClaimsPrincipal other = new(context.User.Identities.Select(i => i.Clone()));
                AuthorizationResult otherPrincipal = await authorization.AuthorizeAsync(other, context, s_dynamicPolicy);
                return $"{again.Succeeded} {otherPrincipal.Succeeded}";
            }).RequireAuthorization(),
            services: s => s.AddSingleton(counter));
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read");
        await AssignAsync(app, "orders", "Counted");

        string body = await app.CreateClient(user).GetStringAsync("/api/orders/twice");

        Assert.Equal("True True", body);
        Assert.Equal(2, counter.Count); // the request's principal once, the other principal once
    }

    [Fact]
    public async Task A_failed_evaluation_stays_failed_for_the_request()
    {
        PolicyCounter counter = new() { Results = [false, true] };
        await using TestApp app = await StartAsync(services: s => s.AddSingleton(counter));
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read");
        await AssignAsync(app, "orders", "Counted");
        ClaimsPrincipal principal = await app.CreatePrincipalAsync(user);

        (bool first, bool second, bool otherEndpoint) = await app.WithScopeAsync(async services =>
        {
            DefaultHttpContext context = new() { RequestServices = services, User = principal };
            context.SetEndpoint(app.GetCatalog().FindEndpoint("mvc::Orders:Index")!.Endpoint);
            IAuthorizationService authorization = services.GetRequiredService<IAuthorizationService>();
            bool first = (await authorization.AuthorizeAsync(principal, context, s_dynamicPolicy)).Succeeded;
            bool second = (await authorization.AuthorizeAsync(principal, context, s_dynamicPolicy)).Succeeded;

            // Another endpoint of the same resource, in the same request, is evaluated afresh.
            context.SetEndpoint(app.GetCatalog().FindEndpoint("endpoint:GET /api/v1/orders")!.Endpoint);
            bool otherEndpoint = (await authorization.AuthorizeAsync(principal, context, s_dynamicPolicy)).Succeeded;

            return (first, second, otherEndpoint);
        });

        Assert.False(first);
        Assert.False(second);
        Assert.True(otherEndpoint);
        Assert.Equal(2, counter.Count);
    }

    [Fact]
    public async Task Policies_supplied_by_a_custom_provider_are_evaluated()
    {
        await using TestApp app = await StartAsync(
            assignable: ["ProviderDeny"],
            services: s => s.AddSingleton<IAuthorizationPolicyProvider, CustomPolicyProvider>());
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read");
        await AssignAsync(app, "orders", "ProviderDeny");

        Assert.Equal(HttpStatusCode.Forbidden, await app.CreateClient(user).GetStatusAsync("/Orders"));
    }

    /// <summary>
    ///   The resolver cannot inspect named policies that only a custom provider knows, so it treats endpoints protected
    ///   by them as statically protected: their permission is still checked at runtime, but no policy is assigned to
    ///   them. A documented limitation.
    /// </summary>
    [Fact]
    public async Task Endpoints_guarded_by_a_policy_only_a_custom_provider_knows_get_no_assigned_policies()
    {
        await using TestApp app = await StartAsync(
            e => e.MapGet("/api/provided", () => "provided").RequireAuthorization("ProviderGuarded"),
            services: s => s.AddSingleton<IAuthorizationPolicyProvider, CustomPolicyProvider>());
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "endpoint:GET /api/provided");
        await AssignAsync(app, "provided", "Deny");

        Assert.Equal(EndpointProtection.PolicyOnly, app.GetCatalog().FindEndpoint("endpoint:GET /api/provided")?.Protection);
        Assert.Equal(HttpStatusCode.OK, await app.CreateClient(user).GetStatusAsync("/api/provided"));
    }

    [Fact]
    public async Task Endpoints_that_are_not_permission_checked_are_not_affected()
    {
        await using TestApp app = await StartAsync();
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "reports.schedule");
        HttpClient client = app.CreateClient(user);
        await AssignAsync(app, "public", "Deny");
        await AssignAsync(app, "ignored", "Deny");
        await AssignAsync(app, "schedule", "Deny");

        Assert.Equal(HttpStatusCode.OK, await app.CreateClient().GetStatusAsync("/api/public"));
        Assert.Equal(HttpStatusCode.OK, await client.GetStatusAsync("/api/ignored"));
        Assert.Equal(HttpStatusCode.OK, await client.GetStatusAsync("/api/schedule")); // static policy, explicit permission
    }

    [Fact]
    public async Task Checks_in_code_and_the_tag_helper_are_not_affected()
    {
        await using TestApp app = await StartAsync();
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read");
        await AssignAsync(app, "orders", "Deny");
        ClaimsPrincipal principal = await app.CreatePrincipalAsync(user);

        bool granted = await app.WithScopeAsync(s => s.GetRequiredService<IPermissionChecker>().HasPermissionAsync(principal, "orders.read"));
        string links = await app.CreateClient(user).GetStringAsync("/Links");

        Assert.True(granted);
        Assert.Contains("[orders]", links, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Forbidden, await app.CreateClient(user).GetStatusAsync("/Orders"));
    }

    [Fact]
    public async Task Changes_apply_to_the_next_request()
    {
        await using TestApp app = await StartAsync();
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read");
        HttpClient client = app.CreateClient(user);
        Assert.Equal(HttpStatusCode.OK, await client.GetStatusAsync("/Orders"));

        await AssignAsync(app, "orders", "Deny");
        Assert.Equal(HttpStatusCode.Forbidden, await client.GetStatusAsync("/Orders"));

        await AssignAsync(app, "orders");
        Assert.Equal(HttpStatusCode.OK, await client.GetStatusAsync("/Orders"));
    }

    private static Task<TestApp> StartAsync(
        Action<WebApplication>? endpoints = null,
        Action<DynamicAuthorizationOptions>? configure = null,
        Action<IServiceCollection>? services = null,
        string[]? assignable = null) =>
        TestApp.StartAsync(o =>
        {
            o.Authorization = a =>
            {
                foreach (string name in assignable ?? ["Allow", "Deny", "RequireMfa", "Nested", "Counted"])
                {
                    a.AddAssignablePolicy(name);
                }

                configure?.Invoke(a);
            };
            o.Endpoints = endpoints;
            o.Services = s =>
            {
                s.AddAuthorizationBuilder()
                    .AddPolicy("Allow", p => p.RequireAssertion(_ => true))
                    .AddPolicy("Deny", p => p.RequireAssertion(_ => false))
                    .AddPolicy("RequireMfa", p => p.RequireAssertion(c => c.Resource is HttpContext h && h.Request.Headers.ContainsKey(MfaHeader)))
                    .AddPolicy("Recursive", p => p.RequireAuthenticatedUser().AddRequirements(new DynamicPermissionRequirement()))
                    .AddPolicy("WithScheme", p => p.AddAuthenticationSchemes(TestAuthHandler.SchemeName).RequireAuthenticatedUser())
                    .AddPolicy("Nested", p => p.AddRequirements(new NestedRequirement()))
                    .AddPolicy("Counted", p => p.AddRequirements(new CountedRequirement()));
                s.TryAddSingleton<PolicyCounter>();
                s.AddSingleton<IAuthorizationHandler, NestedHandler>();
                s.AddSingleton<IAuthorizationHandler, CountedHandler>();
                services?.Invoke(s);
            };
        });

    /// <summary>
    ///   Replaces the policies of a resource the way the management service will: through the store, then invalidating
    ///   the cached assignments.
    /// </summary>
    private static Task AssignAsync(TestApp app, string resource, params string[] policies) =>
        app.WithScopeAsync(async s =>
        {
            await s.GetRequiredService<IResourcePolicyStore>().SetPoliciesAsync(resource, policies);
            await s.GetRequiredService<IDynamicAuthorizationCache>().InvalidateResourcePoliciesAsync();
            return true;
        });

    private sealed class NestedRequirement : IAuthorizationRequirement;

    /// <summary>
    ///   Authorizes the request again with a policy that requires the endpoint's permission, from inside an assigned policy.
    /// </summary>
    private sealed class NestedHandler : AuthorizationHandler<NestedRequirement>
    {
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, NestedRequirement requirement)
        {
            HttpContext httpContext = (HttpContext)context.Resource!;
            IAuthorizationService authorization = httpContext.RequestServices.GetRequiredService<IAuthorizationService>();
            if ((await authorization.AuthorizeAsync(context.User, httpContext, s_dynamicPolicy)).Succeeded)
            {
                context.Succeed(requirement);
            }
        }
    }

    private sealed class CountedRequirement : IAuthorizationRequirement;

    /// <summary>
    ///   Counts how often the counted policy is evaluated, and answers from <see cref="Results"/> in turn.
    /// </summary>
    private sealed class PolicyCounter
    {
        private int _count;

        public int Count => Volatile.Read(ref _count);

        public bool[] Results { get; init; } = [true];

        public bool Next()
        {
            int index = Interlocked.Increment(ref _count) - 1;
            return Results[Math.Min(index, Results.Length - 1)];
        }
    }

    private sealed class CountedHandler(PolicyCounter counter) : AuthorizationHandler<CountedRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, CountedRequirement requirement)
        {
            if (counter.Next())
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }

    /// <summary>
    ///   Supplies policies that <see cref="AuthorizationOptions"/> does not know.
    /// </summary>
    private sealed class CustomPolicyProvider(IOptions<AuthorizationOptions> options) : DefaultAuthorizationPolicyProvider(options)
    {
        public override async Task<AuthorizationPolicy?> GetPolicyAsync(string policyName) => policyName switch
        {
            "ProviderDeny" => new AuthorizationPolicyBuilder().AddRequirements(new AssertionRequirement(_ => false)).Build(),
            "ProviderGuarded" => s_dynamicPolicy,
            _ => await base.GetPolicyAsync(policyName),
        };
    }

    /// <summary>
    ///   An application's own checker, which only answers granted or not and delegates the evaluation.
    /// </summary>
    private sealed class WrappingChecker(IServiceProvider services) : IPermissionChecker
    {
        private IPermissionChecker Inner => ActivatorUtilities.CreateInstance<PermissionChecker>(services);

        public Task<bool> HasPermissionAsync(ClaimsPrincipal user, string permission, CancellationToken cancellationToken = default) =>
            Inner.HasPermissionAsync(user, permission, cancellationToken);

        public Task<PermissionEvaluation> EvaluateAsync(ClaimsPrincipal user, string permission, CancellationToken cancellationToken = default) =>
            Inner.EvaluateAsync(user, permission, cancellationToken);

        public Task<PermissionEvaluation> EvaluateUserAsync(string userId, string? userName, string permission, CancellationToken cancellationToken = default) =>
            Inner.EvaluateUserAsync(userId, userName, permission, cancellationToken);
    }
}
