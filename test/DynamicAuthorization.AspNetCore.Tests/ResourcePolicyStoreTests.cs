using DynamicAuthorization.AspNetCore.EntityFrameworkCore;
using DynamicAuthorization.AspNetCore.Tests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace DynamicAuthorization.AspNetCore.Tests;

/// <summary>
///   The Entity Framework store of the policies assigned to resources. Its table is opt-in, so that applications that
///   don't assign policies get no model change when they upgrade.
/// </summary>
public sealed class ResourcePolicyStoreTests
{
    [Fact]
    public async Task Model_maps_resource_policies_when_enabled()
    {
        await using TestApp app = await TestApp.StartAsync();

        IEntityType entity = await app.WithScopeAsync(s =>
            Task.FromResult(s.GetRequiredService<TestDbContext>().Model.FindEntityType(typeof(ResourcePolicy))!));

        Assert.Equal("AspNetResourcePolicies", entity.GetTableName());
        Assert.Equal(
            [nameof(ResourcePolicy.Resource), nameof(ResourcePolicy.PolicyName)],
            entity.FindPrimaryKey()!.Properties.Select(p => p.Name));
        Assert.Equal(DynamicAuthorizationModelOptions.MaxPermissionLength, entity.FindProperty(nameof(ResourcePolicy.Resource))!.GetMaxLength());
        Assert.Equal(AssignablePolicyDefinition.MaxNameLength, entity.FindProperty(nameof(ResourcePolicy.PolicyName))!.GetMaxLength());
        Assert.Empty(entity.GetForeignKeys());
    }

    [Fact]
    public void Model_does_not_map_resource_policies_unless_enabled()
    {
        using OptedOutDbContext context = new(new DbContextOptionsBuilder<OptedOutDbContext>().UseSqlite("DataSource=:memory:").Options);

        Assert.Null(context.Model.FindEntityType(typeof(ResourcePolicy)));
        Assert.NotNull(context.Model.FindEntityType(typeof(RolePermission<string>)));
    }

    [Fact]
    public void Model_uses_the_configured_table_name_and_schema()
    {
        using RenamedDbContext context = new(new DbContextOptionsBuilder<RenamedDbContext>().UseSqlite("DataSource=:memory:").Options);

        IEntityType entity = context.Model.FindEntityType(typeof(ResourcePolicy))!;

        Assert.Equal("Policies", entity.GetTableName());
        Assert.Equal("authz", entity.GetSchema());
    }

    [Fact]
    public async Task Assignments_are_replaced_per_resource()
    {
        await using TestApp app = await TestApp.StartAsync();

        await SetAsync(app, "orders", "BusinessHours", "RequireMfa");
        await SetAsync(app, "reports", "BusinessHours");
        await SetAsync(app, "orders", "requiremfa", "RequireMfa", " ", "Audit ");
        await SetAsync(app, "reports");
        IReadOnlyDictionary<string, IReadOnlySet<string>> assignments = await GetAsync(app);

        Assert.Equal(["orders"], assignments.Keys);
        Assert.Equal(["Audit", "requiremfa"], assignments["orders"].Order(StringComparer.OrdinalIgnoreCase));
        Assert.Contains("REQUIREMFA", assignments["orders"]);
    }

    [Fact]
    public async Task Resource_keys_are_stored_in_lower_case_and_read_ignoring_case()
    {
        await using TestApp app = await TestApp.StartAsync();

        await SetAsync(app, " Admin.Reports ", "BusinessHours");
        await SetAsync(app, "ADMIN.REPORTS", "RequireMfa");
        IReadOnlyDictionary<string, IReadOnlySet<string>> assignments = await GetAsync(app);

        Assert.Equal(["admin.reports"], assignments.Keys);
        Assert.Equal(["RequireMfa"], assignments["Admin.Reports"]);
    }

    [Fact]
    public async Task Invalid_resources_and_names_are_rejected()
    {
        await using TestApp app = await TestApp.StartAsync();

        await Assert.ThrowsAsync<ArgumentException>(() => SetAsync(app, " ", "BusinessHours"));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            SetAsync(app, new string('r', DynamicAuthorizationModelOptions.MaxPermissionLength + 1), "BusinessHours"));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            SetAsync(app, "orders", new string('p', AssignablePolicyDefinition.MaxNameLength + 1)));
        Assert.Empty(await GetAsync(app));
    }

    /// <summary>
    ///   A replacement deletes and inserts in one transaction, so a reader sees the policies from before or after it,
    ///   never an empty or merged set.
    /// </summary>
    [Fact]
    public async Task Readers_never_observe_a_partial_replacement()
    {
        await using TestApp app = await TestApp.StartAsync(o => o.FileDatabase = true);
        string[] before = ["BusinessHours", "RequireMfa"];
        string[] after = ["Audit"];
        await SetAsync(app, "orders", before);

        Task writer = Task.Run(async () =>
        {
            for (int i = 0; i < 20; i++)
            {
                await SetAsync(app, "orders", i % 2 == 0 ? after : before);
            }
        });
        List<string[]> observed = [];
        while (!writer.IsCompleted)
        {
            IReadOnlyDictionary<string, IReadOnlySet<string>> assignments = await GetAsync(app);
            observed.Add(assignments.TryGetValue("orders", out IReadOnlySet<string>? policies) ? [.. policies.Order(StringComparer.Ordinal)] : []);
        }

        await writer;
        Assert.NotEmpty(observed);
        Assert.All(observed, policies => Assert.True(
            policies.SequenceEqual(before) || policies.SequenceEqual(after),
            $"Observed [{string.Join(", ", policies)}]."));
    }

    [Fact]
    public async Task Concurrent_replacements_leave_the_last_one()
    {
        await using TestApp app = await TestApp.StartAsync(o => o.FileDatabase = true);

        for (int i = 0; i < 10; i++)
        {
            await Task.WhenAll(
                Task.Run(() => SetAsync(app, "orders", "BusinessHours", "Audit")),
                Task.Run(() => SetAsync(app, "orders", "RequireMfa")));

            string[] policies = [.. (await GetAsync(app))["orders"].Order(StringComparer.Ordinal)];
            Assert.True(
                policies.SequenceEqual(["Audit", "BusinessHours"]) || policies.SequenceEqual(["RequireMfa"]),
                $"Observed [{string.Join(", ", policies)}].");
        }
    }

    /// <summary>
    ///   Rows a context tracks, from an earlier replacement in the same scope, do not prevent the next replacement.
    /// </summary>
    [Fact]
    public async Task Replacements_can_be_repeated_in_one_scope()
    {
        await using TestApp app = await TestApp.StartAsync();

        IReadOnlyDictionary<string, IReadOnlySet<string>> assignments = await app.WithScopeAsync(async s =>
        {
            IResourcePolicyStore store = s.GetRequiredService<IResourcePolicyStore>();
            await store.SetPoliciesAsync("orders", ["RequireMfa"]);
            await store.SetPoliciesAsync("orders", ["RequireMfa"]);
            await store.SetPoliciesAsync("orders", ["BusinessHours", "RequireMfa"]);
            return await store.GetAssignmentsAsync();
        });

        Assert.Equal(["BusinessHours", "RequireMfa"], assignments["orders"].Order(StringComparer.Ordinal));
    }

    /// <summary>
    ///   Under READ COMMITTED, deleting no rows takes no row locks, so two first assignments of a resource could both
    ///   commit and leave the union of the two. Replacements run serializable instead.
    /// </summary>
    [Fact]
    public async Task Replacements_run_in_a_serializable_transaction()
    {
        IsolationRecorder recorder = new();
        await using TestApp app = await TestApp.StartAsync(o => o.DbContext = b => b.AddInterceptors(recorder));
        recorder.Levels.Clear(); // creating the database starts transactions of its own

        await SetAsync(app, "orders", "BusinessHours");

        Assert.Equal([System.Data.IsolationLevel.Serializable], recorder.Levels);
    }

    [Fact]
    public async Task Store_explains_how_to_enable_the_table()
    {
        await using SqliteConnection connection = new("DataSource=:memory:");
        await connection.OpenAsync();
        ServiceCollection collection = new();
        collection.AddLogging();
        collection.AddDbContext<OptedOutDbContext>(o => o.UseSqlite(connection));
        collection.AddIdentityCore<IdentityUser>().AddRoles<IdentityRole>().AddEntityFrameworkStores<OptedOutDbContext>();
        collection.AddDynamicAuthorization(o => o.AddAssignablePolicy("BusinessHours")).AddEntityFrameworkStore<OptedOutDbContext>();
        await using ServiceProvider services = collection.BuildServiceProvider();
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<OptedOutDbContext>().Database.EnsureCreatedAsync();
        IResourcePolicyStore store = scope.ServiceProvider.GetRequiredService<IResourcePolicyStore>();

        InvalidOperationException read = await Assert.ThrowsAsync<InvalidOperationException>(() => store.GetAssignmentsAsync());
        InvalidOperationException write = await Assert.ThrowsAsync<InvalidOperationException>(() => store.SetPoliciesAsync("orders", ["BusinessHours"]));

        Assert.Contains("ResourcePolicies = true", read.Message, StringComparison.Ordinal);
        Assert.Contains("migration", read.Message, StringComparison.Ordinal);
        Assert.Equal(read.Message, write.Message);
    }

    private static Task SetAsync(TestApp app, string resource, params string[] policies) =>
        app.WithScopeAsync(async s =>
        {
            await s.GetRequiredService<IResourcePolicyStore>().SetPoliciesAsync(resource, policies);
            return true;
        });

    private static Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetAsync(TestApp app) =>
        app.WithScopeAsync(s => s.GetRequiredService<IResourcePolicyStore>().GetAssignmentsAsync());

    /// <summary>
    ///   Records the isolation level of the transactions a context starts.
    /// </summary>
    private sealed class IsolationRecorder : Microsoft.EntityFrameworkCore.Diagnostics.DbTransactionInterceptor
    {
        public List<System.Data.IsolationLevel> Levels { get; } = [];

        public override ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbTransaction>> TransactionStartingAsync(
            System.Data.Common.DbConnection connection,
            Microsoft.EntityFrameworkCore.Diagnostics.TransactionStartingEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbTransaction> result,
            CancellationToken cancellationToken = default)
        {
            lock (Levels)
            {
                Levels.Add(eventData.IsolationLevel);
            }

            return base.TransactionStartingAsync(connection, eventData, result, cancellationToken);
        }
    }

    private sealed class OptedOutDbContext(DbContextOptions<OptedOutDbContext> options) : IdentityDbContext(options)
    {
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.EnableDynamicAuthorization();
        }
    }

    private sealed class RenamedDbContext(DbContextOptions<RenamedDbContext> options) : IdentityDbContext(options)
    {
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.EnableDynamicAuthorization(o =>
            {
                o.ResourcePolicies = true;
                o.ResourcePolicyTableName = "Policies";
                o.Schema = "authz";
            });
        }
    }
}
