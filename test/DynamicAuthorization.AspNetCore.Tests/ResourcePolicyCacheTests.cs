using DynamicAuthorization.AspNetCore.HybridCache;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace DynamicAuthorization.AspNetCore.Tests;

/// <summary>
///   The policies assigned to resources are cached as one entry with the contract of user roles and role permissions:
///   concurrent misses share one load, an invalidation during a load discards its result, failed loads are not kept, a
///   cancelled caller does not cancel the load, and an invalidation on one instance reaches the others. Cache stores
///   that predate the entry still get it cached, in the memory of the instance.
/// </summary>
public sealed class ResourcePolicyCacheTests
{
    public static TheoryData<CacheKind> Kinds => [CacheKind.Memory, CacheKind.Hybrid];

    [Theory]
    [MemberData(nameof(Kinds))]
    public async Task Assignments_are_loaded_once_and_cached(CacheKind kind)
    {
        AssignmentGate gate = new();
        await using ServiceProvider services = BuildServices(gate, kind);

        IReadOnlyDictionary<string, IReadOnlySet<string>> first = await ReadAsync(services);
        IReadOnlyDictionary<string, IReadOnlySet<string>> second = await ReadAsync(services);

        Assert.Equal(["BusinessHours"], first["ORDERS"]);
        Assert.Contains("businesshours", second["orders"]);
        Assert.Equal(1, gate.Calls);
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public async Task Concurrent_misses_share_one_load(CacheKind kind)
    {
        AssignmentGate gate = new() { Gated = true };
        await using ServiceProvider services = BuildServices(gate, kind);

        Task<IReadOnlyDictionary<string, IReadOnlySet<string>>>[] reads = [.. Enumerable.Range(0, 16).Select(_ => ReadAsync(services))];
        await gate.Started;
        gate.Release();

        Assert.All(await Task.WhenAll(reads), r => Assert.Equal(["BusinessHours"], r["orders"]));
        Assert.Equal(1, gate.Calls);
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public async Task Invalidating_during_a_load_discards_its_result(CacheKind kind)
    {
        AssignmentGate gate = new() { Gated = true };
        await using ServiceProvider services = BuildServices(gate, kind);

        Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> pending = ReadAsync(services);
        await gate.Started;
        await services.GetRequiredService<IDynamicAuthorizationCache>().InvalidateResourcePoliciesAsync();
        gate.Policies = ["RequireMfa"];
        gate.Release();

        // The read that started before the change still sees what it loaded; the next one reloads.
        Assert.Equal(["BusinessHours"], (await pending)["orders"]);
        Assert.Equal(["RequireMfa"], (await ReadAsync(services))["orders"]);
        Assert.Equal(2, gate.Calls);
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public async Task Failed_loads_are_not_cached(CacheKind kind)
    {
        AssignmentGate gate = new() { Fail = true };
        await using ServiceProvider services = BuildServices(gate, kind);

        await Assert.ThrowsAsync<InvalidOperationException>(() => ReadAsync(services));
        gate.Fail = false;

        Assert.Equal(["BusinessHours"], (await ReadAsync(services))["orders"]);
        Assert.Equal(2, gate.Calls);
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public async Task Cancelling_one_caller_does_not_fail_the_shared_load(CacheKind kind)
    {
        AssignmentGate gate = new() { Gated = true };
        await using ServiceProvider services = BuildServices(gate, kind);
        using CancellationTokenSource cancellation = new();

        Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> cancelled = ReadAsync(services, cancellation.Token);
        await gate.Started;
        Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> other = ReadAsync(services);
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        gate.Release();

        Assert.Equal(["BusinessHours"], (await other)["orders"]);
        Assert.Equal(1, gate.Calls);
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public async Task Invalidating_everything_drops_the_assignments(CacheKind kind)
    {
        AssignmentGate gate = new();
        await using ServiceProvider services = BuildServices(gate, kind);
        await ReadAsync(services);
        gate.Policies = ["RequireMfa"];

        await services.GetRequiredService<IDynamicAuthorizationCache>().InvalidateAllAsync();

        Assert.Equal(["RequireMfa"], (await ReadAsync(services))["orders"]);
        Assert.Equal(2, gate.Calls);
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public async Task Invalidating_roles_or_users_keeps_the_assignments(CacheKind kind)
    {
        AssignmentGate gate = new();
        await using ServiceProvider services = BuildServices(gate, kind);
        await ReadAsync(services);
        IDynamicAuthorizationCache cache = services.GetRequiredService<IDynamicAuthorizationCache>();

        await cache.InvalidateRoleAsync("role0");
        await cache.InvalidateUserAsync("user");
        await ReadAsync(services);

        Assert.Equal(1, gate.Calls);
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public async Task Disabling_the_cache_reads_the_store_every_time(CacheKind kind)
    {
        AssignmentGate gate = new();
        await using ServiceProvider services = BuildServices(gate, kind, o => o.CacheDuration = TimeSpan.Zero);

        await ReadAsync(services);
        await ReadAsync(services);

        Assert.Equal(2, gate.Calls);
    }

    [Fact]
    public async Task Invalidations_change_the_cache_version()
    {
        AssignmentGate gate = new();
        await using ServiceProvider services = BuildServices(gate, CacheKind.Memory);
        DynamicAuthorizationCache cache = services.GetRequiredService<DynamicAuthorizationCache>();
        long before = cache.Version;

        await cache.InvalidateResourcePoliciesAsync();

        Assert.NotEqual(before, cache.Version);
    }

    /// <summary>
    ///   A cache store written before resource policies existed does not cache them; the library keeps them in the
    ///   memory of the instance instead, so the store of record is not read on every request.
    /// </summary>
    [Fact]
    public async Task Cache_stores_without_the_entry_get_it_cached_in_memory()
    {
        AssignmentGate gate = new();
        await using ServiceProvider services = BuildServices(gate, CacheKind.Memory, configureServices: s =>
            s.AddSingleton<IDynamicAuthorizationCacheStore>(sp => new DelegatingCacheStore(
                new MemoryDynamicAuthorizationCacheStore(sp.GetRequiredService<IOptions<DynamicAuthorizationOptions>>()))));
        IDynamicAuthorizationCache cache = services.GetRequiredService<IDynamicAuthorizationCache>();

        await ReadAsync(services);
        await ReadAsync(services);
        Assert.Equal(1, gate.Calls);

        await cache.InvalidateResourcePoliciesAsync();
        await ReadAsync(services);
        Assert.Equal(2, gate.Calls);

        await cache.InvalidateAllAsync();
        await ReadAsync(services);
        Assert.Equal(3, gate.Calls);
    }

    [Fact]
    public async Task Other_cache_implementations_invalidate_everything_for_resource_policies()
    {
        RecordingCache cache = new();

        await ((IDynamicAuthorizationCache)cache).InvalidateResourcePoliciesAsync();

        Assert.Equal(1, cache.InvalidatedAll);
    }

    /// <summary>
    ///   Without an invalidation, an instance whose local copy expired reads the shared entry again rather than the
    ///   store; an invalidation on another instance makes it load again.
    /// </summary>
    [Fact]
    public async Task Instances_sharing_a_distributed_cache_see_each_others_invalidations()
    {
        AssignmentGate gate = new();
        SharedDistributedCache distributedCache = new();
        TimeSpan local = TimeSpan.FromMilliseconds(200);
        await using ServiceProvider first = BuildServices(gate, CacheKind.Hybrid, distributedCache: distributedCache, localCacheDuration: local);
        await using ServiceProvider second = BuildServices(gate, CacheKind.Hybrid, distributedCache: distributedCache, localCacheDuration: local);
        Assert.Equal(["BusinessHours"], (await ReadAsync(first))["orders"]);
        await distributedCache.WaitForAsync("dynamic-authorization:resource-policies");

        gate.Policies = ["RequireMfa"];
        await Task.Delay(local * 2);
        Assert.Equal(["BusinessHours"], (await ReadAsync(first))["orders"]);
        Assert.Equal(1, gate.Calls);

        await second.GetRequiredService<IDynamicAuthorizationCache>().InvalidateResourcePoliciesAsync();

        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        while ((await ReadAsync(first))["orders"].Contains("BusinessHours"))
        {
            await Task.Delay(50, timeout.Token);
        }

        Assert.Equal(2, gate.Calls);
    }

    /// <summary>
    ///   The entry goes through the distributed cache as JSON: another instance reads it instead of loading, and still
    ///   compares resources and names ignoring case.
    /// </summary>
    [Fact]
    public async Task Instances_sharing_a_distributed_cache_share_the_assignments()
    {
        AssignmentGate gate = new();
        SharedDistributedCache distributedCache = new();
        await using ServiceProvider first = BuildServices(gate, CacheKind.Hybrid, distributedCache: distributedCache);
        await using ServiceProvider second = BuildServices(gate, CacheKind.Hybrid, distributedCache: distributedCache);
        await ReadAsync(first);
        await distributedCache.WaitForAsync("dynamic-authorization:resource-policies");

        IReadOnlyDictionary<string, IReadOnlySet<string>> shared = await ReadAsync(second);

        Assert.Equal(1, gate.Calls);
        Assert.Contains("BUSINESSHOURS", shared["Orders"]);
    }

    private static async Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> ReadAsync(ServiceProvider services, CancellationToken cancellationToken = default) =>
        (await services.GetRequiredService<DynamicAuthorizationCache>().GetResourcePoliciesAsync(cancellationToken)).Value;

    private static ServiceProvider BuildServices(
        AssignmentGate gate,
        CacheKind kind,
        Action<DynamicAuthorizationOptions>? configure = null,
        Action<IServiceCollection>? configureServices = null,
        IDistributedCache? distributedCache = null,
        TimeSpan? localCacheDuration = null)
    {
        ServiceCollection services = new();
        services.AddLogging();
        configureServices?.Invoke(services);
        IDynamicAuthorizationBuilder builder = services.AddDynamicAuthorization(o =>
        {
            o.AddAssignablePolicy("BusinessHours");
            configure?.Invoke(o);
        });
        if (kind == CacheKind.Hybrid)
        {
            if (distributedCache is not null)
            {
                services.AddSingleton(distributedCache);
            }

            builder.UseHybridCache(o => o.LocalCacheDuration = localCacheDuration ?? o.LocalCacheDuration);
        }

        services.AddSingleton(gate);
        services.AddScoped<IResourcePolicyStore, GatedResourcePolicyStore>();

        return services.BuildServiceProvider();
    }

    /// <summary>
    ///   What the store returns for <c>orders</c>, how often it was read, and whether reads wait, or fail.
    /// </summary>
    private sealed class AssignmentGate
    {
        private readonly TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public bool Gated { get; init; }

        public bool Fail { get; set; }

        public string[] Policies { get; set; } = ["BusinessHours"];

        public Task Started => _started.Task;

        public void Release() => _gate.TrySetResult();

        public async Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> LoadAsync()
        {
            Interlocked.Increment(ref _calls);
            string[] policies = Policies;
            _started.TrySetResult();
            if (Gated)
            {
                await _gate.Task;
            }

            if (Fail)
            {
                throw new InvalidOperationException("The store failed.");
            }

            return new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal) { ["orders"] = new HashSet<string>(policies, StringComparer.Ordinal) };
        }
    }

    private sealed class GatedResourcePolicyStore(AssignmentGate gate) : IResourcePolicyStore
    {
        public Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetAssignmentsAsync(CancellationToken cancellationToken = default) => gate.LoadAsync();

        public Task SetPoliciesAsync(string resource, IEnumerable<string> policyNames, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    /// <summary>
    ///   A distributed cache shared by several service providers. HybridCache does not use a bare
    ///   <see cref="MemoryDistributedCache"/> as its second level, so it is wrapped.
    /// </summary>
    private sealed class SharedDistributedCache : IDistributedCache
    {
        private readonly MemoryDistributedCache _inner = new(Options.Create(new MemoryDistributedCacheOptions()));

        public async Task WaitForAsync(string key)
        {
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
            while (await _inner.GetAsync(key, timeout.Token) is null)
            {
                await Task.Delay(20, timeout.Token);
            }
        }

        public byte[]? Get(string key) => _inner.Get(key);

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => _inner.GetAsync(key, token);

        public void Refresh(string key) => _inner.Refresh(key);

        public Task RefreshAsync(string key, CancellationToken token = default) => _inner.RefreshAsync(key, token);

        public void Remove(string key) => _inner.Remove(key);

        public Task RemoveAsync(string key, CancellationToken token = default) => _inner.RemoveAsync(key, token);

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => _inner.Set(key, value, options);

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default) =>
            _inner.SetAsync(key, value, options, token);
    }

    /// <summary>
    ///   A cache store that only implements the original contract.
    /// </summary>
    private sealed class DelegatingCacheStore(IDynamicAuthorizationCacheStore inner) : IDynamicAuthorizationCacheStore
    {
        public ValueTask<CachedValue<IReadOnlyList<RoleReference>>> GetUserRolesAsync(
            string userId, Func<CancellationToken, Task<IReadOnlyList<RoleReference>>> load, CancellationToken cancellationToken) =>
            inner.GetUserRolesAsync(userId, load, cancellationToken);

        public ValueTask<CachedValue<IReadOnlyDictionary<string, IReadOnlySet<string>>>> GetRolePermissionsAsync(
            IReadOnlyList<string> roleIds,
            Func<IReadOnlyList<string>, CancellationToken, Task<IReadOnlyDictionary<string, IReadOnlySet<string>>>> load,
            CancellationToken cancellationToken) =>
            inner.GetRolePermissionsAsync(roleIds, load, cancellationToken);

        public ValueTask InvalidateUserAsync(string userId, CancellationToken cancellationToken) => inner.InvalidateUserAsync(userId, cancellationToken);

        public ValueTask InvalidateRoleAsync(string roleId, CancellationToken cancellationToken) => inner.InvalidateRoleAsync(roleId, cancellationToken);

        public ValueTask InvalidateAllAsync(CancellationToken cancellationToken) => inner.InvalidateAllAsync(cancellationToken);
    }

    /// <summary>
    ///   An application's own cache, written before resource policies existed.
    /// </summary>
    private sealed class RecordingCache : IDynamicAuthorizationCache
    {
        public int InvalidatedAll { get; private set; }

        public ValueTask InvalidateUserAsync(string userId, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;

        public ValueTask InvalidateRoleAsync(string roleId, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;

        public ValueTask InvalidateAllAsync(CancellationToken cancellationToken = default)
        {
            InvalidatedAll++;
            return ValueTask.CompletedTask;
        }
    }
}
