namespace DynamicAuthorization.AspNetCore.Tests.Infrastructure;

/// <summary>
///   A resource policy store kept in memory, which counts its calls and can be told to fail, for tests that are not
///   about the Entity Framework store.
/// </summary>
internal sealed class InMemoryResourcePolicyStore : IResourcePolicyStore
{
    private readonly Lock _lock = new();
    private readonly Dictionary<string, HashSet<string>> _assignments = [with(StringComparer.OrdinalIgnoreCase)];
    private int _reads;
    private int _writes;

    public int Reads => Volatile.Read(ref _reads);

    public int Writes => Volatile.Read(ref _writes);

    /// <summary>
    ///   Gets or sets a value indicating whether every call throws, to prove that a code path never reaches the store.
    /// </summary>
    public bool Throw { get; set; }

    public Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetAssignmentsAsync(CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _reads);
        ThrowIfRequested();

        lock (_lock)
        {
            Dictionary<string, IReadOnlySet<string>> copy = [with(StringComparer.OrdinalIgnoreCase)];
            foreach ((string resource, HashSet<string> policies) in _assignments)
            {
                copy[resource] = new HashSet<string>(policies, StringComparer.OrdinalIgnoreCase);
            }

            return Task.FromResult<IReadOnlyDictionary<string, IReadOnlySet<string>>>(copy);
        }
    }

    public Task SetPoliciesAsync(string resource, IEnumerable<string> policyNames, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(resource);
        ArgumentNullException.ThrowIfNull(policyNames);
        Interlocked.Increment(ref _writes);
        ThrowIfRequested();

        lock (_lock)
        {
            HashSet<string> policies = new(policyNames, StringComparer.OrdinalIgnoreCase);
            if (policies.Count == 0)
            {
                _assignments.Remove(resource);
            }
            else
            {
                _assignments[resource] = policies;
            }
        }

        return Task.CompletedTask;
    }

    private void ThrowIfRequested()
    {
        if (Throw)
        {
            throw new InvalidOperationException("The resource policy store was called.");
        }
    }
}
