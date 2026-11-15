namespace DynamicAuthorization.AspNetCore;

/// <summary>
///   Implemented by an <see cref="IDynamicAuthorizationCacheStore"/> that also keeps the policies assigned to
///   resources, which are cached as one entry. A cache store that does not implement it still works: the assignments
///   are then cached in the memory of the instance, so an invalidation does not reach the other instances until their
///   copy expires after <see cref="DynamicAuthorizationOptions.CacheDuration"/>.
/// </summary>
/// <remarks>
///   The contract of <see cref="IDynamicAuthorizationCacheStore"/> applies: concurrent reads that miss share one call of
///   the load; invalidating the entry while its load runs discards the result of that load; a failed load is not kept;
///   a load runs to completion when the caller that started it is cancelled; and
///   <see cref="IDynamicAuthorizationCacheStore.InvalidateAllAsync"/> removes the entry too.
/// </remarks>
public interface IResourcePolicyCacheStore
{
    /// <summary>
    ///   Gets the policies assigned to resources, loading them with <paramref name="load"/> when they are not cached.
    /// </summary>
    /// <param name="load">Loads every assignment, keyed by resource.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The assignments and when the cached entry expires.</returns>
    ValueTask<CachedValue<IReadOnlyDictionary<string, IReadOnlySet<string>>>> GetResourcePoliciesAsync(
        Func<CancellationToken, Task<IReadOnlyDictionary<string, IReadOnlySet<string>>>> load,
        CancellationToken cancellationToken);

    /// <summary>
    ///   Removes the cached assignments.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    ValueTask InvalidateResourcePoliciesAsync(CancellationToken cancellationToken);
}
