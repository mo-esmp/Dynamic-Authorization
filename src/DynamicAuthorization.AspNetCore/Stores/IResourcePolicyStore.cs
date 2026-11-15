namespace DynamicAuthorization.AspNetCore;

/// <summary>
///   Stores the authorization policies assigned to resources, see
///   <see cref="DynamicAuthorizationOptions.AssignablePolicies"/>. Required only when policies are assignable.
/// </summary>
/// <remarks>
///   Resource keys and policy names are compared ignoring case. Permission checks read every assignment at once and
///   cache them, so the store is read at most once per <see cref="DynamicAuthorizationOptions.CacheDuration"/> per
///   instance.
/// </remarks>
public interface IResourcePolicyStore
{
    /// <summary>
    ///   Gets every assignment.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    ///   The names of the policies assigned to each resource, keyed by resource. Resources without policies are
    ///   omitted. Keys and names are compared ignoring case.
    /// </returns>
    Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetAssignmentsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    ///   Replaces the policies assigned to a resource. Readers never observe a partial replacement.
    /// </summary>
    /// <param name="resource">The resource key, for example <c>orders</c>.</param>
    /// <param name="policyNames">The names of the policies to assign; an empty list removes every assignment of the resource.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A task that completes when the replacement is stored.</returns>
    Task SetPoliciesAsync(string resource, IEnumerable<string> policyNames, CancellationToken cancellationToken = default);
}
