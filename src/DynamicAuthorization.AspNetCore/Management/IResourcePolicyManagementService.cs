namespace DynamicAuthorization.AspNetCore.Management;

/// <summary>
///   Manages the authorization policies assigned to resources, see
///   <see cref="DynamicAuthorizationOptions.AssignablePolicies"/>. Available when an <see cref="IResourcePolicyStore"/>
///   is registered.
/// </summary>
public interface IResourcePolicyManagementService
{
    /// <summary>
    ///   Gets the policies that can be assigned, the permission-checked resources with the policies assigned to them,
    ///   and assignments left behind by resources that no longer exist.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The assignments.</returns>
    Task<ResourcePolicyAssignments> GetAssignmentsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    ///   Replaces the policies assigned to a resource. The change applies to the next request.
    /// </summary>
    /// <param name="resource">The resource key, for example <c>orders</c>.</param>
    /// <param name="policyNames">
    ///   The names of the policies to assign; an empty list removes every assignment of the resource, even one that no
    ///   longer exists. Policies that are no longer registered may be kept or removed, but not added.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The result, with the reasons when the change is refused.</returns>
    Task<ManagementResult> SetPoliciesAsync(string resource, IEnumerable<string> policyNames, CancellationToken cancellationToken = default);
}

/// <summary>
///   The policies that can be assigned and the resources they are assigned to.
/// </summary>
/// <param name="Policies">The assignable policies, in registration order.</param>
/// <param name="Resources">The permission-checked resources, ordered by display name, with their assignments.</param>
/// <param name="Orphaned">Assignments of resources that no longer have permission-checked endpoints.</param>
public sealed record ResourcePolicyAssignments(
    IReadOnlyList<AssignablePolicyDefinition> Policies,
    IReadOnlyList<ResourcePolicySummary> Resources,
    IReadOnlyList<ResourcePolicySummary> Orphaned);

/// <summary>
///   A resource and the policies assigned to it.
/// </summary>
/// <param name="Resource">The resource key, for example <c>orders</c>.</param>
/// <param name="DisplayName">The display name, for example <c>Orders</c>; the key for orphaned assignments.</param>
/// <param name="EndpointCount">The number of permission-checked endpoints of the resource.</param>
/// <param name="Enforced">The assigned policies that are registered and enforced, ordered by name.</param>
/// <param name="Skipped">The assigned policies that are no longer registered and therefore skipped, ordered by name.</param>
public sealed record ResourcePolicySummary(
    string Resource,
    string DisplayName,
    int EndpointCount,
    IReadOnlyList<string> Enforced,
    IReadOnlyList<string> Skipped)
{
    /// <summary>
    ///   Gets a value indicating whether the resource is one of the dashboard's own, which can take policies only while
    ///   a super admin is configured.
    /// </summary>
    public bool IsDashboard => Resource.StartsWith(ResourcePolicyManagementService.DashboardResourcePrefix, StringComparison.OrdinalIgnoreCase);
}
