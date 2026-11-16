using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace DynamicAuthorization.AspNetCore.Management;

/// <summary>
///   Manages resource policies over the registered <see cref="IResourcePolicyStore"/>, validating changes against the
///   catalog and the registered policies, and invalidating the cache after they are stored.
/// </summary>
internal sealed class ResourcePolicyManagementService(
    IResourcePolicyStore store,
    IPermissionCatalogProvider catalogProvider,
    AssignablePolicyRegistry registry,
    IAuthorizationPolicyProvider policyProvider,
    IDynamicAuthorizationCache cache,
    IOptions<DynamicAuthorizationOptions> options) : IResourcePolicyManagementService
{
    /// <summary>
    ///   The prefix of the resources of the dashboard's own pages.
    /// </summary>
    internal const string DashboardResourcePrefix = "authz.";

    public async Task<ResourcePolicyAssignments> GetAssignmentsAsync(CancellationToken cancellationToken = default)
    {
        IReadOnlyDictionary<string, IReadOnlySet<string>> assignments = await store.GetAssignmentsAsync(cancellationToken).ConfigureAwait(false);
        Dictionary<string, (string DisplayName, int Count)> resources = GetResources();

        List<ResourcePolicySummary> known = [];
        foreach ((string resource, (string displayName, int count)) in resources)
        {
            known.Add(Summarize(resource, displayName, count, assignments.GetValueOrDefault(resource)));
        }

        List<ResourcePolicySummary> orphaned = [];
        foreach ((string resource, IReadOnlySet<string> policies) in assignments)
        {
            if (policies.Count > 0 && !resources.ContainsKey(resource))
            {
                orphaned.Add(Summarize(resource, resource, 0, policies));
            }
        }

        return new ResourcePolicyAssignments(
            registry.Policies,
            [.. known.OrderBy(r => r.DisplayName, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.Resource, StringComparer.Ordinal)],
            [.. orphaned.OrderBy(r => r.Resource, StringComparer.Ordinal)]);
    }

    public async Task<ManagementResult> SetPoliciesAsync(string resource, IEnumerable<string> policyNames, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policyNames);
        if (string.IsNullOrWhiteSpace(resource))
        {
            return ManagementResult.Fail("A resource is required.");
        }

        resource = resource.Trim();
        List<string> names = [.. policyNames.Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim()).Distinct(StringComparer.OrdinalIgnoreCase)];

        // Clearing is always allowed, so that assignments of resources that no longer exist can be removed.
        if (names.Count > 0)
        {
            List<string> errors = await ValidateAsync(resource, names, cancellationToken).ConfigureAwait(false);
            if (errors.Count > 0)
            {
                return ManagementResult.Fail(errors);
            }
        }

        await store.SetPoliciesAsync(resource, names, cancellationToken).ConfigureAwait(false);

        // The change is stored, so the invalidation is not left to the caller's cancellation.
        await cache.InvalidateResourcePoliciesAsync(CancellationToken.None).ConfigureAwait(false);

        return ManagementResult.Ok();
    }

    private async Task<List<string>> ValidateAsync(string resource, List<string> names, CancellationToken cancellationToken)
    {
        if (!GetResources().ContainsKey(resource))
        {
            return [$"'{resource}' is not a resource with permission-checked endpoints, so policies cannot be assigned to it."];
        }

        DynamicAuthorizationOptions settings = options.Value;
        if (resource.StartsWith(DashboardResourcePrefix, StringComparison.OrdinalIgnoreCase)
            && settings.SuperAdminUsers.Count == 0
            && settings.SuperAdminRoles.Count == 0)
        {
            return [
                $"Policies cannot be assigned to the dashboard resource '{resource}' while no super admin is configured: a policy " +
                $"that never passes would lock everyone out of the dashboard. Add a user to {nameof(DynamicAuthorizationOptions.SuperAdminUsers)} " +
                $"or a role to {nameof(DynamicAuthorizationOptions.SuperAdminRoles)} first.",
            ];
        }

        IReadOnlyDictionary<string, IReadOnlySet<string>> assignments = await store.GetAssignmentsAsync(cancellationToken).ConfigureAwait(false);
        IReadOnlySet<string>? current = assignments.GetValueOrDefault(resource);
        List<string> errors = [];
        foreach (string name in names)
        {
            bool alreadyAssigned = current?.Contains(name) == true;
            if (!registry.IsRegistered(name))
            {
                // A policy that is no longer registered may stay assigned, skipped, but not be added.
                if (!alreadyAssigned)
                {
                    errors.Add($"The policy '{name}' is not assignable. Register it with {nameof(DynamicAuthorizationOptions.AddAssignablePolicy)}.");
                }

                continue;
            }

            if (alreadyAssigned)
            {
                continue;
            }

            AuthorizationPolicy? policy = await policyProvider.GetPolicyAsync(name).ConfigureAwait(false);
            if (policy is null)
            {
                errors.Add($"The policy '{name}' is registered as assignable but is not defined.");
            }
            else if (policy.AuthenticationSchemes.Count > 0)
            {
                errors.Add($"The policy '{name}' names authentication schemes, which an assigned policy cannot authenticate with.");
            }
            else if (policy.Requirements.Any(r => r is DynamicPermissionRequirement))
            {
                errors.Add($"The policy '{name}' requires a dynamic permission, which cannot be evaluated while a permission is checked.");
            }
        }

        return errors;
    }

    private ResourcePolicySummary Summarize(string resource, string displayName, int endpointCount, IReadOnlySet<string>? policies)
    {
        IEnumerable<string> ordered = (policies ?? Enumerable.Empty<string>()).Order(StringComparer.OrdinalIgnoreCase);
        return new ResourcePolicySummary(
            resource,
            displayName,
            endpointCount,
            [.. ordered.Where(registry.IsRegistered)],
            [.. ordered.Where(p => !registry.IsRegistered(p))]);
    }

    /// <summary>
    ///   Gets the resources with permission-checked endpoints, keyed ignoring case, with their display name and number
    ///   of endpoints. Controllers and pages name a resource before Minimal APIs do.
    /// </summary>
    private Dictionary<string, (string DisplayName, int Count)> GetResources()
    {
        Dictionary<string, (string DisplayName, int Count)> resources = [with(StringComparer.OrdinalIgnoreCase)];
        foreach (IGrouping<string, EndpointAuthorizationInfo> group in catalogProvider.GetCatalog().Endpoints
            .Where(e => e is { Protection: EndpointProtection.DynamicPermission, Resource: not null })
            .GroupBy(e => e.Resource!, StringComparer.OrdinalIgnoreCase))
        {
            EndpointAuthorizationInfo named = group.OrderBy(e => e.Source == PermissionSource.Endpoint ? 1 : 0).First();
            resources[group.Key] = (named.Group, group.Select(e => e.Endpoint).Distinct().Count());
        }

        return resources;
    }
}
