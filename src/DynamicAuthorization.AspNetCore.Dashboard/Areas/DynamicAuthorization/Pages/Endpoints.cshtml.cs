using System.ComponentModel;
using DynamicAuthorization.AspNetCore.Management;
using Microsoft.AspNetCore.Mvc;

namespace DynamicAuthorization.AspNetCore.Dashboard.Pages;

[DisplayName("Endpoints")]
[PermissionResource(DashboardConstants.EndpointsResource, DisplayName = "Dashboard / Endpoints")]
internal sealed class EndpointsModel : DashboardPageModel
{
    private ILookup<string, RoleReference> _grants = Array.Empty<RoleReference>().ToLookup(r => r.Id);

    [BindProperty(SupportsGet = true)]
    public string? Protection { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? Source { get; set; }

    [BindProperty(SupportsGet = true, Name = "q")]
    public string? Query { get; set; }

    public IReadOnlyList<EndpointAuthorizationInfo> Endpoints { get; private set; } = [];

    /// <summary>
    ///   Gets a value indicating whether policies can be assigned to resources, which adds the policies column.
    /// </summary>
    public bool ShowPolicies => _policies is not null;

    private Dictionary<string, ResourcePolicySummary>? _policies;

    public IEnumerable<RoleReference> GetGrantedRoles(EndpointAuthorizationInfo endpoint) =>
        endpoint.Permission is null ? [] : _grants[endpoint.Permission.Permission];

    /// <summary>
    ///   Gets the policies assigned to the resource of a permission-checked endpoint.
    /// </summary>
    public ResourcePolicySummary? GetPolicies(EndpointAuthorizationInfo endpoint) =>
        endpoint is { Protection: EndpointProtection.DynamicPermission, Resource: { } resource } && _policies is not null
            ? _policies.GetValueOrDefault(resource)
            : null;

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        Endpoints = GetService<IPermissionCatalogProvider>().GetCatalog().Endpoints;
        IReadOnlyList<RoleGrant> grants = await GetService<IRoleManagementService>().GetGrantsAsync(cancellationToken);
        _grants = grants.ToLookup(g => g.Permission, g => new RoleReference(g.RoleId, g.RoleName), StringComparer.OrdinalIgnoreCase);
        _policies = (await GetResourcePolicyAssignmentsAsync(cancellationToken))?.Resources
            .ToDictionary(r => r.Resource, StringComparer.OrdinalIgnoreCase);
    }
}
