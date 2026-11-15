using System.ComponentModel;
using DynamicAuthorization.AspNetCore.Management;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace DynamicAuthorization.AspNetCore.Dashboard.Pages.Policies;

// The page requires authz.policies.update.
[DisplayName("Edit policies")]
[PermissionResource(DashboardConstants.PoliciesResource, DisplayName = "Dashboard / Policies")]
internal sealed class EditModel : DashboardPageModel
{
    [BindProperty]
    public List<string> PolicyNames { get; set; } = [];

    public ResourcePolicySummary Resource { get; private set; } = null!;

    public IReadOnlyList<AssignablePolicyDefinition> Policies { get; private set; } = [];

    public bool NeedsSuperAdmin { get; private set; }

    public async Task<IActionResult> OnGetAsync(string resource, CancellationToken cancellationToken)
    {
        if (!await LoadAsync(resource, cancellationToken))
        {
            return NotFound();
        }

        PolicyNames = [.. Resource.Enforced, .. Resource.Skipped];

        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string resource, CancellationToken cancellationToken)
    {
        if (!await LoadAsync(resource, cancellationToken))
        {
            return NotFound();
        }

        ManagementResult result = await GetService<IResourcePolicyManagementService>().SetPoliciesAsync(Resource.Resource, PolicyNames, cancellationToken);
        if (!result.Succeeded)
        {
            foreach (string error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error);
            }

            return Page();
        }

        SetStatus($"The policies of '{Resource.DisplayName}' were saved.");
        return RedirectToPage("Index");
    }

    private async Task<bool> LoadAsync(string resource, CancellationToken cancellationToken)
    {
        ResourcePolicyAssignments assignments = await GetService<IResourcePolicyManagementService>().GetAssignmentsAsync(cancellationToken);
        ResourcePolicySummary? found = assignments.Resources.FirstOrDefault(r => string.Equals(r.Resource, resource, StringComparison.OrdinalIgnoreCase));
        if (found is null)
        {
            return false;
        }

        DynamicAuthorizationOptions settings = GetService<IOptions<DynamicAuthorizationOptions>>().Value;
        Resource = found;
        Policies = assignments.Policies;
        NeedsSuperAdmin = found.IsDashboard && settings.SuperAdminUsers.Count == 0 && settings.SuperAdminRoles.Count == 0;

        return true;
    }
}
