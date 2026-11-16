using System.ComponentModel;
using DynamicAuthorization.AspNetCore.Management;
using Microsoft.AspNetCore.Mvc;

namespace DynamicAuthorization.AspNetCore.Dashboard.Pages.Policies;

// The page requires authz.policies.read; clearing orphaned assignments requires authz.policies.update.
[DisplayName("Policies")]
[PermissionResource(DashboardConstants.PoliciesResource, DisplayName = "Dashboard / Policies")]
internal sealed class IndexModel : DashboardPageModel
{
    public ResourcePolicyAssignments Assignments { get; private set; } = new([], [], []);

    public bool CanEdit { get; private set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        Assignments = await GetService<IResourcePolicyManagementService>().GetAssignmentsAsync(cancellationToken);
        CanEdit = await CanAccessPageAsync("/Policies/Edit", cancellationToken);
    }

    [Permission(Operation = PermissionOperation.Update)]
    public async Task<IActionResult> OnPostClearAsync(string resource, CancellationToken cancellationToken)
    {
        ManagementResult result = await GetService<IResourcePolicyManagementService>().SetPoliciesAsync(resource, [], cancellationToken);
        if (result.Succeeded)
        {
            SetStatus($"The policies assigned to '{resource}' were removed.");
        }
        else
        {
            SetError(result.Errors);
        }

        return RedirectToPage("Index");
    }
}
