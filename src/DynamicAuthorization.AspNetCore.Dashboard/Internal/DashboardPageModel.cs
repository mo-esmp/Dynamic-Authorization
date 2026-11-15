using DynamicAuthorization.AspNetCore.Management;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace DynamicAuthorization.AspNetCore.Dashboard;

/// <summary>
///   The base class of the dashboard pages.
/// </summary>
/// <remarks>
///   Services are resolved on demand rather than through the constructor so that the pages can return 404 when the
///   dashboard is not enabled, instead of failing to activate.
/// </remarks>
internal abstract class DashboardPageModel : PageModel
{
    /// <inheritdoc />
    /// <remarks>
    ///   <see cref="NonHandlerAttribute"/> keeps Razor Pages from treating this <c>On…Async</c> override as a page
    ///   handler for a "Page" HTTP method.
    /// </remarks>
    [NonHandler]
    public override async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        if (HttpContext.RequestServices.GetService<DashboardMarker>() is null)
        {
            context.Result = NotFound();
            return;
        }

        await next().ConfigureAwait(false);
    }

    private protected T GetService<T>()
        where T : notnull => HttpContext.RequestServices.GetRequiredService<T>();

    /// <summary>
    ///   Determines whether the current user may open another dashboard page, so that a link to it is rendered only
    ///   then. Pages that are not in the catalog are never linked.
    /// </summary>
    private protected async Task<bool> CanAccessPageAsync(string page, CancellationToken cancellationToken)
    {
        EndpointAuthorizationInfo? target = GetService<IPermissionCatalogProvider>().GetCatalog()
            .FindEndpoint(PermissionKeys.ForPage(DashboardConstants.AreaName, page));
        if (target is null)
        {
            return false;
        }

        return target.Permission is null
            || await GetService<IPermissionChecker>().HasPermissionAsync(User, target.Permission.Permission, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    ///   Gets the policies assigned to resources, keyed by resource ignoring case, or <see langword="null"/> while no
    ///   policy is assignable, in which case the store is not read.
    /// </summary>
    private protected async Task<ResourcePolicyAssignments?> GetResourcePolicyAssignmentsAsync(CancellationToken cancellationToken) =>
        GetService<IOptions<DynamicAuthorizationOptions>>().Value.AssignablePolicies.Count == 0
            ? null
            : await GetService<IResourcePolicyManagementService>().GetAssignmentsAsync(cancellationToken).ConfigureAwait(false);

    private protected void SetStatus(string message) => TempData[DashboardConstants.StatusKey] = message;

    private protected void SetError(IEnumerable<string> errors) => TempData[DashboardConstants.ErrorKey] = string.Join(" ", errors);
}
