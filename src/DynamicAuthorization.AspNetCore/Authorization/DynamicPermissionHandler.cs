using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Logging;

namespace DynamicAuthorization.AspNetCore;

internal sealed partial class DynamicPermissionHandler(
    IPermissionChecker permissionChecker,
    EndpointAuthorizationResolver resolver,
    ResourcePolicyEvaluator resourcePolicies,
    ILogger<DynamicPermissionHandler> logger) : AuthorizationHandler<DynamicPermissionRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, DynamicPermissionRequirement requirement)
    {
        (bool applicable, string? permission, HttpContext? request, EndpointAuthorizationInfo? requested) = requirement.Permission is { } required
            ? (true, required, null, null)
            : ResolvePermission(context.Resource);

        if (!applicable)
        {
            context.Succeed(requirement);
            return;
        }

        if (permission is null)
        {
            LogUnresolvedPermission(logger, context.Resource?.GetType().Name ?? "null");
            return;
        }

        // Only the decision is needed here: stop at the first role that grants the permission instead of collecting
        // every granting role, which costs one store query per role on a cold cache.
        CancellationToken cancellationToken = request?.RequestAborted ?? (context.Resource is HttpContext httpContext ? httpContext.RequestAborted : default);
        PermissionDecision? decision = await DecideAsync(context.User, permission, cancellationToken).ConfigureAwait(false);
        if (decision is not (PermissionDecision.GrantedByRole or PermissionDecision.SuperAdminRole or PermissionDecision.SuperAdminUser))
        {
            LogPermissionDenied(logger, permission, context.User.Identity?.Name);
            return;
        }

        LogPermissionGranted(logger, permission, context.User.Identity?.Name);

        // A request to a permission-checked endpoint must also pass the policies assigned to the endpoint's resource.
        // Explicit permissions, endpoints on their own (the secure-content tag helper) and code checks are not affected.
        // Super admins skip them; the built-in checker has already said whether the user is one, so they never depend
        // on the assignments being readable.
        if (request is not null
            && requested is { Protection: EndpointProtection.DynamicPermission, Resource: not null }
            && resourcePolicies.IsEnabled
            && decision is PermissionDecision.GrantedByRole
            && !await resourcePolicies.AuthorizeAsync(
                request,
                context.Resource,
                context.User,
                requested,
                ct => IsSuperAdminAsync(context.User, permission, ct),
                cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        context.Succeed(requirement);
    }

    /// <summary>
    ///   Tells whether a user whose permission was granted by roles is a super admin after all. The built-in checker has
    ///   already said no; an application's own checker only answers granted or not, so it is asked for the full
    ///   evaluation, which only happens when the resource has assigned policies.
    /// </summary>
    private async Task<bool> IsSuperAdminAsync(ClaimsPrincipal user, string permission, CancellationToken cancellationToken)
    {
        if (permissionChecker is PermissionChecker)
        {
            return false;
        }

        PermissionDecision decision = (await permissionChecker.EvaluateAsync(user, permission, cancellationToken).ConfigureAwait(false)).Decision;

        return decision is PermissionDecision.SuperAdminRole or PermissionDecision.SuperAdminUser;
    }

    /// <summary>
    ///   Decides the permission. The built-in checker tells how, for example that the user is a super admin, at the cost
    ///   of the decision alone; an application's own checker only answers granted (reported as
    ///   <see cref="PermissionDecision.GrantedByRole"/>) or not.
    /// </summary>
    private async Task<PermissionDecision?> DecideAsync(ClaimsPrincipal user, string permission, CancellationToken cancellationToken)
    {
        if (permissionChecker is PermissionChecker builtIn)
        {
            return await builtIn.DecideAsync(user, permission, cancellationToken).ConfigureAwait(false);
        }

        return await permissionChecker.HasPermissionAsync(user, permission, cancellationToken).ConfigureAwait(false)
            ? PermissionDecision.GrantedByRole
            : null;
    }

    /// <summary>
    ///   Resolves the permission to check for an authorization resource.
    /// </summary>
    /// <returns>
    ///   Whether the dynamic check applies to the resource and, if so, the permission to check. A <see langword="null"/>
    ///   permission for an applicable resource denies access. For an HTTP request, also the request and the entry of
    ///   the endpoint it reaches.
    /// </returns>
    private (bool Applicable, string? Permission, HttpContext? Request, EndpointAuthorizationInfo? Requested) ResolvePermission(object? resource)
    {
        // Requests resolve the Razor Page handler that will run; endpoints on their own (e.g. from the secure-content
        // tag helper) resolve the permission needed to navigate to them.
        HttpContext? request = resource switch
        {
            HttpContext httpContext => httpContext,
            FilterContext filterContext => filterContext.HttpContext,
            _ => null,
        };
        EndpointAuthorizationInfo? info = resource switch
        {
            _ when request?.GetEndpoint() is { } endpoint => resolver.Describe(endpoint, request),
            Endpoint endpoint => resolver.Describe(endpoint),
            EndpointAuthorizationInfo entry => entry,
            _ => null,
        };

        if (info is not null)
        {
            return info.Protection == EndpointProtection.Excluded
                ? (false, null, null, null)
                : (true, info.Permission?.Permission ?? info.TargetKey, request, request is null ? null : info);
        }

        return resource switch
        {
            string permission => (true, permission, null, null),

            // An HTTP request without an endpoint cannot be mapped to a permission: deny.
            HttpContext or FilterContext => (true, null, null, null),

            // Hub methods are authorized per connection; only an explicit permission on the method is checked.
            HubInvocationContext invocation => invocation.HubMethod.GetCustomAttribute<PermissionAttribute>()?.Permission is { } permission
                ? (true, permission, null, null)
                : (false, null, null, null),

            // Authorization without a resource (for example <AuthorizeView> or IAuthorizationService calls) has no
            // endpoint to check; the rest of the policy, such as requiring an authenticated user, still applies.
            _ => (false, null, null, null),
        };
    }

    [LoggerMessage(1, LogLevel.Debug, "Permission '{Permission}' was granted to '{UserName}'.")]
    private static partial void LogPermissionGranted(ILogger logger, string permission, string? userName);

    [LoggerMessage(2, LogLevel.Information, "Permission '{Permission}' was denied for '{UserName}'.")]
    private static partial void LogPermissionDenied(ILogger logger, string permission, string? userName);

    [LoggerMessage(3, LogLevel.Warning, "No permission could be resolved for the authorization resource '{ResourceType}'. Access is denied.")]
    private static partial void LogUnresolvedPermission(ILogger logger, string resourceType);
}
