using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DynamicAuthorization.AspNetCore;

/// <summary>
///   Evaluates the policies admins assigned to the resource of an endpoint, after its permission was granted. Every
///   assigned policy must pass. Policies that are no longer registered are skipped; a registered policy that cannot be
///   resolved, that requires a dynamic permission itself, or that names authentication schemes denies.
/// </summary>
/// <remarks>
///   <para>
///     While assigned policies are evaluated, a nested permission check, for example by a requirement handler that
///     authorizes another policy, checks its permission but does not evaluate assigned policies again: that would
///     recurse. The outcome is remembered for the request, per principal and endpoint, so a request that is authorized
///     more than once, even concurrently, evaluates the policies once; a failure stays a failure. Assigned policies
///     receive the authorization resource as given, an <see cref="HttpContext"/> or an MVC filter context.
///   </para>
///   <para>
///     Policies assigned to the dashboard's own resources are skipped while no super admin is configured, so that a
///     change of configuration cannot lock everyone out of the dashboard.
///   </para>
///   <para>
///     <see cref="IAuthorizationService"/> and <see cref="IAuthorizationPolicyProvider"/> are resolved from the request
///     when needed: the authorization service depends on every authorization handler, including the one that calls
///     this evaluator.
///   </para>
/// </remarks>
internal sealed partial class ResourcePolicyEvaluator(
    AssignablePolicyRegistry registry,
    DynamicAuthorizationCache cache,
    IOptions<DynamicAuthorizationOptions> options,
    ILogger<ResourcePolicyEvaluator> logger)
{
    private static readonly AsyncLocal<bool> s_evaluating = new();
    private static readonly object s_outcomesKey = new();

    /// <summary>
    ///   Gets a value indicating whether any policy is assignable; while none is, nothing is evaluated.
    /// </summary>
    public bool IsEnabled => registry.IsEnabled;

    /// <summary>
    ///   Evaluates the policies assigned to the resource of an endpoint for a request whose permission was granted to a
    ///   user who is not known to be a super admin.
    /// </summary>
    /// <param name="httpContext">The request: its services, and the scope of the remembered outcomes.</param>
    /// <param name="resource">The authorization resource, passed on to the assigned policies as it was given.</param>
    /// <param name="user">The principal being authorized.</param>
    /// <param name="endpoint">The endpoint being authorized, with its resource.</param>
    /// <param name="isSuperAdminAsync">
    ///   Tells whether the user is a super admin, asked only when the resource has assigned policies; super admins skip
    ///   them.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>Whether every assigned policy passes.</returns>
    public Task<bool> AuthorizeAsync(
        HttpContext httpContext,
        object? resource,
        ClaimsPrincipal user,
        EndpointAuthorizationInfo endpoint,
        Func<CancellationToken, Task<bool>> isSuperAdminAsync,
        CancellationToken cancellationToken)
    {
        if (s_evaluating.Value || endpoint.Resource is not { } resourceKey)
        {
            return Task.FromResult(true);
        }

        // Concurrent authorizations of one request share the evaluation of a key, so the policies run once; a failed
        // evaluation is forgotten, so the next authorization retries it.
        Outcomes outcomes = GetOutcomes(httpContext);
        (ClaimsPrincipal, Endpoint) key = (user, endpoint.Endpoint);
        Lazy<Task<bool>> evaluation;
        lock (outcomes)
        {
            if (!outcomes.TryGetValue(key, out evaluation!))
            {
                evaluation = new Lazy<Task<bool>>(() => EvaluateAsync(httpContext, resource, user, resourceKey, isSuperAdminAsync, cancellationToken));
                outcomes[key] = evaluation;
            }
        }

        return AwaitAsync(outcomes, key, evaluation);
    }

    private static async Task<bool> AwaitAsync(Outcomes outcomes, (ClaimsPrincipal, Endpoint) key, Lazy<Task<bool>> evaluation)
    {
        try
        {
            return await evaluation.Value.ConfigureAwait(false);
        }
        catch
        {
            lock (outcomes)
            {
                if (outcomes.TryGetValue(key, out Lazy<Task<bool>>? current) && ReferenceEquals(current, evaluation))
                {
                    outcomes.Remove(key);
                }
            }

            throw;
        }
    }

    private async Task<bool> EvaluateAsync(
        HttpContext httpContext,
        object? authorizationResource,
        ClaimsPrincipal user,
        string resource,
        Func<CancellationToken, Task<bool>> isSuperAdminAsync,
        CancellationToken cancellationToken)
    {
        IReadOnlyDictionary<string, IReadOnlySet<string>> assignments =
            (await cache.GetResourcePoliciesAsync(cancellationToken).ConfigureAwait(false)).Value;
        if (!assignments.TryGetValue(resource, out IReadOnlySet<string>? assigned) || assigned.Count == 0)
        {
            return true;
        }

        // The dashboard's own resources take policies only while a super admin can undo them. A configuration change
        // that removes the last super admin must not leave a policy that could lock everyone out of the dashboard.
        if (resource.StartsWith(Management.ResourcePolicyManagementService.DashboardResourcePrefix, StringComparison.OrdinalIgnoreCase)
            && options.Value is { SuperAdminUsers.Count: 0, SuperAdminRoles.Count: 0 })
        {
            LogDashboardPoliciesSkipped(logger, resource);
            return true;
        }

        if (await isSuperAdminAsync(cancellationToken).ConfigureAwait(false))
        {
            return true;
        }

        IServiceProvider services = httpContext.RequestServices;
        IAuthorizationPolicyProvider? policyProvider = null;
        IAuthorizationService? authorization = null;
        foreach (string name in assigned.Order(StringComparer.Ordinal))
        {
            if (!registry.IsRegistered(name))
            {
                LogUnregisteredPolicySkipped(logger, name, resource);
                continue;
            }

            policyProvider ??= services.GetRequiredService<IAuthorizationPolicyProvider>();
            AuthorizationPolicy? policy = await policyProvider.GetPolicyAsync(name).ConfigureAwait(false);
            if (policy is null)
            {
                LogPolicyNotFound(logger, name, resource);
                return false;
            }

            if (policy.Requirements.Any(r => r is DynamicPermissionRequirement))
            {
                LogRecursivePolicy(logger, name, resource);
                return false;
            }

            if (policy.AuthenticationSchemes.Count > 0)
            {
                LogPolicyWithSchemes(logger, name, resource);
                return false;
            }

            authorization ??= services.GetRequiredService<IAuthorizationService>();
            AuthorizationResult result;
            bool outer = s_evaluating.Value;
            s_evaluating.Value = true;
            try
            {
                // The policy sees the resource the request was authorized with, as it would on the endpoint itself: an
                // HttpContext, or an MVC filter context.
                result = await authorization.AuthorizeAsync(user, authorizationResource, policy).ConfigureAwait(false);
            }
            finally
            {
                s_evaluating.Value = outer;
            }

            if (!result.Succeeded)
            {
                LogPolicyDenied(logger, name, resource, user.Identity?.Name);
                return false;
            }
        }

        return true;
    }

    private static Outcomes GetOutcomes(HttpContext httpContext)
    {
        // HttpContext.Items is not safe for concurrent writes: create the request's outcomes under a lock, which is
        // held only for this lookup.
        lock (s_outcomesKey)
        {
            if (httpContext.Items.TryGetValue(s_outcomesKey, out object? value) && value is Outcomes outcomes)
            {
                return outcomes;
            }

            outcomes = new Outcomes();
            httpContext.Items[s_outcomesKey] = outcomes;

            return outcomes;
        }
    }

    [LoggerMessage(15, LogLevel.Warning, "Policies are assigned to the dashboard resource '{Resource}', but no super admin is configured to undo them. They are skipped.")]
    private static partial void LogDashboardPoliciesSkipped(ILogger logger, string resource);

    /// <summary>
    ///   The evaluations of one request, by principal and endpoint. Guarded by its own lock.
    /// </summary>
    private sealed class Outcomes : Dictionary<(ClaimsPrincipal, Endpoint), Lazy<Task<bool>>>;

    [LoggerMessage(10, LogLevel.Warning, "The policy '{PolicyName}' assigned to the resource '{Resource}' is not registered as assignable and is skipped.")]
    private static partial void LogUnregisteredPolicySkipped(ILogger logger, string policyName, string resource);

    [LoggerMessage(11, LogLevel.Warning, "The policy '{PolicyName}' assigned to the resource '{Resource}' was not found. Access is denied.")]
    private static partial void LogPolicyNotFound(ILogger logger, string policyName, string resource);

    [LoggerMessage(12, LogLevel.Error, "The policy '{PolicyName}' assigned to the resource '{Resource}' requires a dynamic permission, which cannot be evaluated while its own permission is checked. Access is denied.")]
    private static partial void LogRecursivePolicy(ILogger logger, string policyName, string resource);

    [LoggerMessage(13, LogLevel.Error, "The policy '{PolicyName}' assigned to the resource '{Resource}' names authentication schemes, which an assigned policy cannot authenticate with. Access is denied.")]
    private static partial void LogPolicyWithSchemes(ILogger logger, string policyName, string resource);

    [LoggerMessage(14, LogLevel.Information, "The policy '{PolicyName}' assigned to the resource '{Resource}' denied '{UserName}'.")]
    private static partial void LogPolicyDenied(ILogger logger, string policyName, string resource, string? userName);
}
