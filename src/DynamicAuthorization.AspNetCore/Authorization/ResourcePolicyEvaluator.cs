using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

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
///     more than once evaluates the policies once; a failure stays a failure.
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
    ILogger<ResourcePolicyEvaluator> logger)
{
    private static readonly AsyncLocal<bool> s_evaluating = new();
    private static readonly object s_outcomesKey = new();

    /// <summary>
    ///   Gets a value indicating whether any policy is assignable; while none is, nothing is evaluated.
    /// </summary>
    public bool IsEnabled => registry.IsEnabled;

    /// <summary>
    ///   Evaluates the policies assigned to the resource of an endpoint for a request whose permission was granted.
    /// </summary>
    /// <param name="httpContext">The request.</param>
    /// <param name="user">The principal being authorized.</param>
    /// <param name="endpoint">The endpoint being authorized, with its resource.</param>
    /// <param name="isSuperAdminAsync">Tells whether the user is a super admin; super admins skip assigned policies.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>Whether every assigned policy passes.</returns>
    public async Task<bool> AuthorizeAsync(
        HttpContext httpContext,
        ClaimsPrincipal user,
        EndpointAuthorizationInfo endpoint,
        Func<CancellationToken, Task<bool>> isSuperAdminAsync,
        CancellationToken cancellationToken)
    {
        if (s_evaluating.Value || endpoint.Resource is not { } resource)
        {
            return true;
        }

        Dictionary<(ClaimsPrincipal, Endpoint), bool> outcomes = GetOutcomes(httpContext);
        (ClaimsPrincipal, Endpoint) key = (user, endpoint.Endpoint);
        if (outcomes.TryGetValue(key, out bool known))
        {
            return known;
        }

        bool outcome = await EvaluateAsync(httpContext, user, resource, isSuperAdminAsync, cancellationToken).ConfigureAwait(false);
        outcomes[key] = outcome;

        return outcome;
    }

    private async Task<bool> EvaluateAsync(
        HttpContext httpContext,
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
                result = await authorization.AuthorizeAsync(user, httpContext, policy).ConfigureAwait(false);
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

    private static Dictionary<(ClaimsPrincipal, Endpoint), bool> GetOutcomes(HttpContext httpContext)
    {
        if (httpContext.Items.TryGetValue(s_outcomesKey, out object? value) && value is Dictionary<(ClaimsPrincipal, Endpoint), bool> outcomes)
        {
            return outcomes;
        }

        outcomes = [];
        httpContext.Items[s_outcomesKey] = outcomes;

        return outcomes;
    }

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
