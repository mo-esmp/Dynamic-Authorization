using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace DynamicAuthorization.AspNetCore;

/// <summary>
///   Validates <see cref="DynamicAuthorizationOptions"/> at startup: the names of assignable policies must be
///   unambiguous, because they are stored with assignments and compared ignoring case, like ASP.NET Core compares
///   policy names; and assignments need a store.
/// </summary>
internal sealed class ValidateDynamicAuthorizationOptions(IServiceProviderIsService services) : IValidateOptions<DynamicAuthorizationOptions>
{
    public ValidateOptionsResult Validate(string? name, DynamicAuthorizationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string> failures = [];
        if (options.AssignablePolicies.Count > 0 && !services.IsService(typeof(IResourcePolicyStore)))
        {
            failures.Add(
                $"{nameof(DynamicAuthorizationOptions.AssignablePolicies)} is not empty, but no {nameof(IResourcePolicyStore)} is registered " +
                "to store the policies assigned to resources. Call AddEntityFrameworkStore<TContext>() and enable the table with " +
                "EnableDynamicAuthorization(o => o.ResourcePolicies = true), or register your own " +
                $"{nameof(IResourcePolicyStore)}.");
        }

        HashSet<string> names = [with(StringComparer.OrdinalIgnoreCase)];
        foreach (AssignablePolicyDefinition? policy in options.AssignablePolicies)
        {
            string? policyName = policy?.Name;
            if (string.IsNullOrWhiteSpace(policyName))
            {
                failures.Add($"{nameof(DynamicAuthorizationOptions.AssignablePolicies)} contains a policy without a name.");
            }
            else if (policyName.Length != policyName.Trim().Length)
            {
                failures.Add(
                    $"{nameof(DynamicAuthorizationOptions.AssignablePolicies)} contains the policy name '{policyName}' with leading or " +
                    "trailing white space.");
            }
            else if (policyName.Length > AssignablePolicyDefinition.MaxNameLength)
            {
                failures.Add(
                    $"{nameof(DynamicAuthorizationOptions.AssignablePolicies)} contains a policy name longer than " +
                    $"{AssignablePolicyDefinition.MaxNameLength} characters: '{Truncate(policyName)}'.");
            }
            else if (!names.Add(policyName))
            {
                failures.Add(
                    $"{nameof(DynamicAuthorizationOptions.AssignablePolicies)} contains the policy '{policyName}' more than once. " +
                    "Policy names are compared ignoring case.");
            }
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private static string Truncate(string value)
    {
        const int Shown = 40;
        return value.Length <= Shown ? value : $"{value[..Shown]}...";
    }
}
