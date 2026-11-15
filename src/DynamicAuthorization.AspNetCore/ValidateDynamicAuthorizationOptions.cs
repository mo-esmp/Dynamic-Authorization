using Microsoft.Extensions.Options;

namespace DynamicAuthorization.AspNetCore;

/// <summary>
///   Validates <see cref="DynamicAuthorizationOptions"/> at startup: the names of assignable policies must be
///   unambiguous, because they are stored with assignments and compared ignoring case, like ASP.NET Core compares
///   policy names.
/// </summary>
internal sealed class ValidateDynamicAuthorizationOptions : IValidateOptions<DynamicAuthorizationOptions>
{
    public ValidateOptionsResult Validate(string? name, DynamicAuthorizationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string> failures = [];
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
