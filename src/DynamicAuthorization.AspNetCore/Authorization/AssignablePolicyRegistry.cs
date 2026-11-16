using Microsoft.Extensions.Options;

namespace DynamicAuthorization.AspNetCore;

/// <summary>
///   The assignable policies registered in <see cref="DynamicAuthorizationOptions.AssignablePolicies"/>, read once so that
///   permission checks can tell in constant time whether the feature is on and whether a stored assignment is still
///   registered.
/// </summary>
internal sealed class AssignablePolicyRegistry
{
    private readonly Dictionary<string, AssignablePolicyDefinition> _policies;

    public AssignablePolicyRegistry(IOptions<DynamicAuthorizationOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        Policies = [.. options.Value.AssignablePolicies];
        _policies = new Dictionary<string, AssignablePolicyDefinition>(Policies.Count, StringComparer.OrdinalIgnoreCase);
        foreach (AssignablePolicyDefinition policy in Policies)
        {
            _policies.TryAdd(policy.Name, policy);
        }
    }

    /// <summary>
    ///   Gets a value indicating whether any policy is assignable. While none is, assignments are neither read nor
    ///   enforced.
    /// </summary>
    public bool IsEnabled => _policies.Count > 0;

    /// <summary>
    ///   Gets the assignable policies in registration order.
    /// </summary>
    public IReadOnlyList<AssignablePolicyDefinition> Policies { get; }

    /// <summary>
    ///   Determines whether a policy is registered, ignoring case.
    /// </summary>
    public bool IsRegistered(string name) => _policies.ContainsKey(name);

    /// <summary>
    ///   Gets the registration of a policy, ignoring case.
    /// </summary>
    public bool TryGet(string name, [System.Diagnostics.CodeAnalysis.MaybeNullWhen(false)] out AssignablePolicyDefinition policy) =>
        _policies.TryGetValue(name, out policy);
}
