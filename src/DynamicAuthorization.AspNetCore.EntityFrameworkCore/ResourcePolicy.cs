namespace DynamicAuthorization.AspNetCore.EntityFrameworkCore;

/// <summary>
///   An authorization policy assigned to a resource. Mapped when
///   <see cref="DynamicAuthorizationModelOptions.ResourcePolicies"/> is enabled.
/// </summary>
public class ResourcePolicy
{
    /// <summary>
    ///   Gets or sets the resource key, in lower case, for example <c>orders</c>.
    /// </summary>
    public virtual string Resource { get; set; } = string.Empty;

    /// <summary>
    ///   Gets or sets the name of the assigned policy.
    /// </summary>
    public virtual string PolicyName { get; set; } = string.Empty;
}
