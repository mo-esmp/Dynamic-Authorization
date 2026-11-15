namespace DynamicAuthorization.AspNetCore.EntityFrameworkCore;

/// <summary>
///   A permission granted to a role.
/// </summary>
/// <typeparam name="TKey">The type of the role key.</typeparam>
public class RolePermission<TKey>
    where TKey : IEquatable<TKey>
{
    /// <summary>
    ///   Gets or sets the identifier of the role the permission is granted to.
    /// </summary>
    public virtual TKey RoleId { get; set; } = default!;

    /// <summary>
    ///   Gets or sets the permission key.
    /// </summary>
    public virtual string Permission { get; set; } = string.Empty;
}

/// <summary>
///   Options for the dynamic authorization entity model.
/// </summary>
public sealed class DynamicAuthorizationModelOptions
{
    /// <summary>
    ///   The maximum length of a permission key.
    /// </summary>
    public const int MaxPermissionLength = 256;

    /// <summary>
    ///   Gets or sets the name of the table that stores role permissions. Defaults to <c>AspNetRolePermissions</c>.
    /// </summary>
    public string TableName { get; set; } = "AspNetRolePermissions";

    /// <summary>
    ///   Gets or sets the schema of the dynamic authorization tables. Defaults to the model's default schema.
    /// </summary>
    public string? Schema { get; set; }

    /// <summary>
    ///   Gets or sets a value indicating whether the table that stores the authorization policies assigned to resources
    ///   is added to the model. Enable it, and add a migration, to let admins assign the policies registered with
    ///   <c>DynamicAuthorizationOptions.AddAssignablePolicy</c>. Defaults to <see langword="false"/>, so that applications
    ///   that don't assign policies have no table to migrate.
    /// </summary>
    public bool ResourcePolicies { get; set; }

    /// <summary>
    ///   Gets or sets the name of the table that stores the policies assigned to resources. Defaults to
    ///   <c>AspNetResourcePolicies</c>.
    /// </summary>
    public string ResourcePolicyTableName { get; set; } = "AspNetResourcePolicies";
}
