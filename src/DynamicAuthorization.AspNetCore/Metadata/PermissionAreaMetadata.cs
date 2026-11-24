namespace DynamicAuthorization.AspNetCore;

/// <summary>
///   Places an endpoint in an area. Add it with <c>WithPermissionArea</c>.
/// </summary>
public sealed class PermissionAreaMetadata : IPermissionAreaMetadata
{
    /// <summary>
    ///   Initializes a new instance of the <see cref="PermissionAreaMetadata"/> class.
    /// </summary>
    /// <param name="area">The area name, for example <c>admin</c>.</param>
    /// <exception cref="ArgumentException">
    ///   <paramref name="area"/> is empty, or has no letter or digit to name a permission key segment, like <c>---</c>.
    /// </exception>
    public PermissionAreaMetadata(string area)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(area);
        if (PermissionKeys.ToSegment(area).Length == 0)
        {
            throw new ArgumentException($"The area '{area}' has no letter or digit to name a permission key segment.", nameof(area));
        }

        Area = area;
    }

    /// <inheritdoc />
    public string Area { get; }
}
