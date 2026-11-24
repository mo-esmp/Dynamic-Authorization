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
    /// <exception cref="ArgumentException"><paramref name="area"/> is empty or whitespace.</exception>
    public PermissionAreaMetadata(string area)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(area);

        Area = area;
    }

    /// <inheritdoc />
    public string Area { get; }
}
