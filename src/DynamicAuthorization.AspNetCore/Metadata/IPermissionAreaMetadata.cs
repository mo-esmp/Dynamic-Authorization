namespace DynamicAuthorization.AspNetCore;

/// <summary>
///   Metadata that places an endpoint, such as a Minimal API, in an area, the way <c>[Area]</c> does for a controller.
///   The area's route segment is skipped, and the area prefixes the resource derived from the rest of the route:
///   <c>GET /api/admin/orders</c> in the <c>admin</c> area requires <c>admin.orders.read</c>.
/// </summary>
public interface IPermissionAreaMetadata
{
    /// <summary>
    ///   Gets the area name, for example <c>admin</c>.
    /// </summary>
    string Area { get; }
}
