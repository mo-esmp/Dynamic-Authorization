using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace DynamicAuthorization.AspNetCore;

/// <summary>
///   Fails the start of the application when two controllers would require the same permission only because they have
///   the same name. MVC identifies a controller by its area and name, and so do resources and target keys: two
///   controllers named <c>WidgetsController</c> in different namespaces, outside of an area, are both the
///   <c>widgets</c> resource, so granting <c>widgets.read</c> for one would silently grant it for the other.
/// </summary>
/// <remarks>
///   Runs once the host has started, when the endpoints of the application, mapped in <c>Program.cs</c> or in
///   <c>Startup.Configure</c>, are known. Only controllers that share a name are described, so applications without
///   such controllers pay nothing.
/// </remarks>
internal sealed class ControllerNameValidator(
    EndpointDataSource endpointDataSource,
    EndpointAuthorizationResolver resolver,
    IOptions<DynamicAuthorizationOptions> options) : IHostedLifecycleService
{
    public Task StartingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StartedAsync(CancellationToken cancellationToken)
    {
        Validate();

        return Task.CompletedTask;
    }

    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private void Validate()
    {
        bool endpointConvention = options.Value.Convention == PermissionConvention.Endpoint;
        List<string> errors = [];

        IEnumerable<IGrouping<string, (Endpoint Endpoint, ControllerActionDescriptor Action)>> sharedNames = endpointDataSource.Endpoints
            .Select(e => (Endpoint: e, Action: e.Metadata.GetMetadata<ControllerActionDescriptor>()!))
            .Where(e => e.Action is not null)
            .GroupBy(e => $"{GetArea(e.Action)}:{e.Action.ControllerName}", StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Select(e => e.Action.ControllerTypeInfo).Distinct().Skip(1).Any());

        foreach (IGrouping<string, (Endpoint Endpoint, ControllerActionDescriptor Action)> controllers in sharedNames)
        {
            // The permissions each controller derives from its name. Declared permissions, and with the CRUD convention
            // declared resources, are shared on purpose.
            Dictionary<string, HashSet<Type>> derived = [with(StringComparer.OrdinalIgnoreCase)];
            string? resource = null;
            foreach ((Endpoint endpoint, ControllerActionDescriptor action) in controllers)
            {
                EndpointMetadataCollection metadata = endpoint.Metadata;
                if (metadata.GetMetadata<IPermissionMetadata>()?.Permission is not null
                    || (!endpointConvention && metadata.GetMetadata<IPermissionResourceMetadata>() is not null))
                {
                    continue;
                }

                foreach (EndpointAuthorizationInfo entry in resolver.DescribeAll(endpoint))
                {
                    if (entry.Protection == EndpointProtection.DynamicPermission && entry.Permission is { } permission)
                    {
                        resource ??= entry.Resource;
                        if (!derived.TryGetValue(permission.Permission, out HashSet<Type>? types))
                        {
                            derived[permission.Permission] = types = [];
                        }

                        types.Add(action.ControllerTypeInfo);
                    }
                }
            }

            string[] shared = [.. derived.Where(p => p.Value.Count > 1).Select(p => p.Key).Order(StringComparer.Ordinal)];
            if (shared.Length == 0)
            {
                continue;
            }

            ControllerActionDescriptor first = controllers.First().Action;
            string? area = GetArea(first);
            string[] typeNames =
            [
                .. derived.Where(p => p.Value.Count > 1)
                    .SelectMany(p => p.Value)
                    .Select(t => t.FullName!.Replace('+', '.'))
                    .Distinct()
                    .Order(StringComparer.Ordinal),
            ];
            string remedy = endpointConvention
                ? "Put the controllers in different areas with [Area], or give each a name of its own with [ControllerName]. " +
                  "To share a permission, declare it on the actions with [Permission]."
                : "Put the controllers in different areas with [Area], or give each a resource of its own with [PermissionResource]. " +
                  $"To share the permissions, declare the resource on each controller with [PermissionResource(\"{resource}\")].";

            errors.Add(
                $"The controllers {JoinNames(typeNames)} are named '{first.ControllerName}'" +
                (area is null ? " and are not in an area" : $" in the area '{area}'") +
                $", so their actions require the same permissions: {string.Join(", ", shared)}. " +
                $"Granting one of them grants it for all of these controllers. {remedy}");
        }

        if (errors.Count > 0)
        {
            throw new InvalidOperationException(string.Join(Environment.NewLine, errors));
        }
    }

    private static string? GetArea(ControllerActionDescriptor action) =>
        action.RouteValues.TryGetValue("area", out string? area) && !string.IsNullOrEmpty(area) ? area : null;

    private static string JoinNames(string[] names) =>
        names.Length == 2 ? $"{names[0]} and {names[1]}" : $"{string.Join(", ", names[..^1])} and {names[^1]}";
}
