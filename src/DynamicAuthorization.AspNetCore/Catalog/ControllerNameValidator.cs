using System.Reflection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace DynamicAuthorization.AspNetCore;

/// <summary>
///   Finds controllers that would share a resource or a permission only because they have the same name. Resources
///   and target keys come from a controller's area and name, not its namespace: two controllers named
///   <c>WidgetsController</c> in different namespaces, outside of an area, are both the <c>widgets</c> resource, so
///   granting <c>widgets.read</c>, or assigning a policy to <c>widgets</c>, for one would silently apply to the other.
/// </summary>
/// <remarks>
///   <para>
///     Sharing is accepted only when every controller involved opts in: with <see cref="PermissionResourceAttribute"/>
///     for its resource and the permissions derived from it, and with an explicit <see cref="PermissionAttribute"/>
///     key for a permission.
///   </para>
///   <para>
///     The application fails to start when such controllers exist. Independently of the start, authorization denies
///     their endpoints: the conflicts are computed for the endpoints requests are routed to, and again whenever the
///     endpoints change, so controllers added at runtime, or requests served before the start completes, never share
///     grants either. Only controllers with the same name are described, so other applications pay nothing.
///   </para>
/// </remarks>
internal sealed class ControllerNameValidator(
    IServiceProvider services,
    EndpointAuthorizationResolver resolver,
    IOptions<DynamicAuthorizationOptions> options) : IHostedLifecycleService
{
    private const string ResourceClaim = "resource";
    private const string PermissionClaim = "permission";

    private static readonly Snapshot s_empty = new(new CancellationChangeToken(CancellationToken.None), [], new Dictionary<Endpoint, string>());

    private Snapshot? _snapshot;

    public Task StartingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    ///   Validates once every hosted service has started, when the endpoints mapped in <c>Program.cs</c> or in
    ///   <c>Startup.Configure</c> are known.
    /// </summary>
    public Task StartedAsync(CancellationToken cancellationToken)
    {
        if (GetSnapshot().Errors is { Count: > 0 } errors)
        {
            throw new InvalidOperationException(string.Join(Environment.NewLine, errors));
        }

        return Task.CompletedTask;
    }

    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    ///   Gets why an endpoint must not be authorized, because its controller shares a resource or permission with a
    ///   controller of the same name.
    /// </summary>
    /// <returns>The error, or <see langword="null"/> when the endpoint has no such conflict.</returns>
    public string? GetConflict(Endpoint endpoint) => GetSnapshot().Conflicts.GetValueOrDefault(endpoint);

    private Snapshot GetSnapshot()
    {
        // Routing only selects the endpoints of a new generation after the change token has fired, so a snapshot whose
        // token has not changed covers every endpoint a request can reach.
        Snapshot? snapshot = Volatile.Read(ref _snapshot);
        if (snapshot is null || snapshot.ChangeToken.HasChanged)
        {
            snapshot = Compute();
            Volatile.Write(ref _snapshot, snapshot);
        }

        return snapshot;
    }

    private Snapshot Compute()
    {
        // Applications without routing, such as workers that only check permissions in code, have no endpoints.
        if (services.GetService<EndpointDataSource>() is not { } dataSource)
        {
            return s_empty;
        }

        IChangeToken changeToken = dataSource.GetChangeToken();
        Controller[] controllers =
        [
            .. dataSource.Endpoints
                .Select(e => (Endpoint: e, Action: e.Metadata.GetMetadata<ControllerActionDescriptor>()))
                .Where(e => e.Action is not null)
                .GroupBy(e => e.Action!.ControllerTypeInfo)
                .Select(g => new Controller(g.Key, GetArea(g.First().Action!), g.First().Action!.ControllerName, [.. g.Select(e => e.Endpoint)])),
        ];

        // Controllers are compared when their names lead to the same resource (areas BackOffice and Back-Office are both
        // back-office) or the same target keys (MVC compares names case-insensitively).
        IEnumerable<Controller[]> candidates = controllers
            .GroupBy(c => JoinResource(c.Area, c.Name), StringComparer.OrdinalIgnoreCase)
            .Concat(controllers.GroupBy(c => $"{c.Area}:{c.Name}", StringComparer.OrdinalIgnoreCase))
            .Where(g => g.Skip(1).Any())
            .Select(g => g.ToArray());

        List<string> errors = [];
        Dictionary<Endpoint, string> conflicts = [];
        foreach (Controller[] group in candidates)
        {
            if (Validate(group) is not { } conflict || errors.Contains(conflict.Error, StringComparer.Ordinal))
            {
                continue;
            }

            errors.Add(conflict.Error);
            foreach (Endpoint endpoint in conflict.Controllers.SelectMany(c => c.Endpoints))
            {
                conflicts.TryAdd(endpoint, conflict.Error);
            }
        }

        return new Snapshot(changeToken, errors, conflicts);
    }

    private (string Error, Controller[] Controllers)? Validate(Controller[] group)
    {
        DynamicAuthorizationOptions settings = options.Value;
        bool endpointConvention = settings.Convention == PermissionConvention.Endpoint;

        // What each controller's permission-checked actions share with other endpoints, and whether the controller
        // declared it: its own resource, which assigned policies apply to; the permissions it requires; and, when any
        // operation implies read, the resources of those permissions, since a grant of one operation reads them all.
        Dictionary<Controller, Dictionary<(string Kind, string Value), bool>> claims = [];
        foreach (Controller controller in group)
        {
            Dictionary<(string Kind, string Value), bool> own = [with(ClaimComparer.Instance)];
            foreach (Endpoint endpoint in controller.Endpoints)
            {
                bool declaredResource = endpoint.Metadata.GetMetadata<IPermissionResourceMetadata>() is not null;
                bool explicitPermission = endpoint.Metadata.GetMetadata<IPermissionMetadata>()?.Permission is not null;
                foreach (EndpointAuthorizationInfo entry in resolver.DescribeAll(endpoint))
                {
                    if (entry is not { Protection: EndpointProtection.DynamicPermission, Permission: { } permission, Resource: { } resource })
                    {
                        continue;
                    }

                    // A declared resource does not change the permissions of the endpoint convention.
                    bool declaredPermission = explicitPermission || (declaredResource && !endpointConvention);
                    Add(own, ResourceClaim, resource, declaredResource);
                    Add(own, PermissionClaim, permission.Permission, declaredPermission);
                    if (settings.OperationsImplyRead && PermissionKeys.Split(permission.Permission).Resource is { } permissionResource)
                    {
                        Add(own, ResourceClaim, permissionResource, declaredPermission);
                    }
                }
            }

            claims[controller] = own;
        }

        // A claim is shared by accident when two controllers make it and one of them did not declare it.
        (string Kind, string Value)[] shared =
        [
            .. claims.Values
                .SelectMany(c => c.Keys)
                .Distinct(ClaimComparer.Instance)
                .Where(claim =>
                {
                    bool[] declared = [.. claims.Values.Where(c => c.ContainsKey(claim)).Select(c => c[claim])];
                    return declared.Length > 1 && declared.Contains(false);
                })
                .OrderBy(c => c.Kind, StringComparer.Ordinal)
                .ThenBy(c => c.Value, StringComparer.Ordinal),
        ];
        if (shared.Length == 0)
        {
            return null;
        }

        Controller[] involved = [.. group.Where(c => shared.Any(claims[c].ContainsKey)).OrderBy(c => GetName(c.Type), StringComparer.Ordinal)];
        string[] resources = [.. shared.Where(c => c.Kind == ResourceClaim).Select(c => $"'{c.Value}'")];
        string[] permissions = [.. shared.Where(c => c.Kind == PermissionClaim).Select(c => $"'{c.Value}'")];
        string sharedResource = shared.Where(c => c.Kind == ResourceClaim).Select(c => c.Value).FirstOrDefault()
            ?? JoinResource(group[0].Area, group[0].Name);
        string remedy = endpointConvention
            ? "Put the controllers in different areas with [Area] or rename one of them. To share on purpose, declare on " +
              "every one of these controllers the permissions of its actions with [Permission(\"key\")] and its resource " +
              $"with [PermissionResource(\"{sharedResource}\")]."
            : "Put the controllers in different areas with [Area] or rename one of them, or give each a resource of its own " +
              "with [PermissionResource]. To share on purpose, declare the resource on every one of these controllers with " +
              $"[PermissionResource(\"{sharedResource}\")], and a permission of another resource on the actions that require " +
              "it with [Permission(\"key\")].";
        string error =
            $"The controllers {JoinNames([.. involved.Select(c => GetName(c.Type))])} have the same name, so they share " +
            string.Join(" and ", new[] { Describe("resource", resources), Describe("permission", permissions) }.OfType<string>()) +
            $": a permission granted, or a policy assigned, for one of them applies to all of them. {remedy}";

        return (error, involved);
    }

    private static void Add(Dictionary<(string Kind, string Value), bool> claims, string kind, string value, bool declared) =>
        claims[(kind, value)] = declared && claims.GetValueOrDefault((kind, value), true);

    private static string? Describe(string noun, string[] values) => values.Length switch
    {
        0 => null,
        1 => $"the {noun} {values[0]}",
        _ => $"the {noun}s {JoinNames(values)}",
    };

    private static string JoinResource(string? area, string name) =>
        area is null ? PermissionKeys.ToSegment(name) : $"{PermissionKeys.ToSegment(area)}.{PermissionKeys.ToSegment(name)}";

    private static string? GetArea(ControllerActionDescriptor action) =>
        action.RouteValues.TryGetValue("area", out string? area) && !string.IsNullOrEmpty(area) ? area : null;

    private static string GetName(TypeInfo type) => type.FullName!.Replace('+', '.');

    private static string JoinNames(string[] names) =>
        names.Length == 1 ? names[0] : $"{string.Join(", ", names[..^1])} and {names[^1]}";

    private sealed record Controller(TypeInfo Type, string? Area, string Name, Endpoint[] Endpoints);

    private sealed record Snapshot(IChangeToken ChangeToken, IReadOnlyList<string> Errors, IReadOnlyDictionary<Endpoint, string> Conflicts);

    private sealed class ClaimComparer : IEqualityComparer<(string Kind, string Value)>
    {
        public static readonly ClaimComparer Instance = new();

        public bool Equals((string Kind, string Value) x, (string Kind, string Value) y) =>
            string.Equals(x.Kind, y.Kind, StringComparison.Ordinal) && string.Equals(x.Value, y.Value, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode((string Kind, string Value) obj) =>
            HashCode.Combine(obj.Kind, StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Value));
    }
}
