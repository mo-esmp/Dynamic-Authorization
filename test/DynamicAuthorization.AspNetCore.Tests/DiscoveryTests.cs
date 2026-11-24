using System.Net;
using DynamicAuthorization.AspNetCore.Tests.Infrastructure;
using Microsoft.AspNetCore.Authorization;

namespace DynamicAuthorization.AspNetCore.Tests;

public sealed class DiscoveryTests
{
    [Fact]
    public async Task Catalog_lists_one_permission_per_resource_and_operation()
    {
        await using TestApp app = await TestApp.StartAsync();

        PermissionCatalog catalog = app.GetCatalog();

        string[] orders = [.. catalog.Permissions.Where(p => p.Resource == "orders").Select(p => p.Permission)];
        Assert.Equal(
            ["orders.read", "orders.create", "orders.update", "orders.delete", "orders.archive", "orders.export", "orders.report"],
            orders);
        Assert.Null(catalog.FindPermission("mvc::Orders:Index"));
        Assert.Null(catalog.FindPermission("orders.public"));
        Assert.Null(catalog.FindPermission("orders.mine"));
    }

    [Fact]
    public async Task Permissions_describe_their_resource_and_operation()
    {
        await using TestApp app = await TestApp.StartAsync();

        PermissionCatalog catalog = app.GetCatalog();

        PermissionDescriptor read = Assert.IsType<PermissionDescriptor>(catalog.FindPermission("orders.read"));
        Assert.Equal(("orders", "read", "Read", "Orders"), (read.Resource, read.Operation, read.DisplayName, read.Group));
        Assert.Equal("Archive", catalog.FindPermission("orders.archive")!.DisplayName);
        Assert.Equal("Export orders", catalog.FindPermission("orders.export")!.DisplayName);
        Assert.Equal("Export reports", catalog.FindPermission("reports.export")!.DisplayName);
    }

    [Theory]
    [InlineData("legacy.read", "Legacy")]
    [InlineData("admin.settings.read", "Admin / Settings")]
    [InlineData("secure.read", "Secure area")]
    [InlineData("folder.read", "Folder")]
    [InlineData("folder.update", "Folder")]
    [InlineData("products.create", "Products")]
    [InlineData("reports.schedule", "Reports")]
    public async Task Permissions_are_grouped_by_resource(string permission, string group)
    {
        await using TestApp app = await TestApp.StartAsync();

        Assert.Equal(group, app.GetCatalog().FindPermission(permission)?.Group);
    }

    [Fact]
    public async Task Controller_names_win_over_api_tags_for_shared_resources()
    {
        await using TestApp app = await TestApp.StartAsync();

        PermissionCatalog catalog = app.GetCatalog();

        Assert.All(catalog.GetEndpoints("orders.read"), e => Assert.Equal("Orders", e.Permission!.Group));
        Assert.Contains(catalog.GetEndpoints("orders.read"), e => e.Route == "/api/v1/orders");
        Assert.Contains(catalog.GetEndpoints("orders.read"), e => e.Route == "/api/legacy-orders");
        Assert.Equal("Items API", catalog.FindPermission("items.read")!.Group);
    }

    [Fact]
    public async Task Razor_page_handlers_are_listed_with_their_own_permissions()
    {
        await using TestApp app = await TestApp.StartAsync();

        EndpointAuthorizationInfo[] entries = [.. app.GetCatalog().Endpoints.Where(e => e.TargetKey == "page::/Secure/Index")];

        Assert.Equal(
            ["GET  secure.read", "POST  secure.update", "POST Archive secure.archive", "POST Delete secure.delete"],
            entries.Select(e => $"{e.HttpMethods[0]} {e.Handler} {e.Permission!.Permission}").Order());
        Assert.All(entries, e => Assert.Equal("/Secure", e.Route));
    }

    /// <summary>
    ///   With Razor runtime compilation, the endpoints of pages are created before the pages are compiled, without the
    ///   authorization, the page model attributes and the handlers that only the compiled page has. The pages are loaded
    ///   to describe them, so the catalog is the same as without runtime compilation.
    /// </summary>
    [Fact]
    public async Task Razor_pages_are_described_the_same_with_runtime_compilation()
    {
        await using TestApp compiled = await TestApp.StartAsync();
        await using TestApp runtime = await TestApp.StartAsync(o => o.RazorRuntimeCompilation = true);
        TestUser archiver = await runtime.CreateUserWithPermissionsAsync("alice", "secure.archive");

        string[] expected = DescribePages(compiled.GetCatalog());
        string[] actual = DescribePages(runtime.GetCatalog());
        HttpClient client = runtime.CreateClient(archiver);

        Assert.Contains("page::/Secure/Index /Secure POST Archive DynamicPermission secure.archive Secure 1", expected);
        Assert.Equal(expected, actual);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/Secure?handler=Archive", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsync("/Secure?handler=Delete", null)).StatusCode);
    }

    /// <summary>
    ///   MapHub maps two endpoints, the hub and the negotiate endpoint clients call first. They are one target with
    ///   one permission.
    /// </summary>
    [Fact]
    public async Task Hub_and_its_negotiate_endpoint_share_one_permission()
    {
        await using TestApp app = await TestApp.StartAsync(o =>
        {
            o.Services = s => s.AddSignalR();
            o.Endpoints = e => e.MapHub<PermissionHandlerTests.ChatHub>("/chat").RequireAuthorization();
        });
        TestUser granted = await app.CreateUserWithPermissionsAsync("alice", "chat.access");
        TestUser denied = await app.CreateUserWithPermissionsAsync("bob", "chat.negotiate");

        PermissionCatalog catalog = app.GetCatalog();
        EndpointAuthorizationInfo[] entries = [.. catalog.Endpoints.Where(e => e.Route.StartsWith("/chat", StringComparison.Ordinal))];

        EndpointAuthorizationInfo entry = Assert.Single(entries);
        Assert.Equal(("/chat", "chat.access"), (entry.Route, entry.Permission?.Permission));
        Assert.Empty(entry.HttpMethods);
        Assert.Null(catalog.FindPermission("chat.negotiate"));
        Assert.Equal(HttpStatusCode.OK, (await app.CreateClient(granted).PostAsync("/chat/negotiate?negotiateVersion=1", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await app.CreateClient(denied).PostAsync("/chat/negotiate?negotiateVersion=1", null)).StatusCode);
    }

    private static string[] DescribePages(PermissionCatalog catalog) =>
    [
        .. catalog.Endpoints
            .Where(e => e.Source == PermissionSource.Page)
            .Select(e => $"{e.TargetKey} {e.Route} {string.Join(',', e.HttpMethods)} {e.Handler} {e.Protection} {e.Permission?.Permission}"
                + $" {((e.Endpoint as RouteEndpoint)?.RoutePattern.RawText)} {e.Endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>().Count}")
    ];

    [Theory]
    [InlineData("items.read")]
    [InlineData("items.create")]
    [InlineData("items.update")]
    [InlineData("items.delete")]
    [InlineData("items.ship")]
    [InlineData("items.purge")]
    [InlineData("named.read")]
    [InlineData("strict.read")]
    [InlineData("groups.read")]
    [InlineData("products.read")]
    [InlineData("products.create")]
    [InlineData("products.update")]
    [InlineData("products.delete")]
    public async Task Catalog_contains_api_permissions(string permission)
    {
        await using TestApp app = await TestApp.StartAsync();

        Assert.NotNull(app.GetCatalog().FindPermission(permission));
    }

    [Fact]
    public async Task Custom_permissions_are_listed_with_their_resource()
    {
        await using TestApp app = await TestApp.StartAsync();

        PermissionDescriptor permission = Assert.IsType<PermissionDescriptor>(app.GetCatalog().FindPermission("reports.schedule"));

        Assert.Equal(PermissionSource.Custom, permission.Source);
        Assert.Equal(("reports", "schedule", "Schedule reports"), (permission.Resource, permission.Operation, permission.DisplayName));
    }

    [Theory]
    [InlineData("mvc::Orders:Index", EndpointProtection.DynamicPermission)]
    [InlineData("mvc::Orders:Public", EndpointProtection.AllowAnonymous)]
    [InlineData("mvc::Orders:Mine", EndpointProtection.Excluded)]
    [InlineData("mvc::Reports:Index", EndpointProtection.None)]
    [InlineData("mvc::Managers:Index", EndpointProtection.PolicyOnly)]
    [InlineData("page::/Public", EndpointProtection.None)]
    [InlineData("endpoint:GET /api/schedule", EndpointProtection.PolicyOnly)]
    public async Task Catalog_reports_how_endpoints_are_protected(string targetKey, EndpointProtection expected)
    {
        await using TestApp app = await TestApp.StartAsync();

        EndpointAuthorizationInfo endpoint = Assert.IsType<EndpointAuthorizationInfo>(app.GetCatalog().FindEndpoint(targetKey));

        Assert.Equal(expected, endpoint.Protection);
    }

    [Fact]
    public async Task Actions_with_several_http_methods_are_listed_per_method()
    {
        await using TestApp app = await TestApp.StartAsync();

        EndpointAuthorizationInfo[] endpoints = [.. app.GetCatalog().Endpoints.Where(e => e.TargetKey == "mvc::Orders:Edit")];

        Assert.Equal(2, endpoints.Length);
        Assert.Contains(endpoints, e => e.HttpMethods.SequenceEqual(["GET"]));
        Assert.Contains(endpoints, e => e.HttpMethods.SequenceEqual(["POST"]));
        Assert.All(endpoints, e => Assert.Equal("orders.update", e.Permission?.Permission));
    }

    [Fact]
    public async Task Group_root_endpoints_have_no_trailing_slash_in_their_route()
    {
        await using TestApp app = await TestApp.StartAsync();

        Assert.Contains(app.GetCatalog().Endpoints, e => e.Route == "/api/groups" && e.Permission?.Permission == "groups.read");
    }

    [Fact]
    public async Task Conventional_route_templates_are_not_listed_as_endpoints()
    {
        await using TestApp app = await TestApp.StartAsync();

        Assert.DoesNotContain(app.GetCatalog().Endpoints, e => e.Route.Contains("{controller", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("/api/hooks", "hooks.access")]
    [InlineData("/api/hooks/{id}/replay", "hooks.replay")]
    public async Task Endpoints_for_any_http_method_take_their_operation_from_the_route(string route, string permission)
    {
        await using TestApp app = await TestApp.StartAsync(o => o.Endpoints = e => e.Map(route, () => "hook").RequireAuthorization());

        Assert.Contains(app.GetCatalog().Endpoints, e => e.Route == route && e.Permission?.Permission == permission);
    }

    [Fact]
    public async Task Fallback_endpoints_without_authorization_are_not_listed()
    {
        await using TestApp app = await TestApp.StartAsync(o => o.Endpoints = e =>
        {
            e.MapFallback(() => "fallback");
            e.MapGet("/api/fallback-sibling", () => "sibling");
        });

        Assert.DoesNotContain(app.GetCatalog().Endpoints, e => e.Endpoint is RouteEndpoint { Order: int.MaxValue });
        Assert.Contains(app.GetCatalog().Endpoints, e => e.Route == "/api/fallback-sibling");
    }

    [Theory]
    [InlineData("Orders", "orders")]
    [InlineData("OrderItems", "order-items")]
    [InlineData("APIKeys", "api-keys")]
    [InlineData("Orders API", "orders-api")]
    [InlineData("DynamicAuthorization", "dynamic-authorization")]
    [InlineData("v2", "v2")]
    public void Names_are_converted_to_key_segments(string name, string expected) =>
        Assert.Equal(expected, PermissionKeys.ToSegment(name));

    [Theory]
    [InlineData(null, "Orders", "Edit", "mvc::Orders:Edit")]
    [InlineData("Admin", "Settings", "Index", "mvc:Admin:Settings:Index")]
    public void Action_keys_include_the_area(string? area, string controller, string action, string expected) =>
        Assert.Equal(expected, PermissionKeys.ForAction(area, controller, action));

    [Fact]
    public void Route_keys_are_normalized() =>
        Assert.Equal("endpoint:GET,POST /api/orders/{id}", PermissionKeys.ForRoute(["post", "GET"], "api/orders/{id}"));

    /// <summary>
    ///   Every endpoint belongs to a resource: its controller, its page folder or the first segment of its route. Policies
    ///   assigned to a resource apply to its endpoints whatever permission they require.
    /// </summary>
    [Theory]
    [InlineData(PermissionConvention.Crud)]
    [InlineData(PermissionConvention.Endpoint)]
    public async Task Endpoints_describe_the_resource_they_belong_to(PermissionConvention convention)
    {
        await using TestApp app = await TestApp.StartAsync(o =>
        {
            o.Authorization = a => a.Convention = convention;
            o.Endpoints = e =>
            {
                e.MapGet("/api/v2/invoices", () => "invoices").RequireAuthorization();
                e.MapGet("/api/orders/audit", () => "audit").RequireAuthorization().RequirePermission("reports.export");
            };
        });

        PermissionCatalog catalog = app.GetCatalog();

        Assert.Equal("orders", catalog.FindEndpoint("mvc::Orders:Index")?.Resource);
        Assert.Equal("orders", catalog.FindEndpoint("mvc::Orders:Download")?.Resource);
        Assert.Equal("admin.settings", catalog.FindEndpoint("mvc:Admin:Settings:Index")?.Resource);
        Assert.Equal("legacy", catalog.FindEndpoint("mvc::Inherited:Index")?.Resource);
        Assert.Equal("products", catalog.FindEndpoint("mvc::Products:Get")?.Resource);
        Assert.Equal("folder", catalog.FindEndpoint("page::/Folder/Page")?.Resource);
        Assert.Equal("secure", catalog.FindEndpoint("page::/Secure/Index")?.Resource);
        Assert.Equal("items", catalog.FindEndpoint("endpoint:GET /api/items")?.Resource);
        Assert.Equal("orders", catalog.FindEndpoint("endpoint:GET /api/v1/orders")?.Resource);
        Assert.Equal("orders", catalog.FindEndpoint("endpoint:GET /api/legacy-orders")?.Resource);
        Assert.Equal("invoices", catalog.FindEndpoint("endpoint:GET /api/v2/invoices")?.Resource);

        // The resource of the endpoint, not the resource of the permission it requires.
        EndpointAuthorizationInfo audit = Assert.IsType<EndpointAuthorizationInfo>(catalog.FindEndpoint("endpoint:GET /api/orders/audit"));
        Assert.Equal("reports.export", audit.Permission?.Permission);
        Assert.Equal("orders", audit.Resource);
    }

    [Fact]
    public async Task Every_entry_of_a_page_describes_the_page_resource()
    {
        await using TestApp app = await TestApp.StartAsync();

        IEnumerable<EndpointAuthorizationInfo> secure = app.GetCatalog().Endpoints.Where(e => e.TargetKey == "page::/Secure/Index");

        Assert.True(secure.Count() > 1);
        Assert.All(secure, e => Assert.Equal("secure", e.Resource));
    }

    [Fact]
    public async Task Endpoints_of_a_resource_are_listed_together_ignoring_case()
    {
        await using TestApp app = await TestApp.StartAsync();

        PermissionCatalog catalog = app.GetCatalog();

        EndpointAuthorizationInfo[] orders = [.. catalog.GetResourceEndpoints("ORDERS")];
        Assert.Contains(orders, e => e.TargetKey == "mvc::Orders:Index");
        Assert.Contains(orders, e => e.Route == "/api/v1/orders");
        Assert.Contains(orders, e => e.Route == "/api/legacy-orders");
        Assert.All(orders, e => Assert.Equal("orders", e.Resource, StringComparer.OrdinalIgnoreCase));
        Assert.Empty(catalog.GetResourceEndpoints("unknown"));
    }

    [Fact]
    public void Entries_built_without_a_resource_have_none()
    {
        EndpointAuthorizationInfo entry = new(
            new Endpoint(null, EndpointMetadataCollection.Empty, "test"), "Test", "Test", "/test", [], PermissionSource.Endpoint, null,
            EndpointProtection.None, "endpoint:GET /test", null);

        Assert.Null(entry.Resource);
        Assert.Empty(new PermissionCatalog([], [entry]).GetResourceEndpoints("test"));
    }

    /// <summary>
    ///   A permission area works like an MVC area: its route segment is skipped, and it prefixes the resource derived
    ///   from the rest of the route, whatever the version segments around it.
    /// </summary>
    [Theory]
    [InlineData("GET", "/api/admin", "admin", "admin.read")]
    [InlineData("GET", "/api/admin/orders", "admin.orders", "admin.orders.read")]
    [InlineData("POST", "/api/admin/orders", "admin.orders", "admin.orders.create")]
    [InlineData("POST", "/api/admin/orders/{id:int}/ship", "admin.orders", "admin.orders.ship")]
    [InlineData("GET", "/api/admin/orders/export", "admin.orders", "admin.orders.export")]
    [InlineData("DELETE", "/api/admin/users/{id:int}", "admin.users", "admin.users.delete")]
    [InlineData("GET", "/api/admin/reports/{id:int}", "admin.reports", "admin.reports.read")]
    [InlineData("GET", "/api/admin/audit", "admin.audit", "audit.view")]
    [InlineData("GET", "/api/admin/legacy", "legacy", "legacy.read")]
    [InlineData("POST", "/api/admin/legacy", "legacy", "legacy.create")]
    [InlineData("GET", "/api/v1/admin/invoices", "admin.invoices", "admin.invoices.read")]
    [InlineData("GET", "/api/admin/v2/invoices", "admin.invoices", "admin.invoices.read")]
    [InlineData("GET", "/api/v{version}/admin/invoices", "admin.invoices", "admin.invoices.read")]
    [InlineData("GET", "/api/back-office/stock", "back-office.stock", "back-office.stock.read")]
    [InlineData("GET", "/api/backoffice/orders", "admin.backoffice", "admin.backoffice.read")]
    [InlineData("GET", "/api/backoffice/users", "back-office.users", "back-office.users.read")]
    public async Task Minimal_api_areas_prefix_the_resource_and_keep_the_operation(string method, string route, string resource, string permission)
    {
        await using TestApp app = await TestApp.StartAsync(o => o.Endpoints = MapAdminApis);

        EndpointAuthorizationInfo entry = Assert.IsType<EndpointAuthorizationInfo>(app.GetCatalog().FindEndpoint(PermissionKeys.ForRoute([method], route)));
        Assert.Equal(resource, entry.Resource);
        Assert.Equal(permission, entry.Permission?.Permission);
    }

    [Fact]
    public async Task Minimal_api_areas_are_shown_like_controller_areas()
    {
        await using TestApp app = await TestApp.StartAsync(o => o.Endpoints = MapAdminApis);

        PermissionCatalog catalog = app.GetCatalog();

        Assert.Equal("admin / Orders", catalog.FindPermission("admin.orders.read")?.Group);
        EndpointAuthorizationInfo entry = Assert.IsType<EndpointAuthorizationInfo>(catalog.FindEndpoint("endpoint:GET /api/admin/orders"));
        Assert.Equal("admin", entry.Area);
    }

    [Fact]
    public async Task Minimal_api_areas_keep_endpoint_convention_keys()
    {
        await using TestApp app = await TestApp.StartAsync(o =>
        {
            o.Authorization = a => a.Convention = PermissionConvention.Endpoint;
            o.Endpoints = MapAdminApis;
        });

        EndpointAuthorizationInfo entry = Assert.IsType<EndpointAuthorizationInfo>(app.GetCatalog().FindEndpoint("endpoint:GET /api/admin/orders"));
        Assert.Equal("endpoint:GET /api/admin/orders", entry.Permission?.Permission);
        Assert.Equal("admin.orders", entry.Resource);
    }

    [Fact]
    public void Permission_area_must_not_be_empty()
    {
        Assert.Throws<ArgumentException>(() => new PermissionAreaMetadata(" "));
        Assert.ThrowsAny<ArgumentException>(() => new PermissionAreaMetadata(null!));
    }

    /// <summary>
    ///   A POST to a collection is a create. With an explicit resource, the collection is the route segment named
    ///   after the resource, however many segments come before it.
    /// </summary>
    [Theory]
    [InlineData("/api/legacy/orders", "admin.orders.create")]
    [InlineData("/api/legacy/orders/{id:int}/ship", "admin.orders.ship")]
    [InlineData("/api/legacy/orders/archive", "admin.orders.archive")]
    [InlineData("/api/items/{id:int}/ship", "items.ship")]
    [InlineData("/api/catalog/order-items", "OrderItems.create")]
    public async Task Posts_to_an_explicit_resource_collection_create(string route, string permission)
    {
        await using TestApp app = await TestApp.StartAsync(o => o.Endpoints = e =>
        {
            RouteGroupBuilder legacy = e.MapGroup("/api/legacy/orders").RequireAuthorization().WithPermissionResource("admin.orders");
            legacy.MapPost("", () => "created");
            legacy.MapPost("/{id:int}/ship", (int id) => "shipped");
            legacy.MapPost("/archive", () => "archived");
            e.MapPost("/api/catalog/order-items", () => "created").RequireAuthorization().WithPermissionResource("OrderItems");
        });

        EndpointAuthorizationInfo entry = Assert.IsType<EndpointAuthorizationInfo>(app.GetCatalog().FindEndpoint(PermissionKeys.ForRoute(["POST"], route)));
        Assert.Equal(permission, entry.Permission?.Permission);
    }

    private static void MapAdminApis(IEndpointRouteBuilder e)
    {
        RouteGroupBuilder admin = e.MapGroup("/api/admin").RequireAuthorization().WithPermissionArea("admin");
        admin.MapGet("", () => "admin");
        admin.MapGet("/orders", () => "orders");
        admin.MapPost("/orders", () => "created");
        admin.MapPost("/orders/{id:int}/ship", (int id) => "shipped");
        admin.MapGet("/orders/export", () => "export").RequirePermissionOperation("export");
        admin.MapDelete("/users/{id:int}", (int id) => "deleted");
        admin.MapGroup("/reports").MapGet("/{id:int}", (int id) => "report");
        admin.MapGet("/audit", () => "audit").RequirePermission("audit.view");
        admin.MapGet("/legacy", () => "legacy").WithPermissionResource("legacy");
        admin.MapPost("/legacy", () => "legacy").WithPermissionResource("legacy");
        e.MapGet("/api/v1/admin/invoices", () => "v1").RequireAuthorization().WithPermissionArea("admin");
        e.MapGet("/api/admin/v2/invoices", () => "v2").RequireAuthorization().WithPermissionArea("admin");
        e.MapGet("/api/v{version}/admin/invoices", (string version) => version).RequireAuthorization().WithPermissionArea("admin");
        e.MapGet("/api/back-office/stock", () => "stock").RequireAuthorization().WithPermissionArea("BackOffice");
        e.MapGet("/api/backoffice/orders", () => "back office").RequireAuthorization().WithPermissionArea("admin");
        e.MapGet("/api/backoffice/users", () => "back office users").RequireAuthorization().WithPermissionArea("BackOffice");
    }
}
