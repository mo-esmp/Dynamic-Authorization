using System.Net;
using DynamicAuthorization.AspNetCore.Tests.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DynamicAuthorization.AspNetCore.Tests;

/// <summary>
///   Two controllers with the same name in different namespaces and the same area are the same resource, so their
///   actions would silently require the same permissions: granting one would grant the other.
/// </summary>
public sealed class ControllerNameCollisionTests
{
    [Fact]
    public async Task Controllers_with_the_same_name_must_not_share_permissions_implicitly()
    {
        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            TestApp.StartAsync(o => o.Controllers = [typeof(Admin.WidgetsController), typeof(Client.WidgetsController)]));

        Assert.Contains(typeof(Admin.WidgetsController).FullName!.Replace('+', '.'), exception.Message, StringComparison.Ordinal);
        Assert.Contains(typeof(Client.WidgetsController).FullName!.Replace('+', '.'), exception.Message, StringComparison.Ordinal);
        Assert.Contains("widgets.read", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("widgets.create", exception.Message, StringComparison.Ordinal);
        Assert.Contains("[Area]", exception.Message, StringComparison.Ordinal);
        Assert.Contains("[PermissionResource]", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Controllers_with_the_same_name_must_not_share_endpoint_permissions()
    {
        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            TestApp.StartAsync(o =>
            {
                o.Authorization = a => a.Convention = PermissionConvention.Endpoint;
                o.Controllers = [typeof(Admin.WidgetsController), typeof(Client.WidgetsController)];
            }));

        Assert.Contains("mvc::Widgets:Get", exception.Message, StringComparison.Ordinal);
        Assert.Contains("[Area]", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Controllers_with_the_same_name_and_resources_of_their_own_are_listed_and_authorized_separately()
    {
        await using TestApp app = await TestApp.StartAsync(o =>
            o.Controllers = [typeof(Admin.GadgetsController), typeof(Client.GadgetsController)]);
        TestUser client = await app.CreateUserWithPermissionsAsync("alice", "client-gadgets.read");
        HttpClient http = app.CreateClient(client);

        string[] entries =
        [
            .. app.GetCatalog().Endpoints
                .Where(e => e.Route.EndsWith("/gadgets", StringComparison.Ordinal))
                .Select(e => $"{e.HttpMethods[0]} {e.Route} {e.Permission!.Permission}")
                .Order(StringComparer.Ordinal),
        ];

        Assert.Equal(
            ["GET /api/admin/gadgets admin-gadgets.read", "GET /api/client/gadgets client-gadgets.read", "POST /api/admin/gadgets admin-gadgets.create"],
            entries);
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync("/api/client/gadgets")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await http.GetAsync("/api/admin/gadgets")).StatusCode);
    }

    [Fact]
    public async Task Controllers_with_the_same_name_can_share_a_declared_resource()
    {
        await using TestApp app = await TestApp.StartAsync(o =>
            o.Controllers = [typeof(Admin.ToolsController), typeof(Client.ToolsController)]);

        string[] routes = [.. app.GetCatalog().GetEndpoints("tools.read").Select(e => e.Route).Order(StringComparer.Ordinal)];

        Assert.Equal(["/api/admin/tools", "/api/client/tools"], routes);
    }

    [Fact]
    public async Task Controllers_with_the_same_name_without_permissions_are_allowed()
    {
        await using TestApp app = await TestApp.StartAsync(o =>
            o.Controllers = [typeof(Admin.PingController), typeof(Client.PingController)]);

        Assert.Equal(2, app.GetCatalog().Endpoints.Count(e => e.Route.EndsWith("/ping", StringComparison.Ordinal)));
    }

    internal static class Admin
    {
        [ApiController]
        [Authorize]
        [Route("api/admin/widgets")]
        internal sealed class WidgetsController : ControllerBase
        {
            [HttpGet]
            public IActionResult Get() => Ok("admin widgets");

            [HttpPost]
            public IActionResult Post() => Ok("created");
        }

        [ApiController]
        [Authorize]
        [PermissionResource("admin-gadgets")]
        [Route("api/admin/gadgets")]
        internal sealed class GadgetsController : ControllerBase
        {
            [HttpGet]
            public IActionResult Get() => Ok("admin gadgets");

            [HttpPost]
            public IActionResult Post() => Ok("created");
        }

        [ApiController]
        [Authorize]
        [PermissionResource("tools")]
        [Route("api/admin/tools")]
        internal sealed class ToolsController : ControllerBase
        {
            [HttpGet]
            public IActionResult Get() => Ok("admin tools");
        }

        [ApiController]
        [Route("api/admin/ping")]
        internal sealed class PingController : ControllerBase
        {
            [HttpGet]
            public IActionResult Get() => Ok("admin");
        }
    }

    internal static class Client
    {
        [ApiController]
        [Authorize]
        [Route("api/client/widgets")]
        internal sealed class WidgetsController : ControllerBase
        {
            [HttpGet]
            public IActionResult Get() => Ok("client widgets");
        }

        [ApiController]
        [Authorize]
        [PermissionResource("client-gadgets")]
        [Route("api/client/gadgets")]
        internal sealed class GadgetsController : ControllerBase
        {
            [HttpGet]
            public IActionResult Get() => Ok("client gadgets");
        }

        [ApiController]
        [Authorize]
        [PermissionResource("tools")]
        [Route("api/client/tools")]
        internal sealed class ToolsController : ControllerBase
        {
            [HttpGet]
            public IActionResult Get() => Ok("client tools");
        }

        [ApiController]
        [Route("api/client/ping")]
        internal sealed class PingController : ControllerBase
        {
            [HttpGet]
            public IActionResult Get() => Ok("client");
        }
    }
}
