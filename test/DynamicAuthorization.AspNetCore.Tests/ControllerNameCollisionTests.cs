using System.Net;
using System.Reflection;
using DynamicAuthorization.AspNetCore.Tests.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.Primitives;

namespace DynamicAuthorization.AspNetCore.Tests;

/// <summary>
///   Two controllers with the same name in different namespaces and the same area are the same resource, so their
///   actions would silently require the same permissions and get the same assigned policies: granting one would grant
///   the other.
/// </summary>
public sealed class ControllerNameCollisionTests
{
    [Fact]
    public async Task Controllers_with_the_same_name_must_not_share_permissions_implicitly()
    {
        string message = await StartFailingAsync(typeof(Admin.WidgetsController), typeof(Client.WidgetsController));

        Assert.Contains(Name(typeof(Admin.WidgetsController)), message, StringComparison.Ordinal);
        Assert.Contains(Name(typeof(Client.WidgetsController)), message, StringComparison.Ordinal);
        Assert.Contains("the resource 'widgets'", message, StringComparison.Ordinal);
        Assert.Contains("the permission 'widgets.read'", message, StringComparison.Ordinal);
        Assert.DoesNotContain("widgets.create", message, StringComparison.Ordinal);
        Assert.Contains("[Area]", message, StringComparison.Ordinal);
        Assert.Contains("[PermissionResource(\"widgets\")]", message, StringComparison.Ordinal);
        Assert.DoesNotContain("[ControllerName]", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Controllers_with_the_same_name_must_not_share_endpoint_permissions()
    {
        string message = await StartFailingAsync(
            o => o.Convention = PermissionConvention.Endpoint, typeof(Admin.WidgetsController), typeof(Client.WidgetsController));

        Assert.Contains("'mvc::Widgets:Get'", message, StringComparison.Ordinal);
        Assert.Contains("[Area]", message, StringComparison.Ordinal);
        Assert.Contains("[Permission(\"key\")]", message, StringComparison.Ordinal);
    }

    /// <summary>
    ///   A declared resource does not change the permissions of the endpoint convention.
    /// </summary>
    [Fact]
    public async Task Declared_resources_do_not_separate_endpoint_permissions()
    {
        string message = await StartFailingAsync(
            o => o.Convention = PermissionConvention.Endpoint, typeof(Admin.GadgetsController), typeof(Client.GadgetsController));

        Assert.Contains("the permission 'mvc::Gadgets:Get'", message, StringComparison.Ordinal);
        Assert.DoesNotContain("share the resource", message, StringComparison.Ordinal);
    }

    /// <summary>
    ///   Without a common permission, the controllers still share their resource: the policies assigned to it and, when
    ///   any operation implies read, the read access a grant of another operation gives.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Controllers_with_the_same_name_must_not_share_a_resource(bool operationsImplyRead)
    {
        string message = await StartFailingAsync(
            o => o.OperationsImplyRead = operationsImplyRead, typeof(Admin.PartsController), typeof(Client.PartsController));

        Assert.Contains("share the resource 'parts':", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Sharing_a_resource_requires_every_controller_to_declare_it()
    {
        string message = await StartFailingAsync(typeof(Admin.BoltsController), typeof(Client.BoltsController));

        Assert.Contains("the resource 'bolts' and the permission 'bolts.read'", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Sharing_a_permission_requires_every_controller_to_declare_it()
    {
        string message = await StartFailingAsync(typeof(Admin.NutsController), typeof(Client.NutsController));

        Assert.Contains("the permission 'nuts.read'", message, StringComparison.Ordinal);
        Assert.DoesNotContain("admin-nuts", message, StringComparison.Ordinal);
    }

    /// <summary>
    ///   Areas are converted to key segments, so BackOffice and Back-Office are one resource.
    /// </summary>
    [Fact]
    public async Task Controllers_in_areas_that_are_the_same_resource_must_not_share_permissions()
    {
        string message = await StartFailingAsync(typeof(Admin.ScrewsController), typeof(Client.ScrewsController));

        Assert.Contains("the resource 'back-office.screws'", message, StringComparison.Ordinal);
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
        TestUser reader = await app.CreateUserWithPermissionsAsync("alice", "tools.read");
        HttpClient http = app.CreateClient(reader);

        string[] routes = [.. app.GetCatalog().GetEndpoints("tools.read").Select(e => e.Route).Order(StringComparer.Ordinal)];

        Assert.Equal(["/api/admin/tools", "/api/client/tools"], routes);
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync("/api/admin/tools")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync("/api/client/tools")).StatusCode);
    }

    [Fact]
    public async Task Controllers_with_the_same_name_without_permissions_are_allowed()
    {
        await using TestApp app = await TestApp.StartAsync(o =>
            o.Controllers = [typeof(Admin.PingController), typeof(Client.PingController)]);

        Assert.Equal(2, app.GetCatalog().Endpoints.Count(e => e.Route.EndsWith("/ping", StringComparison.Ordinal)));
    }

    /// <summary>
    ///   The start only validates the controllers it sees. Authorization checks the endpoints requests are routed to, so
    ///   a controller added later cannot share the grants of an existing one either: both are denied.
    /// </summary>
    [Fact]
    public async Task Controllers_added_at_runtime_with_the_same_name_are_denied()
    {
        RuntimeControllers controllers = new(typeof(Admin.WidgetsController));
        await using TestApp app = await TestApp.StartAsync(o => o.Services = s =>
        {
            s.AddSingleton<IActionDescriptorChangeProvider>(controllers);
            s.AddMvcCore().ConfigureApplicationPartManager(m => m.FeatureProviders.Add(controllers));
        });
        TestUser reader = await app.CreateUserWithPermissionsAsync("alice", "widgets.read");
        HttpClient http = app.CreateClient(reader);
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync("/api/admin/widgets")).StatusCode);

        controllers.Add(typeof(Client.WidgetsController));

        Assert.Equal(HttpStatusCode.Forbidden, (await http.GetAsync("/api/client/widgets")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await http.GetAsync("/api/admin/widgets")).StatusCode);
    }

    /// <summary>
    ///   Applications without routing, such as workers that only check permissions in code, have no endpoints to
    ///   validate and still start.
    /// </summary>
    [Fact]
    public async Task Applications_without_routing_start()
    {
        HostApplicationBuilder builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Services.AddDynamicAuthorization();
        using IHost host = builder.Build();

        await host.StartAsync(TestContext.Current.CancellationToken);
        await host.StopAsync(TestContext.Current.CancellationToken);
    }

    private static Task<string> StartFailingAsync(params Type[] controllers) => StartFailingAsync(null, controllers);

    private static async Task<string> StartFailingAsync(Action<DynamicAuthorizationOptions>? configure, params Type[] controllers)
    {
        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            TestApp.StartAsync(o =>
            {
                o.Authorization = configure;
                o.Controllers = controllers;
            }));

        return exception.Message;
    }

    private static string Name(Type type) => type.FullName!.Replace('+', '.');

    private sealed class RuntimeControllers(params Type[] initial) : IActionDescriptorChangeProvider, IApplicationFeatureProvider<ControllerFeature>
    {
        private readonly List<Type> _controllers = [.. initial];
        private CancellationTokenSource _changed = new();

        public void Add(Type controller)
        {
            _controllers.Add(controller);
            CancellationTokenSource changed = Interlocked.Exchange(ref _changed, new CancellationTokenSource());
            changed.Cancel();
            changed.Dispose();
        }

        public IChangeToken GetChangeToken() => new CancellationChangeToken(_changed.Token);

        public void PopulateFeature(IEnumerable<ApplicationPart> parts, ControllerFeature feature)
        {
            foreach (Type controller in _controllers)
            {
                feature.Controllers.Add(controller.GetTypeInfo());
            }
        }
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

        [ApiController]
        [Authorize]
        [Route("api/admin/parts")]
        internal sealed class PartsController : ControllerBase
        {
            [HttpGet]
            public IActionResult Get() => Ok("admin parts");
        }

        [ApiController]
        [Authorize]
        [PermissionResource("bolts")]
        [Route("api/admin/bolts")]
        internal sealed class BoltsController : ControllerBase
        {
            [HttpGet]
            public IActionResult Get() => Ok("admin bolts");
        }

        [ApiController]
        [Authorize]
        [PermissionResource("admin-nuts")]
        [Route("api/admin/nuts")]
        internal sealed class NutsController : ControllerBase
        {
            [HttpGet]
            [Permission("nuts.read")]
            public IActionResult Get() => Ok("admin nuts");
        }

        [ApiController]
        [Area("BackOffice")]
        [Authorize]
        [Route("api/backoffice/screws")]
        internal sealed class ScrewsController : ControllerBase
        {
            [HttpGet]
            public IActionResult Get() => Ok("admin screws");
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

        [ApiController]
        [Authorize]
        [Route("api/client/parts")]
        internal sealed class PartsController : ControllerBase
        {
            [HttpPut("{id:int}")]
            public IActionResult Put(int id) => Ok(id);
        }

        [ApiController]
        [Authorize]
        [Route("api/client/bolts")]
        internal sealed class BoltsController : ControllerBase
        {
            [HttpGet]
            public IActionResult Get() => Ok("client bolts");
        }

        [ApiController]
        [Authorize]
        [Route("api/client/nuts")]
        internal sealed class NutsController : ControllerBase
        {
            [HttpGet]
            public IActionResult Get() => Ok("client nuts");
        }

        [ApiController]
        [Area("Back-Office")]
        [Authorize]
        [Route("api/back-office/screws")]
        internal sealed class ScrewsController : ControllerBase
        {
            [HttpGet]
            public IActionResult Get() => Ok("client screws");
        }
    }
}
