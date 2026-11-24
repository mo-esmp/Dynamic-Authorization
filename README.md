# Dynamic Authorization for ASP.NET Core

[![CI](https://github.com/mo-esmp/Dynamic-Authorization/actions/workflows/ci.yml/badge.svg)](https://github.com/mo-esmp/Dynamic-Authorization/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/DynamicAuthorization.AspNetCore.svg)](https://www.nuget.org/packages/DynamicAuthorization.AspNetCore)

You already know role-based authorization in ASP.NET Core:

```csharp
[Authorize(Roles = "Administrator")]
public class AdministrationController : Controller
{
}
```

But what if you don't want to hard-code roles, and want to create roles later and decide what each one can access, without
touching the source code?

![dynamic-auth.jpg (2288×1008)](https://raw.githubusercontent.com/mo-esmp/Dynamic-Authorization/refs/heads/main/assets/dynamic-auth.jpg)

**Dynamic Authorization** turns every `[Authorize]` endpoint into a permission that you grant to roles at runtime. It works with
**MVC controllers, Razor Pages and Minimal APIs**, stores permissions in your **ASP.NET Core Identity database with Entity
Framework Core** (any provider), and ships a **dashboard** to manage roles, permissions and user roles.

## Contents

- [Packages](#packages)
- [Getting started](#getting-started)
  - [1. Install the packages](#1-install-the-packages)
  - [2. Add the permissions table to your Identity context](#2-add-the-permissions-table-to-your-identity-context)
  - [3. Register dynamic authorization](#3-register-dynamic-authorization)
- [Permissions: resources and operations](#permissions-resources-and-operations)
  - [Overriding the convention](#overriding-the-convention)
  - [Permission-checking only some APIs](#permission-checking-only-some-apis)
  - [One permission per endpoint](#one-permission-per-endpoint)
  - [What is permission-checked](#what-is-permission-checked)
  - [Display names](#display-names)
  - [Permissions checked in code](#permissions-checked-in-code)
- [Assigning policies to resources](#assigning-policies-to-resources)
- [Showing content only to users who may access it](#showing-content-only-to-users-who-may-access-it)
- [Super admins](#super-admins)
- [Dashboard](#dashboard)
  - [Searching users](#searching-users)
- [Caching and multiple instances](#caching-and-multiple-instances)
  - [Sharing the cache between instances](#sharing-the-cache-between-instances)
- [Options](#options)
- [Migrating from 1.x](#migrating-from-1x)
- [Sample](#sample)
- [Building](#building)
- [License](#license)

## Packages

| Package | Description |
| --- | --- |
| `DynamicAuthorization.AspNetCore` | Permission discovery, the authorization handler, the `secure-content` tag helper and `IPermissionChecker`. |
| `DynamicAuthorization.AspNetCore.EntityFrameworkCore` | Stores role permissions in your Identity `DbContext`, with any EF Core provider. |
| `DynamicAuthorization.AspNetCore.Dashboard` | A Razor Pages dashboard to manage roles, user roles and the policies assigned to resources, inspect endpoints and check access. |
| `DynamicAuthorization.AspNetCore.HybridCache` | Caches user roles and role permissions in `HybridCache`, shared between instances through a distributed cache. |

Version 2 targets **.NET 10** and **.NET 11**. Version 1.x (`DynamicAuthorization.Mvc.*`) remains available for older frameworks; see
[Migrating from 1.x](#migrating-from-1x).

## Getting started

### 1. Install the packages

```shell
dotnet add package DynamicAuthorization.AspNetCore.EntityFrameworkCore
dotnet add package DynamicAuthorization.AspNetCore.Dashboard
```

### 2. Add the permissions table to your Identity context

```csharp
public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : IdentityDbContext(options)
{
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.EnableDynamicAuthorization(); // adds the AspNetRolePermissions table
    }
}
```

Any context that derives from `IdentityDbContext` with roles works, including custom user and role types, other key types
(`int`, `Guid`, ...) and contexts that inherit through your own base class. Then add a migration:

```shell
dotnet ef migrations add AddDynamicAuthorization
```

### 3. Register dynamic authorization

```csharp
builder.Services
    .AddIdentity<IdentityUser, IdentityRole>()            // roles are required
    .AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services
    .AddDynamicAuthorization(options => options.SuperAdminUsers.Add("admin@example.com"))
    .AddEntityFrameworkStore<ApplicationDbContext>()
    .AddDashboard();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();
app.MapDynamicAuthorizationDashboard();                   // https://your-app/authz
```

That's it: every endpoint protected by `[Authorize]` now requires a permission, such as `orders.read` or `orders.update`.
Sign in as the super admin, open `/authz`, create roles, choose their permissions and assign them to users.

## Permissions: resources and operations

Permissions are named `{resource}.{operation}`. The **resource** comes from the controller, the Razor Pages folder or the
route. The **operation** is `read`, `create`, `update` or `delete`, or a custom operation such as `archive`:

| Endpoint | Permission |
| --- | --- |
| `OrdersController.Index`, `.Details`, any other `[HttpGet]` action | `orders.read` |
| `OrdersController.Create` (GET and POST) | `orders.create` |
| `OrdersController.Edit` (GET and POST) | `orders.update` |
| `OrdersController.Delete` (GET and POST) | `orders.delete` |
| `[HttpPost] OrdersController.Archive` | `orders.archive` |
| `[Area("Admin")] ReportsController.Index` | `admin.reports.read` |
| `/Orders/Index` and `/Orders/Details` pages | `orders.read` |
| `/Orders/Edit` page, `OnGet` and `OnPost` | `orders.update` |
| `/Orders/Index` page, `OnPostArchive` handler | `orders.archive` |
| `GET /api/orders`, `GET /api/orders/{id}` | `orders.read` |
| `POST /api/orders` | `orders.create` |
| `PUT` or `PATCH /api/orders/{id}` | `orders.update` |
| `DELETE /api/orders/{id}` | `orders.delete` |
| `POST /api/orders/{id}/ship` | `orders.ship` |

The operation is inferred in this order; the first rule that matches wins:

1. An override: `[Permission(...)]`, `.RequirePermission(...)` or `.RequirePermissionOperation(...)`.
2. The name of the action, page, page handler or endpoint (`WithName`): `Index`, `Details`, `List` and `Get…` mean read;
   `Create`, `Add…`, `New…` and `Post…` create; `Edit`, `Update…`, `Put…` and `Patch…` update; `Delete…` and `Remove…` delete.
3. The HTTP method, when it is unambiguous: GET means read, PUT and PATCH update, DELETE delete, and a POST to a collection
   (`POST /api/orders`) create.
4. Otherwise, the operation is named after the action, page handler or last route segment: `POST Orders/Approve` requires
   `orders.approve`. A POST is never guessed to be a create.

Endpoints with the same resource share its permissions: `orders.read` grants the read actions of `OrdersController`, the
pages in `/Orders` and `GET /api/orders` alike. Areas are part of the resource (`admin.reports`). A Minimal API's resource
is the first route segment after `api` and a version segment, so `/api/v2/orders` is `orders` too. A Minimal API area
(`WithPermissionArea("admin")`, see [Permission-checking only some APIs](#permission-checking-only-some-apis)) skips its
own segment and prefixes the resource: `/api/admin/orders` is `admin.orders`.

**Any operation implies read.** A role granted `orders.update` can also open the pages that require `orders.read`, such
as the list that links to the edit form. Set `OperationsImplyRead = false` to require read explicitly.

**Razor Page handlers are authorized separately.** `OnPostArchive` on the orders page requires `orders.archive` although
`OnGet` only requires `orders.read`.

### Overriding the convention

```csharp
[Permission("orders.approve")]                        // an explicit permission
public IActionResult Approve(int id) { ... }

[HttpPost]
[Permission(Operation = PermissionOperation.Update)]  // the derived resource with another operation: orders.update
public IActionResult Reopen(int id) { ... }

[PermissionResource("sales-orders", DisplayName = "Sales orders")]  // another resource for the whole controller
public class OrdersController : Controller { ... }

app.MapPost("/api/orders/{id}/approve", Approve).RequirePermission("orders.approve");
app.MapPost("/api/orders/{id}/reopen", Reopen).RequirePermissionOperation(PermissionOperation.Update);
app.MapGroup("/api/v1/sales").WithPermissionResource("orders");
app.MapGroup("/api/admin").WithPermissionArea("admin");              // like [Area("Admin")]: admin.orders, admin.users, ...
```

`[Permission]` also works on page handler methods, for example on `OnPostApprove`.

### Permission-checking only some APIs

To check permissions only on some endpoints, such as the admin APIs, and leave the others to plain `[Authorize]`, turn
off `ApplyToDefaultPolicy` and require dynamic authorization where you want it. Put the admin endpoints in an area so
that they get permissions of their own:

```csharp
builder.Services.AddDynamicAuthorization(options => options.ApplyToDefaultPolicy = false);

app.MapGroup("/api/client").RequireAuthorization();                 // any signed-in user

RouteGroupBuilder admin = app.MapGroup("/api/admin")
    .RequireDynamicAuthorization()                                  // a granted permission
    .WithPermissionArea("admin");
admin.MapGet("/orders", ...);
admin.MapPost("/orders", ...);
```

| Endpoint | Permission |
| --- | --- |
| `GET /api/admin/orders` | `admin.orders.read` |
| `POST /api/admin/orders` | `admin.orders.create` |
| `POST /api/admin/orders/{id}/ship` | `admin.orders.ship` |
| `DELETE /api/admin/users/{id}` | `admin.users.delete` |
| `GET /api/v2/admin/orders`, `GET /api/admin/v2/orders` | `admin.orders.read` |

Without the area, every admin endpoint would belong to one `admin` resource, and `admin.read` would grant reading
everything under `/api/admin`. The area's route segment is skipped wherever the version segments are, so all versions
share a permission; the area matches its segment whatever the case and separators (`BackOffice` matches
`/api/backoffice` and `/api/back-office`). An area works like `[Area("Admin")]` on a controller: `[Area("Admin")]
OrdersController` and `/api/admin/orders` share the `admin.orders` permissions and the policies assigned to that
resource, and `IgnoredAreas` applies to both. `WithPermissionResource` replaces the whole resource, area included.

You can also keep `ApplyToDefaultPolicy` and exclude the client APIs with `.IgnoreDynamicAuthorization()` instead. Turning
the default off is safer: a new endpoint is never permission-checked by accident, only by asking for it.

### One permission per endpoint

To grant each action, page and route individually instead, use the endpoint convention:

```csharp
options.Convention = PermissionConvention.Endpoint;
```

Permissions are then named `mvc:{area}:{controller}:{action}` (`mvc::Orders:Edit`), `page:{area}:{page}`
(`page::/Orders/Edit`), and `endpoint:{name}` or `endpoint:{methods} {route}` (`endpoint:GET /api/orders`). All handlers of
a page share its permission.

### What is permission-checked

With the default options, the permission check is added to ASP.NET Core's **default authorization policy**. Every endpoint
protected by a plain `[Authorize]`, `RequireAuthorization()` or `AuthorizeFolder()` requires a permission, with no
attribute changes. What is **not** permission-checked:

- `[AllowAnonymous]` endpoints.
- `[Authorize(Roles = "...")]` or `[Authorize(Policy = "...")]` without a plain `[Authorize]`: you already chose static
  authorization for those.
- Endpoints marked `[IgnoreDynamicAuthorization]` or `.IgnoreDynamicAuthorization()`, and areas listed in `IgnoredAreas`
  (`Identity` by default, so the Identity UI account pages stay available), including Minimal API areas set with
  `WithPermissionArea`. They still require a signed-in user.

`RequireDynamicAuthorization()` requires the permission even when `ApplyToDefaultPolicy` is disabled.

Your own policies are permission-checked when they include the requirement: `options.AddPolicy("Managers", p =>
p.RequireRole("Manager").AddRequirements(new DynamicPermissionRequirement()))` requires the role and the endpoint's
permission. Inline policies passed to `RequireAuthorization(policy)` replace the default policy, as in ASP.NET Core, so
they are permission-checked only when they include the requirement. The fallback policy can require an explicit
permission (`new DynamicPermissionRequirement("app.access")`) but not the permission of the endpoint: endpoints without
authorization metadata have none, and startup fails with an explanation.

A SignalR hub is one endpoint, although `MapHub` maps two: `MapHub<ChatHub>("/chat").RequireAuthorization()` requires
`chat.access` for the hub and for `/chat/negotiate`, which clients call first.

Razor runtime compilation is supported. Its pages are compiled when they are first described, for example when the
dashboard lists the endpoints, rather than on their first request, because only a compiled page has its authorization,
page model attributes and handlers.

### Display names

The dashboard names resources after the controller's `[DisplayName]` (or its name), the page folder or the Minimal API tag.
Set `[PermissionResource(..., DisplayName = "...")]` to rename one. Custom operations take the action's `[DisplayName]`:

```csharp
[Authorize, DisplayName("Orders")]
public class OrdersController : Controller
{
    [HttpPost, DisplayName("Approve orders")]
    public IActionResult Approve(int id) { ... }
}
```

### Permissions checked in code

Declare permissions that are not bound to an endpoint, and check them with `IPermissionChecker`, the tag helper, or a
policy. Name them `{resource}.{operation}` to list them with their resource in the dashboard:

```csharp
builder.Services.AddDynamicAuthorization(options => options.AddPermission("orders.export", "Export orders"));

if (await permissionChecker.HasPermissionAsync(User, "orders.export")) { ... }

builder.Services.AddAuthorization(options =>
    options.AddPolicy("CanExport", policy => policy.AddRequirements(new DynamicPermissionRequirement("orders.export"))));
```

## Assigning policies to resources

Instead of hard-coding `[Authorize(Policy = "...")]` on pages and endpoints, let admins assign your authorization
policies to resources in the dashboard. Every request to a permission-checked endpoint of the resource must then pass the
assigned policies, **in addition to** its permission. Policies stay defined in code; only their assignment changes at
runtime, without a redeploy.

Declare which policies admins may assign, and enable the table that stores the assignments:

```csharp
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("BusinessHours", policy => policy.AddRequirements(new BusinessHoursRequirement()))
    .AddPolicy("RequireMfa", policy => policy.RequireClaim("amr", "mfa"));

builder.Services
    .AddDynamicAuthorization(options =>
    {
        options.AddAssignablePolicy("BusinessHours", "Business hours", "Monday to Friday, 8:00 to 18:00.");
        options.AddAssignablePolicy("RequireMfa", "Multi-factor sign-in");
    })
    .AddEntityFrameworkStore<ApplicationDbContext>()
    .AddDashboard();

// In OnModelCreating, then add a migration:
modelBuilder.EnableDynamicAuthorization(o => o.ResourcePolicies = true); // adds the AspNetResourcePolicies table
```

The table is opt-in, so applications that don't assign policies have nothing to migrate. Admins then choose each resource's
policies on the dashboard's **Policies** page, which exists only while a policy is assignable.

- **Per resource.** A policy assigned to `orders` applies to every permission-checked endpoint of the resource: the
  `OrdersController` actions, the `/Orders` pages and `/api/orders`, whatever the operation. The resource is the endpoint's
  own (its controller, page folder or route, or `[PermissionResource]`), not the resource of the permission it requires:
  `[Permission("reports.export")]` on an `OrdersController` action is guarded by the policies of `orders`.
- **All must pass.** Every assigned policy must succeed, like stacked `[Authorize(Policy = ...)]` attributes. Assignments
  never grant a permission; they only add restrictions.
- **Super admins skip them**, without the assignments even being read, so they keep access if the store is unavailable.
  Super admins are the way back in if a policy can never pass. The dashboard's own resources (`authz.*`) take policies
  only while a super admin user or role is configured, and their policies are skipped if a later configuration has none,
  so nobody can be locked out of it.
- **Requests only.** Assigned policies apply when a request is authorized. Endpoints that are not permission-checked
  (`[AllowAnonymous]`, `[IgnoreDynamicAuthorization]`, ignored areas, or protected only by roles or named policies) and
  explicit permissions (`new DynamicPermissionRequirement("orders.export")`) are not affected, and neither are
  `IPermissionChecker` and the `secure-content` tag helper: a link can be shown for a page that an assigned policy denies.
- **Names, not schemes.** Policies are resolved by name through the `IAuthorizationPolicyProvider`, so a custom provider can
  supply them. A policy with authentication schemes, or one that itself requires a dynamic permission, cannot be assigned:
  it would mean something else when evaluated after the permission, so it denies if it shows up anyway. An endpoint
  protected by a named policy that only a custom provider knows is treated as statically protected and gets no assigned
  policies.
- **Removing a registration.** A stored assignment of a policy that is no longer registered with `AddAssignablePolicy` is
  skipped (with a warning in the log and on the Overview page), and enforced again if the policy is registered again.
  During a rolling deployment, instances with different registrations can therefore enforce different policies. A
  registered policy that the provider cannot find denies.

Assigned policies receive the authorization resource the request was authorized with (the `HttpContext`, or an MVC
filter context), as they would on the endpoint itself. Replacing a resource's policies runs in a serializable transaction:
of two concurrent edits, the last to commit wins, and on some providers the other fails with a serialization error and
can be saved again.

Assignments are cached like role permissions, as one entry; the management service invalidates it when they change. Use
`IResourcePolicyManagementService` to change them in code, or call `IDynamicAuthorizationCache.InvalidateResourcePoliciesAsync`
after changing the store yourself. To store them elsewhere, implement `IResourcePolicyStore`.

## Showing content only to users who may access it

Add the tag helper in `_ViewImports.cshtml`:

```cshtml
@addTagHelper *, DynamicAuthorization.AspNetCore
```

Then wrap content in `secure-content`. Pages and actions are evaluated with their complete authorization policy, exactly as the
request would be, so links to anonymous pages are always shown and links to role-protected pages are shown to role members:

```cshtml
<secure-content asp-page="/Orders/Index">
    <a asp-page="/Orders/Index">Orders</a>
</secure-content>

<secure-content asp-area="Admin" asp-controller="Reports" asp-action="Index">
    <a asp-area="Admin" asp-controller="Reports" asp-action="Index">Reports</a>
</secure-content>

<secure-content asp-page="/Orders/Index" asp-page-handler="Archive">
    <button form="archive">Archive</button>
</secure-content>

<secure-content asp-permission="orders.export">
    <button>Export</button>
</secure-content>
```

## Super admins

Super admins have every permission, which lets you bootstrap the first administrator before any role exists:

```csharp
options.SuperAdminUsers.Add("admin@example.com"); // by username
options.SuperAdminRoles.Add("Administrators");    // members of these roles
```

Super admin roles can't be renamed or deleted from the dashboard, and the last member of a super admin role can't be removed
when no super admin user is configured.

## Dashboard

The dashboard is a set of Razor Pages served under `/authz`, styled after the .NET Aspire dashboard, with light and dark themes.
It has no JavaScript or CSS dependencies and works with a strict Content Security Policy.

- **Overview**: roles, users, permissions and unprotected endpoints, plus what needs attention: endpoints without
  authorization, roles without users, and granted permissions that no longer match anything (for example after renaming an
  action).
- **Endpoints**: every page, action and Minimal API with its route, protection, permission and the roles that can access it.
- **Roles**: create, rename and delete roles, and choose their permissions in a resources × operations matrix (read, create,
  update, delete and custom operations), with a filter and an unsaved-changes counter.
- **Policies**: assign authorization policies to resources (see [Assigning policies to resources](#assigning-policies-to-resources)).
  Shown only while a policy is assignable.
- **Users**: search users, assign roles, and see each user's effective permissions and which role grants them.
- **Access check**: pick a user and a permission to see whether access is granted, and why.

```csharp
.AddDashboard(options =>
{
    options.RoutePrefix = "admin/access";      // default: "authz"
    options.Title = "Contoso access control";
    options.AuthorizationPolicy = "Admins";    // default: the dynamic authorization policy
    options.UserSearch = UserSearchMatch.Contains; // default: StartsWith, which the Identity indexes can answer
});
```

By default, the dashboard is protected by permissions like any other part of the application: `authz.roles.read`,
`authz.roles.create`, `authz.roles.update`, `authz.roles.delete`, `authz.users.read`, `authz.users.update`, and read access to
the overview, endpoints and access check. You can let a role view roles without letting it change them, or manage roles
without managing users. Navigation and buttons only show what the user may do. Treat the role and user permissions as
administrator access: whoever can edit roles can grant themselves any permission. The Policies page requires
`authz.policies.read`, and `authz.policies.update` to change assignments.

### Searching users

The users page, like `IUserManagementService.GetUsersAsync`, matches the search text at the start of the username and email
address by default (`UserSearchMatch.StartsWith`). That becomes `LIKE 'TEXT%'` on the normalized columns, which Identity
indexes, so the count and the page can seek the indexes instead of reading every user. Whether the database does depends
on the collation of the two columns:

- **SQL Server** seeks the Identity indexes as they are.
- **SQLite** compares `LIKE` without regard to case, so its indexes must do the same: give `NormalizedUserName` and
  `NormalizedEmail` the `NOCASE` collation, as the sample does.
- **PostgreSQL** cannot use a B-tree index for `LIKE` under a linguistic collation: give the two columns the `C`
  collation, or add an index with the `varchar_pattern_ops` operator class.

```csharp
builder.Entity<IdentityUser>(user =>
{
    user.Property(u => u.NormalizedUserName).UseCollation("NOCASE"); // "C" on PostgreSQL
    user.Property(u => u.NormalizedEmail).UseCollation("NOCASE");
});
```

Add a migration after changing the collation. `UserSearchMatch.Contains` finds the text anywhere but reads every user on
each search, whatever the collation.

## Caching and multiple instances

User roles and role permissions are cached for `CacheDuration` (one minute by default), in the memory of the instance unless
you register another cache (see below). Changes made through the dashboard or the management services apply immediately on
the instance that made them; other instances, and changes made elsewhere (for example with `UserManager.AddToRoleAsync`),
become visible when the cache expires. Call `IDynamicAuthorizationCache.InvalidateUserAsync`/`InvalidateRoleAsync` after
changing roles in your own code, or set `CacheDuration` to `TimeSpan.Zero` to disable caching.

Concurrent requests for the same user or role share one load, and a change made while a load is in progress is never
hidden by it. Loads run in a service scope of their own, outside any ambient transaction, so they read committed data
only and never depend on the request that started them. When you call the management services inside your own
transaction, invalidate the affected role or user (or call `InvalidateAllAsync`) after committing: the services cannot see
when your transaction completes.

### Sharing the cache between instances

With more than one instance, cache the data in `HybridCache` on a distributed cache instead, so that every instance reads
the same entries and an invalidation on one instance reaches the others. Install `DynamicAuthorization.AspNetCore.HybridCache`,
register a distributed cache, and call `UseHybridCache()`:

```csharp
builder.Services.AddStackExchangeRedisCache(options => options.Configuration = "localhost:6379");

builder.Services
    .AddDynamicAuthorization()
    .AddEntityFrameworkStore<ApplicationDbContext>()
    .UseHybridCache();
```

`UseHybridCache()` registers `HybridCache` with its defaults when the application has not; configure it with
`services.AddHybridCache(options => ...)` if you need to. Entries live in the distributed cache for `CacheDuration` and in
the memory of each instance for `LocalCacheDuration` (five seconds by default, `UseHybridCache(o => o.LocalCacheDuration = ...)`).
An invalidation writes a marker to the cache, for the user or role or for everything, and removes the entry from the
distributed cache; every read compares an entry with the markers, so the other instances see the invalidation within
`LocalCacheDuration`, and a load that was running on any instance when it happened is not kept. `HybridCache` reads one key at a time, so the
permissions of roles that are not cached are loaded one role at a time; each load is shared by every instance that reads
the role. Keys and tags start with `KeyPrefix` (`dynamic-authorization:` by default); applications that share a distributed
cache but not their users and roles must use different prefixes.

To use another cache, implement `IDynamicAuthorizationCacheStore` and register it before `AddDynamicAuthorization()`, or
replace the registration afterwards. The interface documents the contract permission checks rely on: concurrent reads of
one key share one load, an invalidation during a load discards its result, failed loads are not kept, and a load runs to
completion when the caller that started it is cancelled. The cache tests in the repository run against every
implementation. Implement `IResourcePolicyCacheStore` as well to cache the [policies assigned to
resources](#assigning-policies-to-resources); otherwise they are cached in the memory of each instance.

The permissions of roles that are not cached are loaded with one store call: the Entity Framework store runs one query,
and a custom `IPermissionStore` can implement `GetPermissionsAsync(IEnumerable<string> roleIds, ...)` to do the same.
Within one request, the roles of the user and the permissions of those roles are resolved once, however many
`secure-content` tags and permission checks the request makes, and no longer than the cache keeps them: a scope that
outlives a request, for example one held by a background service, sees changes made elsewhere when the cache does.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `SuperAdminUsers` | empty | User names that have every permission. |
| `SuperAdminRoles` | empty | Roles whose members have every permission. |
| `Convention` | `Crud` | `Crud`: one permission per resource and operation (`orders.read`). `Endpoint`: one per action, page or route. |
| `OperationsImplyRead` | `true` | Any operation on a resource also grants `{resource}.read`. |
| `ApplyToDefaultPolicy` | `true` | Permission-check every endpoint that uses the default policy (plain `[Authorize]`). |
| `IgnoredAreas` | `Identity` | Areas that only require a signed-in user. |
| `CacheDuration` | 1 minute | How long user roles and role permissions are cached. |
| `Permissions` / `AddPermission` | empty | Permissions that are not bound to an endpoint. |
| `AssignablePolicies` / `AddAssignablePolicy` | empty | Authorization policies admins may assign to resources. |

`EnableDynamicAuthorization(o => { o.TableName = "..."; o.Schema = "..."; })` customizes the table;
`o.ResourcePolicies = true` adds the table of the policies assigned to resources (`o.ResourcePolicyTableName`).

## Migrating from 1.x

| 1.x | 2.x |
| --- | --- |
| `DynamicAuthorization.Mvc.Core` | `DynamicAuthorization.AspNetCore` |
| `DynamicAuthorization.Mvc.JsonStore`, `DynamicAuthorization.Mvc.MsSqlServerStore` | `DynamicAuthorization.AspNetCore.EntityFrameworkCore` |
| `DynamicAuthorization.Mvc.Ui` | `DynamicAuthorization.AspNetCore.Dashboard` |
| `AddDynamicAuthorization<TDbContext>(o => o.DefaultAdminUser = "...")` | `AddDynamicAuthorization(o => o.SuperAdminUsers.Add("..."))` + `.AddEntityFrameworkStore<TDbContext>()` |
| `.AddJsonStore()` / `.AddSqlServerStore(...)` | `.AddEntityFrameworkStore<TDbContext>()` and `modelBuilder.EnableDynamicAuthorization()` |
| `.AddUi(mvcBuilder)`, `/role`, `/userrole` | `.AddDashboard()` + `app.MapDynamicAuthorizationDashboard()`, `/authz` |
| `class MyTagHelper : SecureContentTagHelper<TDbContext, ...>` | Remove it; use `@addTagHelper *, DynamicAuthorization.AspNetCore` |
| `IMvcControllerDiscovery` | `IPermissionCatalogProvider` |
| `IRoleAccessStore` | `IPermissionStore`, `IRoleManagementService` |

1.x granted roles individual actions. After adding the migration, import them once at startup, after the endpoints are
mapped. Each action is granted the permissions its endpoints require today, for example `orders.update` for `Orders/Edit`.
Imports are idempotent, merge with existing permissions and skip roles that no longer exist:

```csharp
// From the 1.x JSON store file. For the 1.x SQL Server store's RoleAccess table, read through your DbContext,
// call ImportDynamicAuthorizationV1SqlServerStoreAsync() instead.
DynamicAuthorizationV1ImportResult result = await app.Services.ImportDynamicAuthorizationV1JsonStoreAsync("RoleAccess.json");

foreach (string widened in result.WidenedAccess)
{
    app.Logger.LogWarning("Review: {Widened}", widened);
}
```

CRUD permissions can grant more than a 1.x action did: a role that could open `Orders/Index` but not `Orders/Details` gets
`orders.read`, which covers both. `WidenedAccess` lists every such case (for example
`Editors: orders.read also grants mvc::Orders:Details`), and `UnmatchedActions` lists 1.x actions that no longer exist. With
`Convention = PermissionConvention.Endpoint`, roles get exactly their 1.x actions.

Version 2 also authorizes Razor Pages and Minimal APIs: Razor Pages protected with `[Authorize]` (including the Identity UI if
you removed `Identity` from `IgnoredAreas`) now require permissions too.

## Sample

[`samples/SampleWebApp`](https://github.com/mo-esmp/Dynamic-Authorization/tree/main/samples/SampleWebApp) protects
Razor Pages, an MVC area and Minimal APIs, uses SQLite with migrations, registers two policies admins can assign to
resources (`BusinessHours` and `CompanyAccounts`), and seeds three demo accounts (the password is in `appsettings.json`):

```shell
dotnet run --project samples/SampleWebApp --framework net11.0 --launch-profile http
```

The sample targets .NET 10 and .NET 11, so `dotnet run` needs `--framework`; use `net10.0` to run it on .NET 10.

## Building

```shell
dotnet build DynamicAuthorization.slnx
dotnet test --solution DynamicAuthorization.slnx
```

CI also fails on code that differs from `.editorconfig`. Check it with the first command and fix what it reports with
the second:

```shell
dotnet format DynamicAuthorization.slnx --verify-no-changes
dotnet format DynamicAuthorization.slnx
```

## License

[MIT](https://github.com/mo-esmp/Dynamic-Authorization/blob/main/LICENSE)
