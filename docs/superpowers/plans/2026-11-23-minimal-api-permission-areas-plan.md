# Permission areas for Minimal APIs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `MapGroup("/api/admin").WithPermissionArea("admin")` gives Minimal API endpoints area-prefixed resources
(`admin.orders.read`), like `[Area("Admin")]` does for controllers, and `WithPermissionResource` groups get `create` for
a POST to the collection.

**Architecture:** A new endpoint metadata (`IPermissionAreaMetadata`) is added by a new convention extension.
`EndpointAuthorizationResolver.DescribeRoute` reads it, drops the area's route segment before deriving the resource and
operation, prefixes the resource with the area, and passes the area to protection (`IgnoredAreas`) and the catalog entry.
`GetRouteOperation` learns about an explicit resource for the create fix.

**Tech Stack:** C# / .NET 10 and 11, ASP.NET Core routing and authorization, xUnit v3 with `TestApp` (in-memory host,
SQLite Identity).

**Spec:** `docs/superpowers/specs/2026-11-23-minimal-api-permission-areas-design.md`

## Global Constraints

- Opt-in: no permission key, resource or target key changes for an endpoint without `WithPermissionArea`, except the
  `WithPermissionResource` POST fix (Task 2).
- Target keys (`endpoint:{methods} {route}`, `endpoint:{name}`) never change; under `PermissionConvention.Endpoint` areas
  only change the resource.
- Use a new metadata type, not MVC's `AreaAttribute`.
- Area segment matching compares `PermissionKeys.ToSegment(literal)` with `PermissionKeys.ToSegment(area)`; only the first
  match after dropping `api` and version segments is removed.
- `WithPermissionResource` replaces the resource wholesale (area not prefixed); the area segment is still dropped for
  operation inference.
- Display group: `{area as given} / {display name}`, the same `WithArea` helper controllers use.
- Every C# file starts with a BOM, LF line endings; `dotnet format --verify-no-changes` must pass (CI checks it).
- Public types and members get XML docs in the style of the neighbouring files.

## Review Focus

- Area written differently from the route segment (`WithPermissionArea("BackOffice")` on `/api/back-office`): still
  matched and dropped. Pinned in Task 1.
- Version before or after the area (`/api/v1/admin/...`, `/api/admin/v2/...`, `/api/v{version}/admin/...`): same
  permission. Pinned in Task 1.
- The route has no segment named after the area (`/api/backoffice/orders` with `admin`): resource `admin.backoffice`, no
  exception. Pinned in Task 1.
- The group root itself (`GET /api/admin`, `MapGet("")`): resource is the area, permission `admin.read`. Pinned in Task 1.
- The user's real setup, `ApplyToDefaultPolicy = false` with a plain client group and a dynamic admin group: client needs
  only sign-in, admin needs the area permission. Pinned in Task 1.

---

### Task 1: `WithPermissionArea` for Minimal APIs

**Files:**
- Create: `src/DynamicAuthorization.AspNetCore/Metadata/IPermissionAreaMetadata.cs`
- Create: `src/DynamicAuthorization.AspNetCore/Metadata/PermissionAreaMetadata.cs`
- Modify: `src/DynamicAuthorization.AspNetCore/Routing/DynamicAuthorizationEndpointConventionBuilderExtensions.cs`
- Modify: `src/DynamicAuthorization.AspNetCore/Catalog/EndpointAuthorizationResolver.cs` (`DescribeRoute`, ~296-343)
- Test: `test/DynamicAuthorization.AspNetCore.Tests/DiscoveryTests.cs`, `AuthorizationTests.cs`, `ResourcePolicyTests.cs`

**Interfaces:**
- Produces: `public interface IPermissionAreaMetadata { string Area { get; } }` (namespace `DynamicAuthorization.AspNetCore`)
- Produces: `public sealed class PermissionAreaMetadata(string area) : IPermissionAreaMetadata` — throws
  `ArgumentException` for null/empty/whitespace.
- Produces: `public static TBuilder WithPermissionArea<TBuilder>(this TBuilder builder, string area) where TBuilder : IEndpointConventionBuilder`
  in `Microsoft.AspNetCore.Builder.DynamicAuthorizationEndpointConventionBuilderExtensions`.
- Produces (internal, used by Task 2): in `DescribeRoute`, `literals` is the array *after* the area segment is removed,
  and that array is what `GetRouteOperation` receives.

- [ ] **Step 0: Branch and commit the design**

```bash
git switch -c minimal-api-permission-areas
git add docs/superpowers/specs/2026-11-23-minimal-api-permission-areas-design.md docs/superpowers/plans/2026-11-23-minimal-api-permission-areas-plan.md
git commit -m "Design permission areas for Minimal APIs"
```

- [ ] **Step 1: Write the failing discovery tests** in `DiscoveryTests.cs`

A shared mapping used by the tests below:

```csharp
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
    e.MapGet("/api/backoffice/orders", () => "bo").RequireAuthorization().WithPermissionArea("admin");
}
```

Tests:
- `Minimal_api_areas_prefix_the_resource_and_keep_the_operation` — `[Theory]` over (method, route, resource, permission),
  looking each up with `catalog.FindEndpoint(PermissionKeys.ForRoute([method], route))`:
  `GET /api/admin` → `admin`, `admin.read`; `GET /api/admin/orders` → `admin.orders`, `admin.orders.read`;
  `POST /api/admin/orders` → `admin.orders.create`; `POST /api/admin/orders/{id:int}/ship` → `admin.orders.ship`;
  `GET /api/admin/orders/export` → `admin.orders.export`; `DELETE /api/admin/users/{id:int}` → `admin.users`,
  `admin.users.delete`; `GET /api/admin/reports/{id:int}` → `admin.reports.read`; `GET /api/admin/audit` → resource
  `admin.audit`, permission `audit.view`; `GET /api/admin/legacy` → `legacy`, `legacy.read`; `POST /api/admin/legacy` →
  `legacy.create`; the three invoice routes → `admin.invoices`, `admin.invoices.read`; `GET /api/back-office/stock` →
  `back-office.stock`, `back-office.stock.read`; `GET /api/backoffice/orders` → `admin.backoffice`, `admin.backoffice.read`.
- `Minimal_api_areas_are_shown_like_controller_areas` — `catalog.FindPermission("admin.orders.read")?.Group` is
  `"admin / Orders"`; the `GET /api/admin/orders` entry's `Area` is `"admin"`; the target key is still
  `endpoint:GET /api/admin/orders`.
- `Minimal_api_areas_keep_endpoint_convention_keys` — with `Convention = PermissionConvention.Endpoint`, the
  `GET /api/admin/orders` entry's permission is `endpoint:GET /api/admin/orders` and its resource `admin.orders`.
- `Permission_area_must_not_be_empty` — `Assert.Throws<ArgumentException>(() => new PermissionAreaMetadata(" "))`.

- [ ] **Step 2: Write the failing request tests**

In `AuthorizationTests.cs`:
- `Only_the_admin_api_area_is_permission_checked` — `ApplyToDefaultPolicy = false`; endpoints:
  `e.MapGroup("/api/client").RequireAuthorization().MapGet("/orders", ...)` and
  `e.MapGroup("/api/admin").RequireDynamicAuthorization().WithPermissionArea("admin").MapGet("/orders", ...)`.
  A user with no permissions gets 200 on `/api/client/orders` and 403 on `/api/admin/orders`; a user with
  `admin.orders.read` gets 200 on `/api/admin/orders`; a user with `orders.read` gets 403 on it.
- `Ignored_areas_apply_to_minimal_api_areas` — `IgnoredAreas.Add("Admin")`, `MapAdminApis`-style
  `GET /api/admin/orders` with `WithPermissionArea("admin")`: a signed-in user without permissions gets 200, and the
  entry's `Protection` is `EndpointProtection.Excluded`.
- `Minimal_api_areas_share_permissions_with_area_controllers` — map
  `GET /api/admin/settings` with `RequireAuthorization().WithPermissionArea("Admin")`; a user with `admin.settings.read`
  gets 200 on both `/Admin/Settings` (the existing `SettingsController`) and `/api/admin/settings`.

In `ResourcePolicyTests.cs`:
- `Policies_of_an_area_resource_apply_to_its_minimal_apis` — `StartAsync(e => e.MapGet("/api/admin/settings", ...).RequireAuthorization().WithPermissionArea("Admin"))`,
  user with `admin.settings.read`, `AssignAsync(app, "admin.settings", "Deny")`: 403 on `/Admin/Settings` and
  `/api/admin/settings`.

- [ ] **Step 3: Run the tests and verify they fail**

Run: `dotnet test test/DynamicAuthorization.AspNetCore.Tests -f net10.0`
Expected: build error — `WithPermissionArea` / `PermissionAreaMetadata` not defined.

- [ ] **Step 4: Add the metadata types and `WithPermissionArea`**

`WithPermissionArea` validates with `ArgumentNullException.ThrowIfNull(builder)` and returns
`builder.WithMetadata(new PermissionAreaMetadata(area))`. Doc comment: the Minimal API counterpart of `[Area]`; the
area's route segment is skipped and the resource becomes `{area}.{resource}`.

- [ ] **Step 5: Derive the resource, operation, display name and protection from the area in `DescribeRoute`**

- `string? area = metadata.GetMetadata<IPermissionAreaMetadata>()?.Area;`
- Build `literals` as today, then when `area` is set remove the first literal whose `ToSegment` equals `ToSegment(area)`.
- Resource: `resource?.Resource` wins; else with an area, `JoinResource(area, [literals[0]])` or `ToSegment(area)` when no
  literal remains; else today's rule.
- Display group: `resource?.DisplayName` wins; else with an area, `WithArea(area, tag ?? GetResourceDisplayName(literals[0]))`,
  or `area` when no literal remains; else today's rule.
- Pass the reduced `literals` to `GetRouteOperation`, `area` to `GetProtection`, and `area` as the `Area` argument of the
  `EndpointAuthorizationInfo`.

- [ ] **Step 6: Run the tests and verify they pass**

Run: `dotnet test test/DynamicAuthorization.AspNetCore.Tests`
Expected: all tests pass on net10.0 and net11.0.

- [ ] **Step 7: Format and commit**

```bash
dotnet format --verify-no-changes
git add src test
git commit -m "Let Minimal API route groups name a permission area"
```

### Task 2: Create for a POST to a `WithPermissionResource` collection

**Files:**
- Modify: `src/DynamicAuthorization.AspNetCore/Catalog/EndpointAuthorizationResolver.cs` (`GetRouteOperation`, its call in `DescribeRoute`)
- Test: `test/DynamicAuthorization.AspNetCore.Tests/DiscoveryTests.cs`

**Interfaces:**
- Consumes: the reduced `literals` from Task 1.
- Produces: `private static string GetRouteOperation(string[] segments, string[] literals, string[] httpMethods, string? explicitResource)`.

- [ ] **Step 1: Write the failing test** `Posts_to_an_explicit_resource_collection_create`

Endpoints: `RouteGroupBuilder legacy = e.MapGroup("/api/legacy/orders").RequireAuthorization().WithPermissionResource("admin.orders");`
with `legacy.MapPost("", ...)`, `legacy.MapPost("/{id:int}/ship", ...)`, `legacy.MapPost("/archive", ...)`.
Assert the permissions `POST /api/legacy/orders` → `admin.orders.create`, `POST /api/legacy/orders/{id:int}/ship` →
`admin.orders.ship`, `POST /api/legacy/orders/archive` → `admin.orders.archive`, and the existing
`POST /api/items/{id:int}/ship` (from `TestApp`) is still `items.ship`.

- [ ] **Step 2: Run it and verify it fails**

Run: `dotnet test test/DynamicAuthorization.AspNetCore.Tests -f net10.0 --filter "FullyQualifiedName~Posts_to_an_explicit_resource_collection_create"`
Expected: FAIL — actual `admin.orders.orders`.

- [ ] **Step 3: Implement**

In the POST branch, a route ending in a literal is a create when `literals.Length <= 1`, or when `explicitResource` is
set and `ToSegment(last)` equals (ordinal, ignore case) the part of `explicitResource` after its last `.` (the whole key
when there is none). `DescribeRoute` passes `resource?.Resource`.

- [ ] **Step 4: Run all tests**

Run: `dotnet test test/DynamicAuthorization.AspNetCore.Tests`
Expected: all pass.

- [ ] **Step 5: Format and commit**

```bash
dotnet format --verify-no-changes
git add src test
git commit -m "Infer create for a POST to the collection of an explicit resource"
```

### Task 3: README

**Files:**
- Modify: `README.md` (the resource sentence under "Permissions: resources and operations", "Overriding the convention",
  "What is permission-checked", Contents)

- [ ] **Step 1: Update the docs**

- The resource rule sentence: add that `WithPermissionArea` prefixes the resource and skips the area's segment.
- New subsection "Permission-checking only some APIs" after "Overriding the convention", linked from Contents: the
  client/admin example with `ApplyToDefaultPolicy = false`, `RequireAuthorization()` on the client group and
  `RequireDynamicAuthorization().WithPermissionArea("admin")` on the admin group; a table with `GET /api/admin/orders` →
  `admin.orders.read`, `POST /api/admin/orders` → `admin.orders.create`, `GET /api/v2/admin/orders` →
  `admin.orders.read`; one line that `[Area("Admin")]` controllers share these permissions and that `IgnoredAreas`
  applies; the alternative of keeping the default and `.IgnoreDynamicAuthorization()` on the client group.
- Add `.WithPermissionArea("admin")` to the "Overriding the convention" code block.
- Mention under "What is permission-checked" that `IgnoredAreas` also covers Minimal API areas.

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "Document permission areas for Minimal APIs"
```

The PR description states the one behaviour change: a POST to the collection of a `WithPermissionResource` group now
requires `{resource}.create` instead of `{resource}.{last segment}`; the dashboard lists old grants as unmatched.
