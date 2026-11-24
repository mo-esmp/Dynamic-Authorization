# Permission areas for Minimal APIs

## Why

An application often has client APIs and admin APIs side by side, for example `/api/client/...` and `/api/admin/...`, and
wants dynamic authorization only on the admin ones. Restricting the check already works
(`ApplyToDefaultPolicy = false` plus `MapGroup("/api/admin").RequireDynamicAuthorization()`), but the permissions it
derives under such a prefix are wrong, because a Minimal API's resource is the first route segment after `api` and a
version:

| Endpoint | Permission today |
| --- | --- |
| `GET /api/admin/orders` | `admin.read` |
| `GET /api/admin/users` | `admin.read` (the same permission) |
| `POST /api/admin/orders` | `admin.orders` |
| `POST /api/admin/orders/{id}/ship` | `admin.ship` |

Granting read on admin orders grants read on admin users. Controllers already solve this with `[Area("Admin")]`, which
yields `admin.orders.*`; Minimal APIs have no equivalent.

## Goals

- `app.MapGroup("/api/admin").WithPermissionArea("admin")` gives its endpoints the resources `admin.orders`,
  `admin.users`, ..., and the operations they would have without the prefix: `admin.orders.read`,
  `admin.orders.create`, `admin.orders.ship`, `admin.users.delete`.
- Works with API versions wherever the version sits: `/api/v1/admin/orders`, `/api/admin/v2/orders` and
  `/api/v{version}/admin/orders` all require `admin.orders.read`. Versions share permissions, as they do today.
- Minimal API areas behave like controller areas: admin controllers (`[Area("Admin")]`) and admin Minimal APIs with the
  same resource share its permissions and its assigned policies, and `IgnoredAreas` applies to both.
- `WithPermissionResource` on a group also gets `create` for a POST to the collection.

## Non-goals

- Deriving areas from namespaces. A Minimal API handler is usually a lambda compiled into whatever class called
  `Map...`, so its namespace says nothing about the area; for controllers, renaming a namespace would silently rename
  permissions and orphan grants. Dropped.
- A global "skip this route prefix" option. It would match the segment by name across the whole application.
- Per-version permissions (still possible with `WithPermissionResource`).
- Two controllers with the same name in different namespaces sharing a permission and an endpoint key: a separate fix.

## Anti-goals

- No existing permission key changes for an application that doesn't call `WithPermissionArea`, except the
  `WithPermissionResource` POST fix below.

## Approaches

1. **Area-style groups (chosen).** An explicit `WithPermissionArea(area)` on a route group or endpoint, mirroring
   `[Area]` on controllers. Opt-in and local: only the endpoints it is applied to change.
2. **Global prefix option**, such as `options.RoutePrefixes.Add("admin")`, skipped like `api` and `v1`. One line, but it
   matches by segment name application-wide (`/api/orders/admin` would be affected) and loses the `admin.` prefix unless
   it adds it back.
3. **Namespaces.** Doesn't work for Minimal APIs (see Non-goals).

## Design

- **API.** `WithPermissionArea<TBuilder>(this TBuilder builder, string area)` in
  `DynamicAuthorizationEndpointConventionBuilderExtensions`, adding new metadata (`IPermissionAreaMetadata` with
  `string Area`, implemented by a sealed `PermissionAreaMetadata` or attribute). It doesn't reuse MVC's `AreaAttribute`, so
  link generation and MVC route values aren't affected.
- **Resource.** In `DescribeRoute`, when the endpoint has an area: drop `api` and version segments as today, then drop the
  first remaining literal equal to the area (case-insensitive, compared after `PermissionKeys.ToSegment`). The resource is
  `{area}.{first remaining literal}`, built with the same `JoinResource` as controllers. If no literal remains
  (`GET /api/admin`), the resource is the area itself. If the route has no segment named after the area
  (`/api/backoffice/orders` with area `admin`), nothing is dropped: `admin.backoffice`.
- **Operation.** Inferred from the remaining literals, so the existing rules apply unchanged: `POST /api/admin/orders` is
  a create, `POST /api/admin/orders/{id}/ship` is `ship`.
- **Precedence.** `WithPermissionResource` replaces the resource wholesale, as `[PermissionResource]` does on an area
  controller; `RequirePermission` / `RequirePermissionOperation` work as today.
- **Display name.** `WithArea(area, name)`, as for controllers: `admin / Orders`, or `admin / {tag}` when a tag names the
  group.
- **Protection.** Pass the area to `GetProtection`, so `IgnoredAreas` excludes it, and set it on `EndpointAuthorizationInfo`
  as controllers do.
- **Endpoint convention.** Keys stay route-based (`endpoint:GET /api/admin/orders`); unaffected.
- **`WithPermissionResource` create fix.** When an explicit resource is set, a POST ending in a literal is a create
  when that literal is the only one, as today, or when it equals the last segment of the resource
  (`/api/legacy/orders` with resource `admin.orders`: `admin.orders.create`). Otherwise the existing rules apply. This
  changes the permission of such endpoints in existing applications (from `admin.orders.orders` to
  `admin.orders.create`); the release notes say so, and the dashboard already lists the old grant as unmatched.
- **Docs and sample.** A README section next to "Overriding the convention" showing client/admin groups with
  `ApplyToDefaultPolicy = false`, `RequireDynamicAuthorization()` and `WithPermissionArea`, including a versioned
  route. Update the resource rule sentence ("A Minimal API's resource is ..."). The sample needs no change.

## Left to the builder

- Whether the metadata type is public (needed if users check it, as with `IPermissionResourceMetadata`): make it public
  for symmetry.
- Tests: discovery (resource, operation, versioned routes, nested groups, no-match route, `GET /api/admin`), protection
  (`IgnoredAreas`), shared permission with an `[Area("Admin")]` controller of the same resource, resource policies on
  `admin.orders`, the `WithPermissionResource` create fix, and an unchanged key for an endpoint without an area.
