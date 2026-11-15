# Resource policies: assigning authorization policies to resources at runtime

Status: approved by the maintainer, 2026-11-15

## Intent

A library user asked (GitHub issue) to stop hardcoding `[Authorize(Policy = "...")]` on endpoints and pages. They want
admins to decide, at runtime and from the dashboard, which of the application's policies guard which part of the app, the
same way admins already decide which roles have which permissions.

Policies stay defined in code: their requirements and handlers are code. What becomes dynamic is the **assignment**: an
admin attaches one or more named policies to a **resource** (for example `orders`), and every request to that resource
must then pass those policies in addition to its permission.

## Goals

- Developers declare which of their policies admins may assign.
- Admins assign and unassign those policies per resource in the dashboard, without a redeploy. Changes apply like role
  permission changes do (immediately on the instance that made them, within the cache duration elsewhere, or across
  instances with the HybridCache package).
- Every request that gets the dynamic permission check also gets the assigned policies of its resource, with no changes
  to existing application code.

## Non-goals

- Defining policies or requirements at runtime. Admins only pick from policies registered in code.
- Assigning policies per operation (`orders.update`) or per individual endpoint. The unit is the resource.
- Assigning policies to roles.
- Making `secure-content` aware of assigned policies. It keeps evaluating the endpoint's static policy only; a link may
  therefore be shown for a page that returns 403 because of an assigned policy. This is accepted.
- Applying assigned policies to code checks through `IPermissionChecker`.

## Anti-goals (a failure even if it works)

- Assignments never grant a permission or bypass static authorization: they only add restrictions on top of the
  permission. Removing an assignment (an admin unassigning it, or a developer removing its registration, see
  Evaluation step 4) relaxes only the restriction that assignment added.
- Admins must not be able to lock everyone out of the dashboard. Super admins always skip assigned policies, and the
  dashboard's own resources (`authz.*`) can take assigned policies only while at least one super admin user or role is
  configured (see Management).
- Existing applications must not change behaviour, or pay a measurable per-request cost, until they register assignable
  policies.

## Decided behaviour

These were decided with the maintainer:

1. **Granularity: per resource.** A policy assigned to `orders` applies to every permission-checked endpoint whose
   resource is `orders` (the Orders controller, the `/Orders` pages, `/api/orders`), whatever the operation.
   "Resource" here means **the resource the endpoint belongs to** (the resolver's target resource: the controller,
   page folder or route, honouring `[PermissionResource]` / `WithPermissionResource`), not the resource of the
   permission it requires. So `[Permission("reports.export")]` on `OrdersController.Export` is guarded by the policies
   of `orders`, and the feature works the same under `PermissionConvention.Endpoint`, where permissions have no
   resource. `EndpointAuthorizationInfo` (or an internal equivalent) must carry this resource key.
2. **All assigned policies must pass**, on top of the endpoint's permission (AND), like stacked
   `[Authorize(Policy = ...)]` attributes.
3. **Only permission-checked endpoints are affected.** Endpoints that are `[AllowAnonymous]`, unprotected, excluded
   (`[IgnoreDynamicAuthorization]`, `IgnoredAreas`) or protected only by a static role/policy (`EndpointProtection`
   other than `DynamicPermission`) never get assigned policies. This inherits an existing resolver limitation: an
   endpoint protected by a named policy that only a custom `IAuthorizationPolicyProvider` knows is classified as
   static (`EndpointAuthorizationResolver.RequiresEndpointPermission`), so it gets no assigned policies even if that
   policy contains `DynamicPermissionRequirement`. Documented, not fixed here.
4. **Super admins skip assigned policies** (both `SuperAdminUsers` and `SuperAdminRoles`). This keeps an escape hatch if
   an assigned policy can never pass, including on the dashboard's own resources. Both lists are empty by default, so
   the escape hatch exists only when one is configured; hence the dashboard-resource safeguard under Management. The
   other recovery path is a code change: removing the policy's registration (step 4 of Evaluation).
5. **`secure-content` ignores assigned policies** (see non-goals).
6. **Requests only.** Assigned policies are evaluated only when the dynamic permission handler authorizes an HTTP
   request (`HttpContext` or `FilterContext` resource with an endpoint). Endpoint-only evaluation (the tag helper),
   explicit-permission requirements (`new DynamicPermissionRequirement("orders.export")`), hub invocations and
   resource-less checks are unaffected.

## Approaches considered

- **A. Evaluate inside `DynamicPermissionHandler` (chosen).** After the permission is granted, the handler looks up the
  resource's assigned policies and evaluates them. Every place that already enforces the endpoint permission (the
  default policy, `RequireDynamicAuthorization()`, application policies that include a parameterless
  `DynamicPermissionRequirement`) gets assigned policies with no application changes. Cost: an assigned-policy failure
  surfaces as a failed `DynamicPermissionRequirement`, so logging must name the failing policy. A policy's own
  authentication schemes can't be honoured from inside a handler, so policies with schemes are rejected (Evaluation
  step 4).
- **B. A separate requirement and handler** next to `DynamicPermissionRequirement`. Cleaner failure reporting, but every
  place that adds the permission check must also add this requirement; applications with their own policies would
  silently miss assigned policies until they update. Rejected because that gap is invisible from the dashboard.
- **C. Rebuild the endpoint's policy per request** (custom policy provider / middleware with policy caching disabled).
  Rejected: it disables ASP.NET Core's per-endpoint policy cache for every endpoint and replaces parts of the
  authorization middleware.

## Design

### Registering assignable policies

```csharp
builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("BusinessHours", p => p.AddRequirements(new BusinessHoursRequirement()));
    o.AddPolicy("RequireMfa", p => p.RequireClaim("amr", "mfa"));
});

builder.Services.AddDynamicAuthorization(o =>
{
    o.AddAssignablePolicy("BusinessHours", "Business hours only");
    o.AddAssignablePolicy("RequireMfa", "Multi-factor sign-in", description: "The user signed in with MFA.");
});
```

- `DynamicAuthorizationOptions.AssignablePolicies : IList<AssignablePolicyDefinition>` and
  `AddAssignablePolicy(string name, string? displayName = null, string? description = null)`, mirroring
  `Permissions` / `AddPermission`.
- Assigned policy names are resolved through `IAuthorizationPolicyProvider.GetPolicyAsync(name)` at request time, so
  a custom policy provider can supply **assigned** policies. (It does not change which endpoints are eligible; see
  decided behaviour 3.)
- **Names:** policy names compare case-insensitively (ordinal), like `AuthorizationOptions`. Names are trimmed, must be
  non-empty and at most 256 characters; registering the same name twice throws at startup. Resource keys are stored
  in the canonical form the resolver produces (lower-case segments, as `PermissionKeys` builds them), at most
  `MaxPermissionLength` characters, and compared ordinally ignoring case.
- The feature is **inactive** while `AssignablePolicies` is empty: no store calls, no cache reads. The Policies page
  is hidden from navigation and returns 404 to direct GET and POST requests.

### Storage

- New public interface `IResourcePolicyStore`:
  - `Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetAssignmentsAsync(CancellationToken)` returns every
    assignment, keyed by resource (case-insensitive). The set of resources is small, so the whole map is loaded and
    cached as one entry.
  - `Task SetPoliciesAsync(string resource, IEnumerable<string> policyNames, CancellationToken)` replaces the policies of
    one resource (an empty list removes the resource's assignments). The replacement is atomic: the EF store deletes
    and inserts in one transaction (as `EntityFrameworkRoleManagementService` does with `ExecuteInTransactionAsync`),
    and cache loads read committed data only, so no reader sees a temporary empty set. Concurrent edits of the same
    resource: last write wins, as for role permissions.
- Entity Framework implementation in `DynamicAuthorization.AspNetCore.EntityFrameworkCore`, registered by
  `AddEntityFrameworkStore<TContext>()`. New table `AspNetResourcePolicies` (`Resource`, `PolicyName`, composite key),
  name and schema configurable alongside the existing table in `DynamicAuthorizationModelOptions`.
- **The table is opt-in** (decided by the maintainer): `EnableDynamicAuthorization(o => o.ResourcePolicies = true)`
  adds it. Upgrading apps that don't use the feature get no pending model change and need no migration.
- The EF store checks on first use that the entity is in the context's model. If it isn't (assignable policies
  registered, table not opted in), it throws an exception that says to set `ResourcePolicies = true` and add a
  migration, instead of failing with a SQL error.
- Startup validation fails with an explanation when `AssignablePolicies` is non-empty and no `IResourcePolicyStore` is
  registered (custom stores).

### Caching

- The assignment map is cached for `CacheDuration` as a single entry through `IDynamicAuthorizationCacheStore`, with
  the same contract as role permissions (shared loads, invalidation discards in-flight loads, failed loads not kept,
  loads run in their own scope).
- The new cache operations (`GetResourcePoliciesAsync(load, ct)`, `InvalidateResourcePoliciesAsync(ct)`) live on a
  new **optional** interface, `IResourcePolicyCacheStore`, rather than on `IDynamicAuthorizationCacheStore`, so custom
  implementations don't break. The memory store and the HybridCache store implement it. When the registered cache
  store doesn't, the library caches this one entry in instance memory with the same contract (so apps with a custom
  store still read the store at most once per `CacheDuration`, not per request). `IDynamicAuthorizationCache` gains
  `InvalidateResourcePoliciesAsync(ct)` as a **default interface member** that calls `InvalidateAllAsync`, so
  existing implementers of that interface don't break; the library's implementation overrides it.
  `InvalidateAllAsync` also clears the entry.
- Invalidation after a write happens after the commit, with `CancellationToken.None`, so a cancelled request can't
  leave a stale entry (the existing management-service pattern).
- The shared cache tests run against every implementation for the new entry too.

### Evaluation (in `DynamicPermissionHandler`)

When the requirement is parameterless, the resource is a request with an endpoint, the endpoint is `DynamicPermission`
protected and the permission was granted:

1. If `AssignablePolicies` is empty, succeed (no further work).
2. If the user is a super admin, succeed. The super-admin decision must come from the work the permission check already
   did, with no extra store query.
3. Read the cached assignment map; take the policies for the endpoint's resource. None: succeed.
4. For each assigned policy name, in ordinal order:
   - Not in `AssignablePolicies` any more (unregistered in code but still stored): **skip it**, log a warning
     (decided by the maintainer). Registration is the developer's list of what admins may assign; removing it is a
     deliberate code change, like deleting an `[Authorize(Policy)]` attribute. Removing the last registration turns
     the feature off the same way (step 1).
   - `GetPolicyAsync` returns null: deny, log a warning.
   - The policy contains any `DynamicPermissionRequirement`: deny, log an error (direct recursion).
   - The policy has non-empty `AuthenticationSchemes`: deny, log an error. A handler can't authenticate with other
     schemes, so evaluating only the requirements against the current principal would change the policy's meaning.
     Checked at request time, because a provider may return a different policy later; the dashboard also refuses to
     assign such a policy when it can see the schemes.
   - Otherwise evaluate its requirements against the request. Failure: deny, log the resource, policy name and user at
     Information level (like the existing denied-permission log).
5. All passed: succeed.

Apart from unregistered policies, failures are fail-closed: a registered policy the provider can't resolve, one that
would recurse, or one with authentication schemes denies. A denied request produces 403 for an authenticated user, as
a denied permission does today.

**Behavioural requirements for the builder:**

- **Reentrancy.** While assigned policies are being evaluated, any nested invocation of `DynamicPermissionHandler`
  (for example a requirement handler that calls `IAuthorizationService` with a policy containing
  `DynamicPermissionRequirement`) checks the permission as usual but does **not** evaluate assigned policies again.
  This guards indirect recursion that the step-4 check can't see.
- **At most once per request.** The outcome is remembered per request, keyed by principal and endpoint; a different
  principal or endpoint is evaluated afresh. Failed outcomes are remembered as failures. An evaluation in progress is
  distinguished from a completed one (a nested call during evaluation is governed by the reentrancy rule, never
  treated as success).
- **No DI cycle.** `DynamicPermissionHandler` must not constructor-inject `IAuthorizationService` (or anything that
  depends on `IAuthorizationHandlerProvider`): the default handler provider takes every `IAuthorizationHandler`, so
  that creates a cycle. Resolve it lazily, for example from `HttpContext.RequestServices`.

### Management

- New `IResourcePolicyManagementService`:
  - list resources that can take policies (permission-checked resources from the catalog) with their assigned policies;
  - `SetPoliciesAsync(resource, policyNames)`: rejects unknown resources, resources that are not permission-checked and
    unregistered policy names (`ManagementResult` errors, like the role service); persists; invalidates the cache entry.
    **Clearing** (an empty list) is always allowed, including for unknown resources, so orphaned assignments the
    Overview flags can be removed. Likewise, saving a resource may drop unregistered policies from it.
  - Rejects assigning any policy to a dashboard resource (`authz.*`) while `SuperAdminUsers` and `SuperAdminRoles` are
    both empty, with an error that explains the lockout risk.
- Implemented over `IResourcePolicyStore` and registered by the **core** package (`TryAdd`), so a custom
  `IResourcePolicyStore` gets the management service and the dashboard page without extra registration. The EF
  package only registers its store.

### Dashboard

- New **Policies** page (`/authz/policies`), shown in navigation only when `AssignablePolicies` is non-empty. It lists
  permission-checked resources (display name, key, endpoint count) with their assigned policies, and lets an admin
  choose policies per resource from the registered list (display name and description). It follows the dashboard's
  existing style: no JavaScript dependencies, strict-CSP compatible, light and dark themes.
- Protected by new dashboard permissions on resource `authz.policies`: `authz.policies.read` and
  `authz.policies.update`, following the existing `authz.*` pattern.
- **Endpoints** page: shows the assigned policies of each endpoint's resource (read-only).
- **Access check** page: when endpoints requiring the checked permission belong to resources with assigned policies,
  lists those resources and policies and says that requests also require them, but that they are not evaluated here
  (they depend on the request). Assignments of unregistered policies are listed separately as **skipped**, not as
  required.
- **Overview** "needs attention", only while the feature is active (at least one assignable policy registered):
  assignments for resources that no longer exist and assignments of policies that are no longer registered (and are
  therefore being skipped), each with a way to clear them. While inactive, the dashboard doesn't read the store.

### Documentation

README section "Assigning policies to resources": registration and naming rules, what is and isn't covered (decided
behaviour 3–6, including the custom-provider limitation), super-admin skip and the dashboard safeguard, policies with
authentication schemes are rejected, caching, EF opt-in and migration, and these consequences of keeping skipped
assignments:

- Restoring a removed registration reactivates its stored assignments.
- During a rolling deployment, instances with different registrations can enforce different restrictions.

## Constraints

- Targets .NET 10 and .NET 11, like the rest of version 2.
- No per-request cost when the feature is unused; when used, one cache read per request in the warm case.
- Dashboard: no JavaScript or CSS dependencies, strict Content Security Policy.
- Public API changes must not break existing custom `IDynamicAuthorizationCacheStore` implementations.

## Calls made by Claude (not discussed)

- Registration API (`AddAssignablePolicy`) and that policies are resolved by name through the policy provider.
- Whole assignment map cached as one entry.
- Dashboard: separate Policies page, `authz.policies.*` permissions, read-only display on Endpoints and Access check.
- An optional `IResourcePolicyCacheStore` interface with an in-memory fallback, instead of changing
  `IDynamicAuthorizationCacheStore`.
- "Resource" means the endpoint's own resource, not its permission's (from "Order endpoint, not Order.Update").
- The EF store detects a missing opt-in on first use and throws a clear error.
- Fail-closed for registered policies the provider can't resolve, for policies containing
  `DynamicPermissionRequirement`, and for policies with authentication schemes.
- Dashboard resources can't take policies while no super admin is configured.
- Clearing is always allowed, including for orphaned resources; last write wins on concurrent edits.
- Nested evaluations skip assigned policies (reentrancy guard).
- The custom-provider endpoint-classification limitation is documented, not fixed.

## Left to the builder

- Type and member names beyond those above, file layout, and how the per-request marker and reentrancy guard are
  implemented (within the behavioural requirements above).
- How the handler obtains the super-admin decision cheaply (internal API on the permission checker or similar).
- Whether assigned policies are combined into one policy and evaluated once, or evaluated one by one (behaviour must
  match step 4, including which policy is logged).
- Dashboard markup and layout within the existing style.
- Further test coverage beyond the acceptance tests below.

## Required acceptance tests

- Indirect recursion and reentrancy (a requirement handler that authorizes a policy containing
  `DynamicPermissionRequirement`) terminates and gives the specified outcome.
- Repeated authorization within a request, including a different principal or endpoint, and a previously failed
  evaluation staying failed.
- Registration removal and restoration, including removing the last registration.
- Assigned policies with authentication schemes are denied (and refused by the dashboard where visible).
- Endpoints protected by a named policy known only to a custom provider get no assigned policies (documented
  limitation); assigned policies supplied by a custom provider are evaluated.
- Super admins skip assigned policies; dashboard-resource assignment is refused with no super admin configured.
- Clearing orphaned assignments (unknown resource, unregistered policy).
- Atomic replacement (no empty set observed) and last-write-wins on concurrent edits.
- Request cancellation after the commit still invalidates the cache.
- Cross-instance invalidation with the HybridCache store, and the in-memory fallback for a custom cache store.
- EF store without the opt-in fails with the explanatory error; with the opt-in, no pending model changes after the
  migration.
