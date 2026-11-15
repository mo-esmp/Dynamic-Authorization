# Resource policies: implementation plan

Design: [2026-11-15-resource-policies-design.md](../specs/2026-11-15-resource-policies-design.md) (approved). The design
is the source of truth for behaviour; this plan orders the work and says what proves each step. Where they disagree,
the design wins and the plan gets fixed.

## Ground rules

- **Branch.** Work on `resource-policies`. It was cut from `main`, which doesn't have the .NET 10/11 retargeting yet,
  so Task 0 rebases it first.
- **Test first.** Each task starts by writing its tests (xUnit v3, in `test/DynamicAuthorization.AspNetCore.Tests`,
  using `TestApp` and its `TestAppOptions` hooks), sees them fail, then implements.
- **Each task ends green:** `dotnet build DynamicAuthorization.slnx -c Release`,
  `dotnet format DynamicAuthorization.slnx --verify-no-changes`, `dotnet test --solution DynamicAuthorization.slnx -c Release`
  (both target frameworks), then one commit per task.
- **Public API:** XML docs on everything public, in the style of the existing files. No breaking changes to existing
  public types (the design's compatibility rules: optional interfaces, default interface members, init-only
  properties instead of new positional record parameters).
- **Performance:** with no assignable policies registered, the request path must not touch the new code beyond one
  `Count == 0` check. Task 7 has a test that proves it.

## Task 0: Rebase onto the .NET 10/11 branch

- Rebase `resource-policies` onto `target-net11` (or onto `main` after that branch merges).
- Done when the solution builds and the existing tests pass on both target frameworks.

## Task 1: Options and registration

Files: `src/DynamicAuthorization.AspNetCore/DynamicAuthorizationOptions.cs`, new `AssignablePolicyDefinition.cs`,
`DependencyInjection/DynamicAuthorizationServiceCollectionExtensions.cs` (validation).

- `AssignablePolicies : IList<AssignablePolicyDefinition>` and
  `AddAssignablePolicy(string name, string? displayName = null, string? description = null)` returning the options,
  mirroring `Permissions` / `AddPermission`.
- `AssignablePolicyDefinition(string Name, string? DisplayName, string? Description)`.
- Startup validation (added to the existing `options.Validate(...).ValidateOnStart()` chain): names trimmed,
  non-empty, at most 256 characters, unique ignoring case.
- An internal lookup (case-insensitive set of registered names) built once, so the handler's "is it registered"
  check is O(1).

Tests (new `ResourcePolicyOptionsTests.cs`): blank, too long and duplicate (different case) names fail at startup;
valid registrations are listed in order with their display names.

## Task 2: The endpoint's own resource on `EndpointAuthorizationInfo`

Files: `Catalog/PermissionCatalog.cs`, `Catalog/EndpointAuthorizationResolver.cs`.

- Add `public string? Resource { get; init; }` to `EndpointAuthorizationInfo` (init-only, so the positional
  constructor is unchanged). The resolver sets it from its `Target.Resource` for MVC actions, Razor Pages (every
  handler entry) and Minimal APIs, honouring `[PermissionResource]` / `WithPermissionResource`.
- Add a lookup on `PermissionCatalog` from resource to its endpoints, for the management service and dashboard.

Tests (`DiscoveryTests.cs`): resource of a controller action, a page and its handlers, an API under `/api/v2/...`,
an area controller (`admin.reports`), a `[PermissionResource]` override, `[Permission("reports.export")]` on an
Orders action (resource stays `orders`), and the same endpoints under `PermissionConvention.Endpoint`.

## Task 3: Store abstraction and startup check

Files: new `Stores/IResourcePolicyStore.cs`; `Authorization/ValidateAuthorizationOptions.cs` or a new
`IValidateOptions<DynamicAuthorizationOptions>`.

- `IResourcePolicyStore` as specified: `GetAssignmentsAsync` (whole map, case-insensitive keys) and
  `SetPoliciesAsync(resource, policyNames)` (replace; empty clears).
- Startup validation: `AssignablePolicies` non-empty and no `IResourcePolicyStore` registered fails with a message
  that names `AddEntityFrameworkStore` and the interface.

Tests: startup fails with that message; succeeds with no registrations and no store (feature off); succeeds with a
fake store.

## Task 4: Entity Framework store

Files: `src/DynamicAuthorization.AspNetCore.EntityFrameworkCore/`: `RolePermission.cs`
(`DynamicAuthorizationModelOptions`), `DynamicAuthorizationModelBuilderExtensions.cs`, new `ResourcePolicy.cs`
entity, new `Internal/EntityFrameworkResourcePolicyStore.cs`, `DynamicAuthorizationEntityFrameworkBuilderExtensions.cs`.

- Model options: `ResourcePolicies` (bool, default false), `ResourcePolicyTableName` (default
  `AspNetResourcePolicies`); the schema is shared with the existing table. Columns `Resource` (max
  `MaxPermissionLength`) and `PolicyName` (max 256), composite key. Mapped only when `ResourcePolicies` is true.
- Store: `GetAssignmentsAsync` reads all rows with no tracking. `SetPoliciesAsync` deletes and inserts the resource's
  rows in one transaction via the context's execution strategy (the pattern `EntityFrameworkRoleManagementService`
  uses with `ExecuteInTransactionAsync`). Keys are stored in canonical form.
- Missing opt-in: on first use, if the entity type isn't in `context.Model`, throw `InvalidOperationException`
  explaining `EnableDynamicAuthorization(o => o.ResourcePolicies = true)` plus a migration.
- `AddEntityFrameworkStore<TContext>()` registers the store (`TryAddScoped`).

Tests (`EntityFrameworkStoreTests.cs`; add an opted-in test context next to `TestDbContext`):
- the opted-out context has no new entity, so existing apps see no model change;
- the opted-in context maps the table with the lengths and key;
- round trip, replace, clear;
- canonical keys and case-insensitive reads;
- atomic replace: a concurrent reader never sees an empty set for a resource being replaced (loop of reads during
  replaces on SQLite);
- last write wins for two writers;
- opted-out context plus registered policies gives the explanatory exception, not a SQL error.

## Task 5: Caching

Files: `Caching/`: new `IResourcePolicyCacheStore.cs`, `MemoryDynamicAuthorizationCacheStore.cs`,
`DynamicAuthorizationCache.cs`, `IDynamicAuthorizationCache.cs`; `src/DynamicAuthorization.AspNetCore.HybridCache/HybridDynamicAuthorizationCacheStore.cs`.

- `IResourcePolicyCacheStore`: `GetResourcePoliciesAsync(load, ct)` returning
  `CachedValue<IReadOnlyDictionary<string, IReadOnlySet<string>>>`, and `InvalidateResourcePoliciesAsync(ct)`, with
  the same contract as `IDynamicAuthorizationCacheStore` (document it the same way).
- The memory store implements it. `DynamicAuthorizationCache.GetResourcePoliciesAsync` uses the registered cache
  store if it implements the interface, otherwise a private memory-store instance for this one entry (the fallback).
  Loads run in their own scope, outside ambient transactions, as the existing loads do.
- `IDynamicAuthorizationCache.InvalidateResourcePoliciesAsync` is a default interface member calling
  `InvalidateAllAsync`; `DynamicAuthorizationCache` overrides it. `InvalidateAllAsync` also clears the entry, including
  in the fallback.
- The HybridCache store implements the interface: one key under `KeyPrefix`, and an invalidation marker like the
  existing role and all markers, so other instances drop it within `LocalCacheDuration`.

Tests (`CacheTests.cs`, extending the suite that runs against every implementation):
- shared load, invalidation during a load discards the result, a failed load isn't kept, and a cancelled caller
  doesn't cancel the load;
- `InvalidateAllAsync` clears the entry;
- a custom store that doesn't implement the interface gets the fallback: the store is loaded once per
  `CacheDuration`, not once per call;
- `CacheDuration = 0` loads every time;
- cross-instance: two service providers sharing one distributed cache, an invalidation on one is seen by the other.

## Task 6: Cheap super-admin decision for the handler

Files: `Authorization/PermissionChecker.cs`, `Authorization/DynamicPermissionHandler.cs`.

- Add an internal method on `PermissionChecker` that returns the `PermissionDecision` from the existing
  stop-at-first-grant path (`EvaluateCoreAsync(..., stopAtFirstGrant: true)`), with no extra store work.
- The handler uses it when the registered `IPermissionChecker` is the built-in one; otherwise it falls back to
  `HasPermissionAsync`, then `EvaluateAsync` only when there are assigned policies to evaluate.

Tests (`PermissionHandlerTests.cs`): existing behaviour unchanged; decision is `SuperAdminUser` / `SuperAdminRole` /
`GrantedByRole` as expected; a counting store shows no extra queries.

## Task 7: Evaluating assigned policies

Files: new internal `Authorization/ResourcePolicyEvaluator.cs` (scoped), `DynamicPermissionHandler.cs`, DI.

The handler calls the evaluator only when the requirement is parameterless, the resource is an `HttpContext` or
`FilterContext` with an endpoint, the entry is `DynamicPermission`, the permission was granted, and
`AssignablePolicies` is non-empty. The evaluator implements design steps 2–5:

- super admins skip;
- read the cached map and take the endpoint's `Resource` entry;
- for each name in ordinal order:
  - unregistered: skip and log a warning;
  - `GetPolicyAsync` returns null: deny and log a warning;
  - contains `DynamicPermissionRequirement`: deny and log an error;
  - non-empty `AuthenticationSchemes`: deny and log an error;
  - otherwise: `IAuthorizationService.AuthorizeAsync(user, httpContext, policy)`; a failure denies and logs at
    Information, naming the resource, policy and user.

Its behavioural requirements:

- **Reentrancy:** an `AsyncLocal` flag set while evaluating. A nested handler invocation checks the permission but
  skips assigned policies.
- **Once per request:** the outcome is stored in `HttpContext.Items` under a private key, keyed by
  (`ClaimsPrincipal` reference, `Endpoint`). States are `InProgress`, `Succeeded` and `Failed`; `Failed` is reused
  as failure, and `InProgress` is governed by the reentrancy rule.
- **No DI cycle:** `IAuthorizationService` and `IAuthorizationPolicyProvider` are resolved from
  `httpContext.RequestServices` when needed, never constructor-injected.
- New `LoggerMessage`s next to the existing ones (new event IDs).

Tests (new `ResourcePolicyTests.cs`, through `TestApp` with real endpoints):
- a passing policy allows; a failing one gives 403; two policies are ANDed;
- the permission is still required (policy passes, permission missing gives 403);
- super admin user and super admin role skip a failing policy;
- unregistered assignment skipped; removing the last registration turns the feature off; restoring a registration
  reactivates the stored assignment;
- a provider returning null denies; a policy with `DynamicPermissionRequirement` denies; a policy with authentication
  schemes denies;
- indirect recursion: a requirement handler that authorizes a policy containing `DynamicPermissionRequirement`
  terminates with the specified outcome;
- repeated authorization in one request reuses the outcome; a different principal or endpoint is evaluated afresh; a
  failed outcome stays failed;
- policies resolved from a custom `IAuthorizationPolicyProvider` are evaluated; an endpoint protected only by a
  provider-only named policy gets no assigned policies (documented limitation);
- unaffected cases: `[AllowAnonymous]`, `[IgnoreDynamicAuthorization]`, ignored areas, static-policy-only endpoints,
  explicit-permission requirements, `IPermissionChecker` calls, and `secure-content` (still renders the link);
- applies under `PermissionConvention.Endpoint`, and to `[Permission("reports.export")]` on an Orders action through
  the `orders` assignment;
- feature off: a store that throws on any call is never called;
- the app starts and resolves `IAuthorizationService` with the handler registered (no DI cycle).

## Task 8: Management service

Files: new `Management/IResourcePolicyManagementService.cs`, result types alongside `RoleDetails` etc., internal
implementation over `IResourcePolicyStore`, registered by the core package with `TryAddScoped` (resolvable only when
a store is registered).

- `GetResourcesAsync()`: permission-checked resources from the catalog (key, display name, endpoint count) with
  assigned policies, each marked enforced or skipped (unregistered); plus orphaned assignments (unknown resources).
- `SetPoliciesAsync(resource, policyNames)`. It returns `ManagementResult` errors in these cases:
  - an unknown or non-permission-checked resource (unless the list is empty);
  - an unregistered policy name being added (keeping or dropping an existing unregistered one is allowed);
  - a policy whose provider result has authentication schemes;
  - any policy on an `authz.*` resource while `SuperAdminUsers` and `SuperAdminRoles` are both empty.
- On success: persists, then `InvalidateResourcePoliciesAsync(CancellationToken.None)` after the commit.

Tests: each rejection; clearing an orphan; dropping an unregistered policy while saving; cancellation of the
caller's token after the commit still invalidates (store wrapper that cancels after the write); a change is visible
to the next request on the same instance.

## Task 9: Dashboard Policies page

Files: `src/DynamicAuthorization.AspNetCore.Dashboard/`: `Internal/DashboardInfrastructure.cs` (new
`PoliciesResource = "authz.policies"`), `Internal/DashboardIcons.cs`, `Pages/Shared/_DashboardLayout.cshtml`
(nav entry), new `Areas/DynamicAuthorization/Pages/Policies/Index.cshtml(.cs)` and `Edit.cshtml(.cs)`, `dashboard.js`
only if the existing patterns need it.

- Index: resources with display name, key, endpoint count, and enforced and skipped policies; the orphans section
  with Clear buttons. Edit: checkboxes for registered policies with display name and description; unregistered
  ones still assigned are shown as skipped with a remove option.
- `[PermissionResource("authz.policies", DisplayName = "Dashboard / Policies")]`; GET requires `authz.policies.read`,
  POST requires `authz.policies.update` (as the Roles pages do).
- Feature off: hidden from navigation, and both pages return 404 to GET and POST (a page filter or an
  `OnPageHandlerExecutionAsync` check in the page model).
- Errors from the management service are shown with the existing `SetError` / status pattern.

Tests (`DashboardTests.cs`): page lists resources and assignments; edit saves and the next request enforces it;
read-only user can view but not post; feature off gives 404 for GET and POST and no nav link; safeguard error shown
for `authz.*` with no super admin; CSP: no inline script or style (existing CSP test pattern).

## Task 10: Endpoints, Access check and Overview

Files: `Pages/Endpoints.cshtml(.cs)`, `Pages/Access.cshtml(.cs)`, `Pages/Index.cshtml(.cs)`.

Shown only while the feature is on. The store isn't read otherwise.

- Endpoints: an assigned-policies column (enforced and skipped) per endpoint's resource.
- Access check: for the checked permission, list the resources of the endpoints requiring it that have assigned
  policies. Show the enforced ones as "also required on requests, not evaluated here" and the skipped ones
  separately.
- Overview "needs attention": orphaned resources and unregistered policies, linking to the Policies page.

Tests: each page with and without the feature; skipped and enforced shown distinctly; no store call with the feature
off.

## Task 11: README and sample

- README: new section "Assigning policies to resources" covering everything the design's Documentation section
  lists, including the options-table rows (`AssignablePolicies`) and the EF opt-in with its migration command.
- Sample app: register one assignable policy (for example a business-hours requirement), opt the model in, add the
  migration. The sample test (if any) or a manual run shows the Policies page.
- Test: the sample's context has no pending model changes after the new migration
  (`context.Database.HasPendingModelChanges()` is false).

## Task 12: Final check

- Full CI sequence locally: restore, Release build, `dotnet format --verify-no-changes`, tests on both target
  frameworks, `dotnet pack`.
- Walk the design's "Required acceptance tests" list and point each item to its test; anything missing gets a test.
- Run the sample, assign a policy in the dashboard, and confirm a request is denied, then allowed after unassigning.
