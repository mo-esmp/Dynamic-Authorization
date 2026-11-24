# Resource policies design: second review

Date: 2026-11-15  
Spec reviewed: [2026-11-15-resource-policies-design.md](2026-11-15-resource-policies-design.md)  
Reviewed status: awaiting maintainer approval

This review covers the revised spec and checks relevant behavior against the current implementation. References to line numbers describe the version reviewed and may shift after edits. These are review recommendations, not implementation instructions or maintainer decisions.

## Addressed since the first review

- **EF schema opt-in:** The resource-policy table is explicitly opt-in. Applications that do not enable it avoid the new model change.
- **Registration removal:** Removing a registration deliberately stops enforcing that policy, consistently including the last registration. This resolves the earlier contradiction between inactive-feature behavior and stale-assignment handling as an explicit design decision.

## Remaining findings

### 1. “Never widen access” still contradicts policy removal

Reference: Anti-goals, spec line 35.

The added exception covers developers removing registrations, but admins can also unassign policies. Removing `RequireMfa` broadens access compared with the previous assignment.

Suggested replacement:

> Assignments never grant permissions or bypass static authorization. Removing assignments may relax the additional restrictions they introduced.

### 2. The dashboard lockout guarantee remains conditional

Reference: Super-admin behavior, spec line 57.

Super-admin bypass helps only when a usable super-admin account exists. Both `SuperAdminUsers` and `SuperAdminRoles` currently default to empty collections.

State that prerequisite, or define safeguards for assigning policies to dashboard resources without a recovery account.

### 3. Recursion protection and “once per request” remain underspecified

Reference: Evaluation, spec lines 152–160.

Rejecting policies containing `DynamicPermissionRequirement` catches direct recursion, but another requirement's handler can indirectly invoke a policy containing it.

Specify a reentrancy guard. Also define how evaluation results are scoped to the principal and endpoint, preserve failed results, and distinguish an evaluation in progress from one that succeeded. These are behavioral requirements, even if the marker's implementation stays with the builder.

### 4. Custom-provider compatibility exceeds what the resolver supports

References: Registration, spec lines 101–102; evaluation eligibility, lines 139–140; `src/DynamicAuthorization.AspNetCore/Catalog/EndpointAuthorizationResolver.cs`, lines 459–460.

The current resolver classifies named endpoint policies known only to a custom provider as static. Such a policy can contain the dynamic requirement, yet the spec's `DynamicPermission` eligibility condition would skip assigned policies.

Either address that integration or explicitly limit the compatibility promise to resolving **assigned policy names**, with the endpoint-classification limitation documented.

### 5. Authentication schemes need an explicit safety decision

Reference: Chosen approach, spec lines 67–72.

The spec acknowledges that authentication schemes are ignored, but that means an assigned policy does not necessarily retain its original meaning. A policy intended to require a particular authentication scheme could instead accept the existing principal.

Recommendation: reject assigned policies with nonempty `AuthenticationSchemes`, including at request time when a provider can change its result. Scheme authentication happens separately in [ASP.NET Core's policy evaluator](https://raw.githubusercontent.com/dotnet/aspnetcore/main/src/Security/Authorization/Policy/src/PolicyEvaluator.cs).

### 6. The new skip behavior needs matching dashboard and lifecycle rules

Reference: Dashboard, spec lines 178–184.

Overview correctly labels unregistered policies as skipped, but Access check still says assigned policies are required. It must distinguish enforced assignments from skipped ones.

Also document these consequences of retaining skipped assignments:

- Restoring a removed registration reactivates its stored assignments.
- Instances with different registrations during a rolling deployment may enforce different restrictions.

### 7. Cleanup and write guarantees remain missing

Reference: Management, spec lines 164–168.

Unknown resources are rejected even when clearing their assignments, so the dashboard can identify orphaned data without offering a repair path. Permit clearing unknown resources or provide a cleanup operation.

Specify atomic replacement, concurrent-edit behavior, and invalidation after commit that survives request cancellation. Atomic replacement must prevent readers from observing a temporary empty assignment set between deletion and insertion.

## Other outstanding contracts

- **Names and validation:** Define policy-name comparison, canonical resource keys, duplicate registration handling, whitespace rules, and storage length limits.
- **Public API compatibility:** Adding a required member to `IDynamicAuthorizationCache` can break its implementers even though `IDynamicAuthorizationCacheStore` is preserved.
- **Custom stores:** Define how applications using non-EF stores register the resource-policy management service.
- **Dependency injection:** Avoid directly constructor-injecting `IAuthorizationService` into its own authorization handler. Under the default registrations, that creates a service → handler provider → handlers → service dependency cycle. See the framework's [authorization service](https://raw.githubusercontent.com/dotnet/aspnetcore/main/src/Security/Authorization/Core/src/DefaultAuthorizationService.cs) and [handler provider](https://raw.githubusercontent.com/dotnet/aspnetcore/main/src/Security/Authorization/Core/src/DefaultAuthorizationHandlerProvider.cs).
- **Inactive dashboard:** Specify that direct GET/POST access is disabled when the feature is inactive, in addition to hiding its navigation entry.

## Required acceptance coverage

Move security acceptance criteria out of the general “left to the builder” test-coverage item. At minimum, require tests for:

- Indirect recursion and reentrancy.
- Repeated authorization, including different principals or endpoints and previously failed evaluations.
- Registration removal and restoration, including removing the last registration.
- Scheme-bearing assigned policies under the chosen contract.
- Endpoint policies supplied by custom policy providers.
- Orphan-assignment cleanup.
- Atomic replacement and the chosen concurrent-edit behavior.
- Request cancellation after persistence commits.
- Cross-instance cache invalidation.

The spec and implementation were not modified as part of this review.
