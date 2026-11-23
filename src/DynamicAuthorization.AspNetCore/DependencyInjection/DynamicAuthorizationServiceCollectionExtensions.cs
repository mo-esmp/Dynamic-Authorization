using DynamicAuthorization.AspNetCore;
using DynamicAuthorization.AspNetCore.Management;
using DynamicAuthorization.AspNetCore.TagHelpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
///   Extension methods for registering dynamic authorization in an <see cref="IServiceCollection"/>.
/// </summary>
public static class DynamicAuthorizationServiceCollectionExtensions
{
    /// <summary>
    ///   Adds dynamic authorization. Add a store, for example with <c>AddEntityFrameworkStore&lt;TContext&gt;()</c>,
    ///   to persist the permissions granted to roles. User roles and role permissions are cached in the memory of the
    ///   instance unless another <see cref="IDynamicAuthorizationCacheStore"/> is registered, before this call or by
    ///   replacing the registration afterwards.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Configures <see cref="DynamicAuthorizationOptions"/>.</param>
    /// <returns>A builder to configure dynamic authorization further.</returns>
    public static IDynamicAuthorizationBuilder AddDynamicAuthorization(
        this IServiceCollection services,
        Action<DynamicAuthorizationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        OptionsBuilder<DynamicAuthorizationOptions> options = services.AddOptions<DynamicAuthorizationOptions>();
        if (configure is not null)
        {
            options.Configure(configure);
        }

        options
            .Validate(o => o.CacheDuration >= TimeSpan.Zero, $"{nameof(DynamicAuthorizationOptions.CacheDuration)} must not be negative.")
            .ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<DynamicAuthorizationOptions>, ValidateDynamicAuthorizationOptions>());

        services.AddAuthorization();
        services.AddOptions<AuthorizationOptions>().ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<AuthorizationOptions>, ValidateAuthorizationOptions>());
        services.TryAddSingleton<IDynamicAuthorizationCacheStore, MemoryDynamicAuthorizationCacheStore>();
        services.TryAddSingleton<DynamicAuthorizationCache>();
        services.TryAddSingleton<IDynamicAuthorizationCache>(sp => sp.GetRequiredService<DynamicAuthorizationCache>());
        services.TryAddSingleton<AssignablePolicyRegistry>();
        services.TryAddSingleton<ResourcePolicyEvaluator>();
        // Resolved through a factory: most applications have no resource policy store, and validating the registration
        // at startup must not require one.
        services.TryAddScoped<IResourcePolicyManagementService>(sp =>
            sp.GetService<IResourcePolicyStore>() is { } store
                ? ActivatorUtilities.CreateInstance<ResourcePolicyManagementService>(sp, store)
                : throw new InvalidOperationException(
                    $"No {nameof(IResourcePolicyStore)} is registered to store the policies assigned to resources. Call " +
                    "AddEntityFrameworkStore<TContext>() and enable the table with EnableDynamicAuthorization(o => o.ResourcePolicies = true), " +
                    $"or register your own {nameof(IResourcePolicyStore)}."));
        services.TryAddSingleton<EndpointAuthorizationResolver>();
        services.TryAddSingleton<EndpointPolicyCache>();
        services.TryAddSingleton<IPermissionCatalogProvider, PermissionCatalogProvider>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, ControllerNameValidator>());
        services.TryAddScoped<IPermissionChecker, PermissionChecker>();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IAuthorizationHandler, DynamicPermissionHandler>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<AuthorizationOptions>, ConfigureAuthorizationOptions>());

        return new DynamicAuthorizationBuilder(services);
    }
}
