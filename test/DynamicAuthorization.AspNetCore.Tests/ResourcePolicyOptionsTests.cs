using DynamicAuthorization.AspNetCore.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace DynamicAuthorization.AspNetCore.Tests;

/// <summary>
///   Applications declare which of their authorization policies admins may assign to resources. Names are compared
///   like ASP.NET Core compares policy names, ignoring case, so a registration must be unambiguous at startup.
/// </summary>
public sealed class ResourcePolicyOptionsTests
{
    [Fact]
    public void AddAssignablePolicy_keeps_registrations_in_order()
    {
        DynamicAuthorizationOptions options = new DynamicAuthorizationOptions()
            .AddAssignablePolicy("BusinessHours", "Business hours only")
            .AddAssignablePolicy("RequireMfa", "Multi-factor sign-in", "The user signed in with MFA.");

        Assert.Equal(
            [
                new AssignablePolicyDefinition("BusinessHours", "Business hours only"),
                new AssignablePolicyDefinition("RequireMfa", "Multi-factor sign-in", "The user signed in with MFA."),
            ],
            options.AssignablePolicies);
    }

    [Fact]
    public void AddAssignablePolicy_trims_the_name()
    {
        DynamicAuthorizationOptions options = new DynamicAuthorizationOptions().AddAssignablePolicy("  BusinessHours ");

        Assert.Equal("BusinessHours", Assert.Single(options.AssignablePolicies).Name);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void AddAssignablePolicy_rejects_a_blank_name(string name) =>
        Assert.Throws<ArgumentException>(() => new DynamicAuthorizationOptions().AddAssignablePolicy(name));

    [Fact]
    public void AddAssignablePolicy_rejects_a_null_name() =>
        Assert.Throws<ArgumentNullException>(() => new DynamicAuthorizationOptions().AddAssignablePolicy(null!));

    [Fact]
    public async Task Duplicate_names_that_differ_only_in_case_are_rejected_at_startup()
    {
        OptionsValidationException exception = await Assert.ThrowsAsync<OptionsValidationException>(() =>
            TestApp.StartAsync(o => o.Authorization = a => a
                .AddAssignablePolicy("BusinessHours")
                .AddAssignablePolicy("businesshours")));

        Assert.Contains("businesshours", exception.Message, StringComparison.Ordinal);
        Assert.Contains("more than once", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Names_longer_than_the_maximum_are_rejected_at_startup()
    {
        string name = new('p', AssignablePolicyDefinition.MaxNameLength + 1);

        OptionsValidationException exception = await Assert.ThrowsAsync<OptionsValidationException>(() =>
            TestApp.StartAsync(o => o.Authorization = a => a.AddAssignablePolicy(name)));

        Assert.Contains(AssignablePolicyDefinition.MaxNameLength.ToString(System.Globalization.CultureInfo.InvariantCulture), exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(" BusinessHours")]
    [InlineData("BusinessHours ")]
    public async Task Blank_or_padded_names_added_to_the_list_directly_are_rejected_at_startup(string name)
    {
        OptionsValidationException exception = await Assert.ThrowsAsync<OptionsValidationException>(() =>
            TestApp.StartAsync(o => o.Authorization = a => a.AssignablePolicies.Add(new AssignablePolicyDefinition(name))));

        Assert.Contains(nameof(DynamicAuthorizationOptions.AssignablePolicies), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Registered_names_are_looked_up_ignoring_case()
    {
        await using TestApp app = await TestApp.StartAsync(o =>
        {
            o.Services = s => s.AddSingleton<IResourcePolicyStore, InMemoryResourcePolicyStore>();
            o.Authorization = a => a
                .AddAssignablePolicy("BusinessHours")
                .AddAssignablePolicy("RequireMfa");
        });

        AssignablePolicyRegistry registry = app.Services.GetRequiredService<AssignablePolicyRegistry>();

        Assert.True(registry.IsEnabled);
        Assert.True(registry.IsRegistered("businesshours"));
        Assert.True(registry.IsRegistered("REQUIREMFA"));
        Assert.False(registry.IsRegistered("Other"));
    }

    [Fact]
    public async Task Assignable_policies_without_a_store_are_rejected_at_startup()
    {
        OptionsValidationException exception = await Assert.ThrowsAsync<OptionsValidationException>(() =>
            TestApp.StartAsync(o =>
            {
                o.Services = s => s.RemoveAll<IResourcePolicyStore>();
                o.Authorization = a => a.AddAssignablePolicy("BusinessHours");
            }));

        Assert.Contains(nameof(IResourcePolicyStore), exception.Message, StringComparison.Ordinal);
        Assert.Contains("AddEntityFrameworkStore", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task No_store_is_needed_while_no_policy_is_assignable()
    {
        await using TestApp app = await TestApp.StartAsync(o => o.Services = s => s.RemoveAll<IResourcePolicyStore>());

        Assert.Null(app.Services.GetService<IResourcePolicyStore>());
        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            app.WithScopeAsync(s => Task.FromResult(s.GetRequiredService<Management.IResourcePolicyManagementService>())));
        Assert.Contains(nameof(IResourcePolicyStore), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Any_registered_store_satisfies_the_startup_check()
    {
        await using TestApp app = await TestApp.StartAsync(o =>
        {
            o.Services = s => s.AddSingleton<IResourcePolicyStore, InMemoryResourcePolicyStore>();
            o.Authorization = a => a.AddAssignablePolicy("BusinessHours");
        });

        Assert.IsType<InMemoryResourcePolicyStore>(app.Services.GetRequiredService<IResourcePolicyStore>());
    }

    [Fact]
    public async Task Feature_is_off_without_registrations()
    {
        await using TestApp app = await TestApp.StartAsync();

        AssignablePolicyRegistry registry = app.Services.GetRequiredService<AssignablePolicyRegistry>();

        Assert.False(registry.IsEnabled);
        Assert.False(registry.IsRegistered("BusinessHours"));
    }
}
