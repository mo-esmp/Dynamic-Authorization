using System.Net;
using System.Text.RegularExpressions;
using DynamicAuthorization.AspNetCore.Tests.Infrastructure;

namespace DynamicAuthorization.AspNetCore.Tests;

/// <summary>
///   The dashboard's Policies pages. They exist only while a policy is assignable, so applications that don't assign
///   policies see no new page, link or permission.
/// </summary>
public sealed partial class DashboardPolicyTests
{
    [Fact]
    public async Task Pages_do_not_exist_while_no_policy_is_assignable()
    {
        await using TestApp app = await TestApp.StartAsync(o => o.Dashboard = true);
        HttpClient client = app.CreateClient(await app.CreateSuperAdminAsync());

        Assert.Equal(HttpStatusCode.NotFound, await client.GetStatusAsync("/authz/Policies"));
        Assert.Equal(HttpStatusCode.NotFound, await client.GetStatusAsync("/authz/Policies/Edit/orders"));
        Assert.Equal(HttpStatusCode.NotFound, await client.SendStatusAsync(HttpMethod.Post, "/authz/Policies?handler=Clear&resource=orders"));
        Assert.DoesNotContain("/authz/Policies", await client.GetStringAsync("/authz"), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(app.GetCatalog().Permissions, p => p.Permission.StartsWith("authz.policies", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Pages_are_protected_by_read_and_update_permissions()
    {
        await using TestApp app = await StartAsync();

        string[] permissions =
        [
            .. app.GetCatalog().Permissions
                .Where(p => p.Resource == "authz.policies")
                .Select(p => p.Permission)
                .Order(StringComparer.Ordinal)
        ];

        Assert.Equal(["authz.policies.read", "authz.policies.update"], permissions);
    }

    [Fact]
    public async Task Admins_list_resources_and_assign_policies()
    {
        await using TestApp app = await StartAsync();
        HttpClient admin = app.CreateClient(await app.CreateSuperAdminAsync());
        TestUser user = await app.CreateUserWithPermissionsAsync("alice", "orders.read");

        string overview = await admin.GetStringAsync("/authz");
        string list = await admin.GetStringAsync("/authz/Policies");
        HttpResponseMessage saved = await PostFormAsync(admin, "/authz/Policies/Edit/orders", "/authz/Policies/Edit/orders", [new("PolicyNames", "Deny")]);
        string after = await FollowRedirectAsync(admin, saved);

        Assert.Contains("href=\"/authz/Policies\"", overview, StringComparison.Ordinal);
        Assert.Contains("href=\"/authz/Policies/Edit/orders\"", list, StringComparison.Ordinal);
        Assert.Contains("data-policy=\"Deny\"", after, StringComparison.Ordinal);
        Assert.Contains("The policies of &#x27;Orders&#x27; were saved.", after, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Forbidden, await app.CreateClient(user).GetStatusAsync("/Orders"));
    }

    [Fact]
    public async Task Readers_can_list_but_not_change()
    {
        await using TestApp app = await StartAsync();
        HttpClient reader = app.CreateClient(await app.CreateUserWithPermissionsAsync("rita", "authz.policies.read"));

        string list = await reader.GetStringAsync("/authz/Policies");

        Assert.DoesNotContain("/authz/Policies/Edit/", list, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Forbidden, await reader.GetStatusAsync("/authz/Policies/Edit/orders"));
        Assert.Equal(HttpStatusCode.Forbidden, await reader.SendStatusAsync(HttpMethod.Post, "/authz/Policies/Edit/orders"));
        Assert.Equal(HttpStatusCode.Forbidden, await reader.SendStatusAsync(HttpMethod.Post, "/authz/Policies?handler=Clear&resource=orders"));
    }

    [Fact]
    public async Task Refused_changes_are_explained()
    {
        await using TestApp app = await StartAsync(a => a.SuperAdminUsers.Clear());
        HttpClient editor = app.CreateClient(await app.CreateUserWithPermissionsAsync("ed", "authz.policies.read", "authz.policies.update"));

        string form = await editor.GetStringAsync("/authz/Policies/Edit/authz.roles");
        HttpResponseMessage refused = await PostFormAsync(editor, "/authz/Policies/Edit/authz.roles", "/authz/Policies/Edit/authz.roles", [new("PolicyNames", "Allow")]);
        string page = await refused.Content.ReadAsStringAsync();

        Assert.Contains("lock everyone out of the dashboard", form, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, refused.StatusCode);
        Assert.Contains("no super admin is configured", page, StringComparison.Ordinal);
        Assert.Empty(await app.WithScopeAsync(s => s.GetRequiredService<IResourcePolicyStore>().GetAssignmentsAsync()));
    }

    [Fact]
    public async Task Skipped_and_orphaned_assignments_are_shown_and_can_be_removed()
    {
        await using TestApp app = await StartAsync();
        await app.WithScopeAsync(async s =>
        {
            IResourcePolicyStore store = s.GetRequiredService<IResourcePolicyStore>();
            await store.SetPoliciesAsync("orders", ["Allow", "Retired"]);
            await store.SetPoliciesAsync("removed", ["Allow"]);
            return true;
        });
        HttpClient admin = app.CreateClient(await app.CreateSuperAdminAsync());

        string list = await admin.GetStringAsync("/authz/Policies");
        string edit = await admin.GetStringAsync("/authz/Policies/Edit/orders");
        HttpResponseMessage cleared = await PostFormAsync(admin, "/authz/Policies", "/authz/Policies?handler=Clear&resource=removed", []);
        await FollowRedirectAsync(admin, cleared);

        Assert.Contains("data-skipped-policy=\"Retired\"", list, StringComparison.Ordinal);
        Assert.Contains("removed", list, StringComparison.Ordinal);
        Assert.Contains("value=\"Retired\" checked=\"checked\"", edit, StringComparison.Ordinal);
        IReadOnlyDictionary<string, IReadOnlySet<string>> remaining = await app.WithScopeAsync(s => s.GetRequiredService<IResourcePolicyStore>().GetAssignmentsAsync());
        Assert.Equal(["orders"], remaining.Keys);
    }

    [Fact]
    public async Task Pages_work_with_a_strict_content_security_policy()
    {
        await using TestApp app = await StartAsync();
        HttpClient admin = app.CreateClient(await app.CreateSuperAdminAsync());

        foreach (string url in new[] { "/authz/Policies", "/authz/Policies/Edit/orders" })
        {
            string html = await admin.GetStringAsync(url);
            Assert.DoesNotMatch(InlineScriptOrStyleRegex(), html);
        }
    }

    [Fact]
    public async Task Other_pages_show_assigned_policies()
    {
        await using TestApp app = await StartAsync();
        await app.WithScopeAsync(async s =>
        {
            IResourcePolicyStore store = s.GetRequiredService<IResourcePolicyStore>();
            await store.SetPoliciesAsync("orders", ["Deny", "Retired"]);
            await store.SetPoliciesAsync("removed", ["Allow"]);
            return true;
        });
        HttpClient admin = app.CreateClient(await app.CreateSuperAdminAsync());
        TestUser alice = await app.CreateUserWithPermissionsAsync("alice", "orders.read");

        string endpoints = await admin.GetStringAsync("/authz/Endpoints");
        string access = await admin.GetStringAsync($"/authz/Access?userId={alice.Id}&permission=orders.read");
        string overview = await admin.GetStringAsync("/authz");

        Assert.Contains("<th scope=\"col\">Policies</th>", endpoints, StringComparison.Ordinal);
        Assert.Contains("data-policy=\"Deny\"", endpoints, StringComparison.Ordinal);
        Assert.Contains("data-skipped-policy=\"Retired\"", endpoints, StringComparison.Ordinal);
        Assert.Contains("data-assigned-policies", access, StringComparison.Ordinal);
        Assert.Contains("data-policy=\"Deny\"", access, StringComparison.Ordinal);
        Assert.Contains("data-skipped-policies", access, StringComparison.Ordinal);
        Assert.Contains("data-orphaned-policies=\"removed\"", overview, StringComparison.Ordinal);
        Assert.Contains("data-skipped-policies=\"orders\"", overview, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Other_pages_do_not_read_assignments_while_no_policy_is_assignable()
    {
        InMemoryResourcePolicyStore store = new() { Throw = true };
        await using TestApp app = await TestApp.StartAsync(o =>
        {
            o.Dashboard = true;
            o.Services = s => s.AddSingleton<IResourcePolicyStore>(store);
        });
        HttpClient admin = app.CreateClient(await app.CreateSuperAdminAsync());
        TestUser alice = await app.CreateUserWithPermissionsAsync("alice", "orders.read");

        string endpoints = await admin.GetStringAsync("/authz/Endpoints");
        string access = await admin.GetStringAsync($"/authz/Access?userId={alice.Id}&permission=orders.read");
        string overview = await admin.GetStringAsync("/authz");

        Assert.DoesNotContain("<th scope=\"col\">Policies</th>", endpoints, StringComparison.Ordinal);
        Assert.DoesNotContain("data-assigned-policies", access, StringComparison.Ordinal);
        Assert.DoesNotContain("data-orphaned-policies", overview, StringComparison.Ordinal);
        Assert.Equal(0, store.Reads);
    }

    private static Task<TestApp> StartAsync(Action<DynamicAuthorizationOptions>? configure = null) =>
        TestApp.StartAsync(o =>
        {
            o.Dashboard = true;
            o.Authorization = a =>
            {
                a.AddAssignablePolicy("Allow", "Always allowed", "Passes for everyone.");
                a.AddAssignablePolicy("Deny");
                configure?.Invoke(a);
            };
            o.Services = s => s.AddAuthorizationBuilder()
                .AddPolicy("Allow", p => p.RequireAssertion(_ => true))
                .AddPolicy("Deny", p => p.RequireAssertion(_ => false));
        });

    private static async Task<string> FollowRedirectAsync(HttpClient client, HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        using HttpRequestMessage request = new(HttpMethod.Get, response.Headers.Location);
        foreach (string cookie in response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? cookies) ? cookies : [])
        {
            request.Headers.Add("Cookie", cookie.Split(';')[0]);
        }

        HttpResponseMessage page = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);

        return await page.Content.ReadAsStringAsync();
    }

    private static async Task<HttpResponseMessage> PostFormAsync(HttpClient client, string formUrl, string postUrl, KeyValuePair<string, string>[] fields)
    {
        HttpResponseMessage form = await client.GetAsync(formUrl);
        Assert.Equal(HttpStatusCode.OK, form.StatusCode);
        string html = await form.Content.ReadAsStringAsync();
        string token = AntiforgeryTokenRegex().Match(html).Groups[1].Value;
        Assert.NotEmpty(token);

        using HttpRequestMessage request = new(HttpMethod.Post, postUrl)
        {
            Content = new FormUrlEncodedContent([.. fields, new("__RequestVerificationToken", token)]),
        };
        foreach (string cookie in form.Headers.GetValues("Set-Cookie"))
        {
            request.Headers.Add("Cookie", cookie.Split(';')[0]);
        }

        return await client.SendAsync(request);
    }

    [GeneratedRegex("""name="__RequestVerificationToken" type="hidden" value="([^"]+)""")]
    private static partial Regex AntiforgeryTokenRegex();

    [GeneratedRegex("""<script(?![^>]*\ssrc=)[^>]*>|\sstyle=|<style""", RegexOptions.IgnoreCase)]
    private static partial Regex InlineScriptOrStyleRegex();
}
