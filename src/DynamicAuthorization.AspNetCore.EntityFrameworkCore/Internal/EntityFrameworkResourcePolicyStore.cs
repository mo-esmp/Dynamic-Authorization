using DynamicAuthorization.AspNetCore.Management;
using Microsoft.EntityFrameworkCore;

namespace DynamicAuthorization.AspNetCore.EntityFrameworkCore;

internal sealed class EntityFrameworkResourcePolicyStore<TContext>(TContext context) : IResourcePolicyStore
    where TContext : DbContext
{
    public async Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetAssignmentsAsync(CancellationToken cancellationToken = default)
    {
        var rows = await context.ResourcePolicies()
            .AsNoTracking()
            .Select(p => new { p.Resource, p.PolicyName })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        Dictionary<string, HashSet<string>> assignments = [with(StringComparer.OrdinalIgnoreCase)];
        foreach (var row in rows)
        {
            if (!assignments.TryGetValue(row.Resource, out HashSet<string>? policies))
            {
                policies = [with(StringComparer.OrdinalIgnoreCase)];
                assignments[row.Resource] = policies;
            }

            policies.Add(row.PolicyName);
        }

        return assignments.ToDictionary(a => a.Key, IReadOnlySet<string> (a) => a.Value, StringComparer.OrdinalIgnoreCase);
    }

    public async Task SetPoliciesAsync(string resource, IEnumerable<string> policyNames, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policyNames);
        string key = NormalizeResource(resource);
        List<string> desired = NormalizeNames(policyNames);
        DbSet<ResourcePolicy> set = context.ResourcePolicies();

        // Deleting first takes the write locks, so a concurrent replacement waits for this one and the last commit wins;
        // readers see the committed policies from before or after, never the empty set in between.
        await context.ExecuteInTransactionAsync(
            async ct =>
            {
                IEnumerable<string> added = desired;
                if (context.Database.IsRelational())
                {
                    await set.Where(p => p.Resource == key).ExecuteDeleteAsync(ct).ConfigureAwait(false);
                }
                else
                {
                    // Without set-based deletes, tracking a deleted and an added row with the same key fails: keep the rows
                    // that stay.
                    List<ResourcePolicy> existing = await set.Where(p => p.Resource == key).ToListAsync(ct).ConfigureAwait(false);
                    HashSet<string> wanted = new(desired, StringComparer.OrdinalIgnoreCase);
                    set.RemoveRange(existing.Where(p => !wanted.Contains(p.PolicyName)));
                    HashSet<string> kept = new(existing.Select(p => p.PolicyName), StringComparer.OrdinalIgnoreCase);
                    added = desired.Where(name => !kept.Contains(name));
                }

                set.AddRange(added.Select(name => new ResourcePolicy { Resource = key, PolicyName = name }));
                await context.SaveChangesAsync(ct).ConfigureAwait(false);

                return ManagementResult.Ok();
            },
            cancellationToken).ConfigureAwait(false);
    }

    private static string NormalizeResource(string resource)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(resource);
        string key = resource.Trim().ToLowerInvariant();
        if (key.Length > DynamicAuthorizationModelOptions.MaxPermissionLength)
        {
            throw new ArgumentException(
                $"The resource '{key}' is longer than {DynamicAuthorizationModelOptions.MaxPermissionLength} characters.", nameof(resource));
        }

        return key;
    }

    private static List<string> NormalizeNames(IEnumerable<string> policyNames)
    {
        List<string> names = [];
        HashSet<string> seen = [with(StringComparer.OrdinalIgnoreCase)];
        foreach (string name in policyNames)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            string trimmed = name.Trim();
            if (trimmed.Length > AssignablePolicyDefinition.MaxNameLength)
            {
                throw new ArgumentException(
                    $"The policy name '{trimmed}' is longer than {AssignablePolicyDefinition.MaxNameLength} characters.", nameof(policyNames));
            }

            if (seen.Add(trimmed))
            {
                names.Add(trimmed);
            }
        }

        return names;
    }
}
