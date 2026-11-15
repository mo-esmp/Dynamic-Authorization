using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace SampleWebApp.Data;

public sealed class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : IdentityDbContext(options)
{
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Adds the AspNetRolePermissions table to the Identity model, and the AspNetResourcePolicies table that stores the
        // policies admins assign to resources.
        builder.EnableDynamicAuthorization(o => o.ResourcePolicies = true);

        // Lets SQLite answer the dashboard's user search from the Identity indexes (see "Searching users" in the README).
        builder.Entity<IdentityUser>(user =>
        {
            user.Property(u => u.NormalizedUserName).UseCollation("NOCASE");
            user.Property(u => u.NormalizedEmail).UseCollation("NOCASE");
        });
    }
}
