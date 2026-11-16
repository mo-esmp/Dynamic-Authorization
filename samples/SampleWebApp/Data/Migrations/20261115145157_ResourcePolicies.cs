using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SampleWebApp.Data.Migrations
{
    /// <inheritdoc />
    public partial class ResourcePolicies : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AspNetResourcePolicies",
                columns: table => new
                {
                    Resource = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    PolicyName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetResourcePolicies", x => new { x.Resource, x.PolicyName });
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AspNetResourcePolicies");
        }
    }
}
