using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AimTrainerRestApi.Migrations
{
    /// <inheritdoc />
    public partial class removeEmail : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Email",
                table: "User");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "Email",
                table: "User",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }
    }
}
