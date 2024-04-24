using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IDriveApi.Migrations
{
    /// <inheritdoc />
    public partial class RefreshTokenRename : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "RefreshToen",
                table: "AspNetUsers",
                newName: "RefreshToken");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "RefreshToken",
                table: "AspNetUsers",
                newName: "RefreshToen");
        }
    }
}
