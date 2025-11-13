using System.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace Helpline.Api.Controllers;

[ApiController]
[Route("users")]
[Authorize(Roles = "Analyst,Admin")]
public class UsersController : ControllerBase
{
    private readonly IConfiguration _cfg;

    public UsersController(IConfiguration cfg) => _cfg = cfg;

    public record UserListItem(Guid Id, string Name, string Email, string Origin, string[] Roles);
    public record UserListResponse(int Total, int Page, int PageSize, IEnumerable<UserListItem> Items);
    public record UpdateRolesRequest(string[] Roles);

    [HttpGet]
    public async Task<ActionResult<UserListResponse>> List(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        [FromQuery] string? q = null,
        [FromQuery] string? origin = null,
        [FromQuery] string? role = null)
    {
        if (page < 1) page = 1;
        if (pageSize < 1) pageSize = 20;
        if (pageSize > 100) pageSize = 100;

        var skip = (page - 1) * pageSize;

        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        const string sql = @"
            IF OBJECT_ID('tempdb..#users') IS NOT NULL DROP TABLE #users;

            SELECT u.Id, u.Name, u.Email, u.Origin
            INTO #users
            FROM dbo.Users u
            WHERE (@q IS NULL OR (u.Name LIKE '%' + @q + '%' OR u.Email LIKE '%' + @q + '%'))
              AND (@origin IS NULL OR u.Origin = @origin);

            SELECT COUNT(*) FROM #users;

            SELECT u.Id, u.Name, u.Email, u.Origin,
                STUFF((
                    SELECT ',' + r.Name
                    FROM dbo.UserRole ur
                    JOIN dbo.Role r ON r.Id = ur.RoleId
                    WHERE ur.UserId = u.Id
                    FOR XML PATH(''), TYPE
                ).value('.', 'nvarchar(max)'), 1, 1, '') AS RolesCsv
            FROM #users u
            WHERE (@role IS NULL OR EXISTS(
                SELECT 1
                FROM dbo.UserRole ur
                JOIN dbo.Role r ON r.Id = ur.RoleId
                WHERE ur.UserId = u.Id AND r.Name = @role
            ))
            ORDER BY u.Name
            OFFSET @skip ROWS FETCH NEXT @take ROWS ONLY;";

        await using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add(new SqlParameter("@q", SqlDbType.NVarChar, 255) { Value = (object?)q ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@origin", SqlDbType.NVarChar, 16) { Value = (object?)origin ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@role", SqlDbType.NVarChar, 50) { Value = (object?)role ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@skip", SqlDbType.Int) { Value = skip });
        cmd.Parameters.Add(new SqlParameter("@take", SqlDbType.Int) { Value = pageSize });

        int total = 0;
        var items = new List<UserListItem>();

        await using (var rdr = await cmd.ExecuteReaderAsync())
        {
            if (await rdr.ReadAsync())
                total = rdr.GetInt32(0);

            if (await rdr.NextResultAsync())
            {
                while (await rdr.ReadAsync())
                {
                    var rolesCsv = rdr.IsDBNull(4) ? "" : rdr.GetString(4);
                    var roles = string.IsNullOrWhiteSpace(rolesCsv) ? Array.Empty<string>() : rolesCsv.Split(',', StringSplitOptions.RemoveEmptyEntries);
                    items.Add(new UserListItem(
                        rdr.GetGuid(0),
                        rdr.GetString(1),
                        rdr.GetString(2),
                        rdr.GetString(3),
                        roles));
                }
            }
        }

        return Ok(new UserListResponse(total, page, pageSize, items));
    }

    [HttpPatch("{id:guid}/roles")]
    public async Task<ActionResult> UpdateRoles(Guid id, [FromBody] UpdateRolesRequest req)
    {
        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        // Remover roles existentes
        var del = new SqlCommand("DELETE FROM dbo.UserRole WHERE UserId = @U", conn);
        del.Parameters.Add(new SqlParameter("@U", SqlDbType.UniqueIdentifier) { Value = id });
        await del.ExecuteNonQueryAsync();

        // Inserir novas roles
        foreach (var role in req.Roles.Distinct())
        {
            var roleIdCmd = new SqlCommand("SELECT Id FROM dbo.Role WHERE Name=@Name", conn);
            roleIdCmd.Parameters.Add(new SqlParameter("@Name", SqlDbType.NVarChar, 50) { Value = role });
            var roleIdObj = await roleIdCmd.ExecuteScalarAsync();
            if (roleIdObj == null || roleIdObj is DBNull)
                return BadRequest($"Role '{role}' não encontrada.");
            var roleId = Convert.ToInt32(roleIdObj);

            var ins = new SqlCommand("INSERT INTO dbo.UserRole(UserId, RoleId) VALUES(@U,@R)", conn);
            ins.Parameters.Add(new SqlParameter("@U", SqlDbType.UniqueIdentifier) { Value = id });
            ins.Parameters.Add(new SqlParameter("@R", SqlDbType.Int) { Value = roleId });
            await ins.ExecuteNonQueryAsync();
        }

        return NoContent();
    }
}