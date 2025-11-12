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

        var cs = _cfg.GetConnectionString("HelpLineDb");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        const string sql = @"
            IF OBJECT_ID('tempdb..#users') IS NOT NULL DROP TABLE #users;

            SELECT u.Id, u.Name, u.Email, u.Origin
            INTO #users
            FROM dbo.[User] u
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
                    var id = rdr.GetGuid(0);
                    var name = rdr.GetString(1);
                    var email = rdr.GetString(2);
                    var originVal = rdr.GetString(3);
                    var rolesCsv = rdr.IsDBNull(4) ? "" : rdr.GetString(4);
                    var rolesArr = string.IsNullOrEmpty(rolesCsv)
                        ? Array.Empty<string>()
                        : rolesCsv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

                    items.Add(new UserListItem(id, name, email, originVal, rolesArr));
                }
            }
        }

        return Ok(new UserListResponse(total, page, pageSize, items));
    }

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<UserListItem>> GetById(Guid id)
    {
        var cs = _cfg.GetConnectionString("HelpLineDb");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        const string sql = @"
            SELECT u.Id, u.Name, u.Email, u.Origin,
                STUFF((
                    SELECT ',' + r.Name
                    FROM dbo.UserRole ur
                    JOIN dbo.Role r ON r.Id = ur.RoleId
                    WHERE ur.UserId = u.Id
                    FOR XML PATH(''), TYPE
                ).value('.', 'nvarchar(max)'), 1, 1, '') AS RolesCsv
            FROM dbo.[User] u
            WHERE u.Id = @Id;";

        await using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = id });

        await using var rdr = await cmd.ExecuteReaderAsync();
        if (!await rdr.ReadAsync())
            return NotFound();

        var rolesCsv = rdr.IsDBNull(4) ? "" : rdr.GetString(4);
        var rolesArr = string.IsNullOrEmpty(rolesCsv)
            ? Array.Empty<string>()
            : rolesCsv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        return Ok(new UserListItem(rdr.GetGuid(0), rdr.GetString(1), rdr.GetString(2), rdr.GetString(3), rolesArr));
    }

    [HttpPatch("{id:guid}/roles")]
    public async Task<IActionResult> UpdateRoles(Guid id, [FromBody] UpdateRolesRequest req)
    {
        var cs = _cfg.GetConnectionString("HelpLineDb");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();
        await using var tx = await conn.BeginTransactionAsync();

        try
        {
            var del = new SqlCommand("DELETE FROM dbo.UserRole WHERE UserId=@U", conn, (SqlTransaction)tx);
            del.Parameters.Add(new SqlParameter("@U", SqlDbType.UniqueIdentifier) { Value = id });
            await del.ExecuteNonQueryAsync();

            foreach (var r in req.Roles ?? Array.Empty<string>())
            {
                var roleIdCmd = new SqlCommand("SELECT Id FROM dbo.Role WHERE Name=@Name", conn, (SqlTransaction)tx);
                roleIdCmd.Parameters.Add(new SqlParameter("@Name", SqlDbType.NVarChar, 50) { Value = r });
                var roleIdObj = await roleIdCmd.ExecuteScalarAsync();
                if (roleIdObj == null || roleIdObj is DBNull)
                    continue;

                var linkRole = new SqlCommand("INSERT INTO dbo.UserRole(UserId, RoleId) VALUES(@U,@R)", conn, (SqlTransaction)tx);
                linkRole.Parameters.Add(new SqlParameter("@U", SqlDbType.UniqueIdentifier) { Value = id });
                linkRole.Parameters.Add(new SqlParameter("@R", SqlDbType.Int) { Value = Convert.ToInt32(roleIdObj) });
                await linkRole.ExecuteNonQueryAsync();
            }

            await tx.CommitAsync();
            return NoContent();
        }
        catch
        {
            await tx.RollbackAsync();
            throw;
        }
    }
}