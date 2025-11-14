using System.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace Helpline.Api.Controllers;

[ApiController]
[Route("departments")]
[AllowAnonymous]
public class DepartmentsController : ControllerBase
{
    private readonly IConfiguration _cfg;

    public DepartmentsController(IConfiguration cfg) => _cfg = cfg;

    public record DepartmentDto(int Id, string Name);

    [HttpGet]
    public async Task<ActionResult<IEnumerable<DepartmentDto>>> GetAll()
    {
        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        const string sql = @"
            SELECT Id, Name
            FROM dbo.Department
            ORDER BY Name;
        ";

        await using var cmd = new SqlCommand(sql, conn);
        var items = new List<DepartmentDto>();
        await using var rdr = await cmd.ExecuteReaderAsync();
        while (await rdr.ReadAsync())
        {
            items.Add(new DepartmentDto(rdr.GetInt32(0), rdr.GetString(1)));
        }

        return Ok(items);
    }
}
