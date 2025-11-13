using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace Helpline.Api.Controllers;

[ApiController]
[Route("health")]
public class HealthController : ControllerBase
{
    private readonly IConfiguration _cfg;
    public HealthController(IConfiguration cfg) => _cfg = cfg;
[HttpGet]
    public async Task<IActionResult> Get()
    {
        var cs = _cfg.GetConnectionString("DatabaseConnection");
        try
        {
            await using var conn = new SqlConnection(cs);
            await conn.OpenAsync();
            await using var cmd = new SqlCommand("SELECT SYSDATETIMEOFFSET()", conn);
            var serverTime = (DateTimeOffset)(await cmd.ExecuteScalarAsync() ?? DateTimeOffset.MinValue);
            return Ok(new { status = "ok", db = "online", serverTime });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { status = "error", db = "offline", message = ex.Message });
        }
    }
}