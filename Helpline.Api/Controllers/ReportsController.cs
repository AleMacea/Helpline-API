using System.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace Helpline.Api.Controllers;

[ApiController]
[Route("reports")]
[Authorize(Roles = "Analyst,Admin")]
public class ReportsController : ControllerBase
{
    private readonly IConfiguration _cfg;

    public ReportsController(IConfiguration cfg) => _cfg = cfg;

    public record ReportRow(string Dia, string Status, string Categoria, string Nivel, string Prioridade, int Qtde);

    [HttpGet]
    public async Task<ActionResult<IEnumerable<ReportRow>>> Get(
        [FromQuery] string? from = null,
        [FromQuery] string? to = null,
        [FromQuery] string? status = null,
        [FromQuery] string? categoria = null,
        [FromQuery] string? nivel = null,
        [FromQuery] string? origin = null)
    {
        DateTime? fromDate = null, toDate = null;
        if (DateTime.TryParse(from, out var fd)) fromDate = fd.Date;
        if (DateTime.TryParse(to, out var td)) toDate = td.Date;

        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        const string sql = @"
            IF OBJECT_ID('tempdb..#base') IS NOT NULL DROP TABLE #base;

            SELECT
                CAST(t.CreatedAt AS date) AS Dia,
                s.Name AS Status,
                c.Name AS Categoria,
                l.Name AS Nivel,
                p.Name AS Prioridade
            INTO #base
            FROM dbo.Ticket t
            JOIN dbo.TicketStatus s ON s.Id = t.StatusId
            JOIN dbo.TicketCategory c ON c.Id = t.CategoryId
            JOIN dbo.TicketLevel l ON l.Id = t.LevelId
            JOIN dbo.TicketPriority p ON p.Id = t.PriorityId
            WHERE (@status IS NULL OR s.Name = @status)
              AND (@categoria IS NULL OR c.Name = @categoria)
              AND (@nivel IS NULL OR l.Name = @nivel)
              AND (@origin IS NULL OR t.Origin = @origin)
              AND (@from IS NULL OR t.CreatedAt >= @from)
              AND (@to IS NULL OR t.CreatedAt < DATEADD(day, 1, @to));

            SELECT
                CONVERT(varchar(10), Dia, 23) AS Dia,
                Status,
                Categoria,
                Nivel,
                Prioridade,
                COUNT(*) AS Qtde
            FROM #base
            GROUP BY Dia, Status, Categoria, Nivel, Prioridade
            ORDER BY Dia DESC, Qtde DESC;
        ";

        await using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add(new SqlParameter("@status", SqlDbType.NVarChar, 50) { Value = (object?)status ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@categoria", SqlDbType.NVarChar, 80) { Value = (object?)categoria ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@nivel", SqlDbType.NVarChar, 10) { Value = (object?)nivel ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@origin", SqlDbType.NVarChar, 16) { Value = (object?)origin ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@from", SqlDbType.DateTime2) { Value = (object?)fromDate ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@to", SqlDbType.DateTime2) { Value = (object?)toDate ?? DBNull.Value });

        var items = new List<ReportRow>();
        await using (var rdr = await cmd.ExecuteReaderAsync())
        {
            while (await rdr.ReadAsync())
            {
                items.Add(new ReportRow(
                    rdr.GetString(0),
                    rdr.GetString(1),
                    rdr.GetString(2),
                    rdr.GetString(3),
                    rdr.GetString(4),
                    rdr.GetInt32(5)
                ));
            }
        }

        return Ok(items);
    }
}
