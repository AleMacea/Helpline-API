using System.Data;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace Helpline.Api.Controllers;

[ApiController]
[Route("faq")]
public class FaqController : ControllerBase
{
    private readonly IConfiguration _cfg;

    public FaqController(IConfiguration cfg) => _cfg = cfg;

    // DTOs
    public record FaqListItem(Guid Id, string Title, string Category, string? Tags, DateTime LastUpdated);
    public record FaqDetail(Guid Id, string Title, string Category, string Content, string? Tags, DateTime LastUpdated);
    public record FaqCreateUpdateRequest(string Title, string Category, string Content, string? Tags);
    public record FaqFeedbackRequest(bool Helpful);

    // GET /faq?q=&category=&tag=
    [HttpGet]
    [Authorize(Roles = "User,Analyst,Admin")]
    public async Task<ActionResult<IEnumerable<FaqListItem>>> Get(
        [FromQuery] string? q,
        [FromQuery] string? category,
        [FromQuery] string? tag)
    {
        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        const string sql = @"
            SELECT Id, Title, Category, Tags, LastUpdated
            FROM dbo.Faq
            WHERE (@cat IS NULL OR Category = @cat)
              AND (
                    @q IS NULL OR
                    Title LIKE '%' + @q + '%' OR
                    Content LIKE '%' + @q + '%' OR
                    Tags LIKE '%' + @q + '%'
                  )
              AND (@tag IS NULL OR (Tags IS NOT NULL AND Tags LIKE '%' + @tag + '%'))
            ORDER BY LastUpdated DESC";

        await using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add(new SqlParameter("@q", SqlDbType.NVarChar, 200) { Value = (object?)q ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@cat", SqlDbType.NVarChar, 50) { Value = (object?)category ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@tag", SqlDbType.NVarChar, 100) { Value = (object?)tag ?? DBNull.Value });

        var list = new List<FaqListItem>();
        await using var rdr = await cmd.ExecuteReaderAsync();
        while (await rdr.ReadAsync())
        {
            list.Add(new FaqListItem(
                rdr.GetGuid(0),
                rdr.GetString(1),
                rdr.GetString(2),
                rdr.IsDBNull(3) ? null : rdr.GetString(3),
                rdr.GetDateTime(4)
            ));
        }

        return Ok(list);
    }

    // GET /faq/{id}
    [HttpGet("{id:guid}")]
    [Authorize(Roles = "User,Analyst,Admin")]
    public async Task<ActionResult<FaqDetail>> GetById(Guid id)
    {
        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        const string sql = @"
            SELECT Id, Title, Category, Content, Tags, LastUpdated
            FROM dbo.Faq
            WHERE Id = @Id";

        await using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = id });

        await using var rdr = await cmd.ExecuteReaderAsync();
        if (!await rdr.ReadAsync())
            return NotFound();

        var item = new FaqDetail(
            rdr.GetGuid(0),
            rdr.GetString(1),
            rdr.GetString(2),
            rdr.GetString(3),
            rdr.IsDBNull(4) ? null : rdr.GetString(4),
            rdr.GetDateTime(5)
        );

        return Ok(item);
    }

    // POST /faq (create) — Analyst/Admin
    [HttpPost]
    [Authorize(Roles = "Analyst,Admin")]
    public async Task<ActionResult<FaqDetail>> Create([FromBody] FaqCreateUpdateRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Title) || string.IsNullOrWhiteSpace(req.Category) || string.IsNullOrWhiteSpace(req.Content))
            return BadRequest("Title, Category e Content são obrigatórios.");

        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        var id = Guid.NewGuid();
        const string sql = @"
            INSERT INTO dbo.Faq (Id, Title, Category, Content, Tags)
            VALUES (@Id, @Title, @Category, @Content, @Tags);
            SELECT Id, Title, Category, Content, Tags, LastUpdated FROM dbo.Faq WHERE Id=@Id;";

        await using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = id });
        cmd.Parameters.Add(new SqlParameter("@Title", SqlDbType.NVarChar, 200) { Value = req.Title });
        cmd.Parameters.Add(new SqlParameter("@Category", SqlDbType.NVarChar, 50) { Value = req.Category });
        cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.NVarChar, -1) { Value = req.Content });
        cmd.Parameters.Add(new SqlParameter("@Tags", SqlDbType.NVarChar, 400) { Value = (object?)req.Tags ?? DBNull.Value });

        await using var rdr = await cmd.ExecuteReaderAsync();
        await rdr.ReadAsync();
        var created = new FaqDetail(
            rdr.GetGuid(0),
            rdr.GetString(1),
            rdr.GetString(2),
            rdr.GetString(3),
            rdr.IsDBNull(4) ? null : rdr.GetString(4),
            rdr.GetDateTime(5)
        );

        return CreatedAtAction(nameof(GetById), new { id = created.Id }, created);
    }

    // PUT /faq/{id} (update) — Analyst/Admin
    [HttpPut("{id:guid}")]
    [Authorize(Roles = "Analyst,Admin")]
    public async Task<ActionResult<FaqDetail>> Update(Guid id, [FromBody] FaqCreateUpdateRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Title) || string.IsNullOrWhiteSpace(req.Category) || string.IsNullOrWhiteSpace(req.Content))
            return BadRequest("Title, Category e Content são obrigatórios.");

        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        const string sql = @"
            UPDATE dbo.Faq
            SET Title=@Title, Category=@Category, Content=@Content, Tags=@Tags, LastUpdated=SYSUTCDATETIME()
            WHERE Id=@Id;

            SELECT Id, Title, Category, Content, Tags, LastUpdated FROM dbo.Faq WHERE Id=@Id;";

        await using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = id });
        cmd.Parameters.Add(new SqlParameter("@Title", SqlDbType.NVarChar, 200) { Value = req.Title });
        cmd.Parameters.Add(new SqlParameter("@Category", SqlDbType.NVarChar, 50) { Value = req.Category });
        cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.NVarChar, -1) { Value = req.Content });
        cmd.Parameters.Add(new SqlParameter("@Tags", SqlDbType.NVarChar, 400) { Value = (object?)req.Tags ?? DBNull.Value });

        await using var rdr = await cmd.ExecuteReaderAsync();
        if (!rdr.HasRows)
            return NotFound();

        await rdr.ReadAsync();
        var updated = new FaqDetail(
            rdr.GetGuid(0),
            rdr.GetString(1),
            rdr.GetString(2),
            rdr.GetString(3),
            rdr.IsDBNull(4) ? null : rdr.GetString(4),
            rdr.GetDateTime(5)
        );

        return Ok(updated);
    }

    // DELETE /faq/{id} — Analyst/Admin
    [HttpDelete("{id:guid}")]
    [Authorize(Roles = "Analyst,Admin")]
    public async Task<IActionResult> Delete(Guid id)
    {
        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        const string sql = @"DELETE FROM dbo.Faq WHERE Id=@Id;";
        await using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = id });

        var rows = await cmd.ExecuteNonQueryAsync();
        if (rows == 0)
            return NotFound();

        return NoContent();
    }

    // POST /faq/{id}/feedback — User/Analyst/Admin (upsert voto)
    [HttpPost("{id:guid}/feedback")]
    [Authorize(Roles = "User,Analyst,Admin")]
    public async Task<IActionResult> Feedback(Guid id, [FromBody] FaqFeedbackRequest req)
    {
        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        // Verifica FAQ
        var check = new SqlCommand("SELECT 1 FROM dbo.Faq WHERE Id=@Id", conn);
        check.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = id });
        var exists = (await check.ExecuteScalarAsync()) != null;
        if (!exists)
            return NotFound();

        // userId do token
        var userIdStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdStr, out var userId))
            return Unauthorized();

        // Upsert feedback
        const string upsert = @"
            MERGE dbo.FaqFeedback WITH (HOLDLOCK) AS t
            USING (SELECT @FaqId AS FaqId, @UserId AS UserId) AS s
            ON (t.FaqId = s.FaqId AND t.UserId = s.UserId)
            WHEN MATCHED THEN UPDATE SET Helpful=@Helpful, CreatedAt=SYSUTCDATETIME()
            WHEN NOT MATCHED THEN INSERT (FaqId, UserId, Helpful) VALUES (s.FaqId, s.UserId, @Helpful);";

        await using var cmd = new SqlCommand(upsert, conn);
        cmd.Parameters.Add(new SqlParameter("@FaqId", SqlDbType.UniqueIdentifier) { Value = id });
        cmd.Parameters.Add(new SqlParameter("@UserId", SqlDbType.UniqueIdentifier) { Value = userId });
        cmd.Parameters.Add(new SqlParameter("@Helpful", SqlDbType.Bit) { Value = req.Helpful });
        await cmd.ExecuteNonQueryAsync();

        return NoContent();
    }

    // GET /faq/popular — ranking por votos (helpful)
    [HttpGet("popular")]
    [Authorize(Roles = "User,Analyst,Admin")]
    public async Task<ActionResult<IEnumerable<object>>> Popular()
    {
        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        const string sql = @"
            SELECT TOP 10
                f.Id, f.Title, f.Category, f.Tags, f.LastUpdated,
                SUM(CASE WHEN fb.Helpful=1 THEN 1 ELSE 0 END) AS Helpful,
                SUM(CASE WHEN fb.Helpful=0 THEN 1 ELSE 0 END) AS NotHelpful
            FROM dbo.Faq f
            LEFT JOIN dbo.FaqFeedback fb ON fb.FaqId = f.Id
            GROUP BY f.Id, f.Title, f.Category, f.Tags, f.LastUpdated
            ORDER BY Helpful DESC, f.LastUpdated DESC";

        await using var cmd = new SqlCommand(sql, conn);
        var list = new List<object>();
        await using var rdr = await cmd.ExecuteReaderAsync();
        while (await rdr.ReadAsync())
        {
            list.Add(new
            {
                Id = rdr.GetGuid(0),
                Title = rdr.GetString(1),
                Category = rdr.GetString(2),
                Tags = rdr.IsDBNull(3) ? null : rdr.GetString(3),
                LastUpdated = rdr.GetDateTime(4),
                Helpful = rdr.IsDBNull(5) ? 0 : rdr.GetInt32(5),
                NotHelpful = rdr.IsDBNull(6) ? 0 : rdr.GetInt32(6)
            });
        }

        return Ok(list);
    }
}





