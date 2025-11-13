using System.Data;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace Helpline.Api.Controllers;

[ApiController]
[Route("tickets")]
public class TicketsController : ControllerBase
{
    private readonly IConfiguration _cfg;
    public TicketsController(IConfiguration cfg) => _cfg = cfg;
    public record TicketCreateRequest(
        Guid RequesterId,
        string Title,
        string? Description,
        int CategoryId,
        int LevelId,
        int PriorityId,
        Guid? AssigneeId,
        int? InitialStatusId,
        string? Origin // novo
    );

    public record TicketCreateResponse(Guid TicketId, string Protocol);
    public record TicketUpdateRequest(int? StatusId, int? PriorityId, int? LevelId, Guid? AssigneeId);
    public record TicketMessageRequest(string SenderType, string Content, Guid? SenderUserId);

    // Qualquer autenticado: User, Analyst, Admin
    [Authorize(Roles = "User,Analyst,Admin")]
    [HttpPost]
    public async Task<ActionResult<TicketCreateResponse>> Create([FromBody] TicketCreateRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Title))
            return BadRequest("Title é obrigatório.");

        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        // Se vier vazio, default web; app mobile já envia 'mobile'
        var origin = string.IsNullOrWhiteSpace(req.Origin) ? "web" : req.Origin;

        await using var cmd = new SqlCommand("dbo.sp_Tickets_Create", conn)
        {
            CommandType = CommandType.StoredProcedure
        };

        cmd.Parameters.Add(new SqlParameter("@RequesterId", SqlDbType.UniqueIdentifier) { Value = req.RequesterId });
        cmd.Parameters.Add(new SqlParameter("@Title", SqlDbType.NVarChar, 255) { Value = req.Title });
        cmd.Parameters.Add(new SqlParameter("@Description", SqlDbType.NVarChar, -1) { Value = (object?)req.Description ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@CategoryId", SqlDbType.Int) { Value = req.CategoryId });
        cmd.Parameters.Add(new SqlParameter("@LevelId", SqlDbType.Int) { Value = req.LevelId });
        cmd.Parameters.Add(new SqlParameter("@PriorityId", SqlDbType.Int) { Value = req.PriorityId });
        cmd.Parameters.Add(new SqlParameter("@AssigneeId", SqlDbType.UniqueIdentifier) { Value = (object?)req.AssigneeId ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@InitialStatusId", SqlDbType.Int) { Value = (object?)req.InitialStatusId ?? DBNull.Value });
        // novo parâmetro — ajuste sua SP para aceitar @Origin NVARCHAR(16) = 'web'
        cmd.Parameters.Add(new SqlParameter("@Origin", SqlDbType.NVarChar, 16) { Value = origin });

        await using var rdr = await cmd.ExecuteReaderAsync();
        if (!await rdr.ReadAsync())
            return StatusCode(500, "A procedure não retornou dados.");

        var ticketId = rdr.GetGuid(rdr.GetOrdinal("TicketId"));
        var protocol = rdr.GetString(rdr.GetOrdinal("Protocol"));

        return CreatedAtAction(nameof(GetById), new { id = ticketId }, new TicketCreateResponse(ticketId, protocol));
    }

    // Qualquer autenticado: User, Analyst, Admin
    // User só pode ver chamado do qual é solicitante; Analyst/Admin podem ver qualquer um
    [Authorize(Roles = "User,Analyst,Admin")]
    [HttpGet("{id:guid}")]
    public async Task<ActionResult<object>> GetById(Guid id)
    {
        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        const string sql = @"SELECT t.Id, t.Protocol, t.Title, t.Description, t.CreatedAt,
t.CategoryId, t.LevelId, t.PriorityId, t.StatusId,
t.RequesterId, t.AssigneeId, t.Origin
FROM dbo.Ticket t
WHERE t.Id = @Id";
        await using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = id });

        await using var rdr = await cmd.ExecuteReaderAsync();
        if (!await rdr.ReadAsync())
            return NotFound();

        var requesterId = rdr.GetGuid(9);
        var isPower = User.IsInRole("Analyst") || User.IsInRole("Admin");
        if (!isPower)
        {
            var selfStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(selfStr, out var selfId) || selfId != requesterId)
                return Forbid();
        }

        var result = new
        {
            Id = rdr.GetGuid(0),
            Protocol = rdr.GetString(1),
            Title = rdr.GetString(2),
            Description = rdr.IsDBNull(3) ? null : rdr.GetString(3),
            CreatedAt = rdr.GetDateTime(4),
            CategoryId = rdr.GetInt32(5),
            LevelId = rdr.GetInt32(6),
            PriorityId = rdr.GetInt32(7),
            StatusId = rdr.GetInt32(8),
            RequesterId = requesterId,
            AssigneeId = rdr.IsDBNull(10) ? (Guid?)null : rdr.GetGuid(10),
            Origin = rdr.GetString(11)
        };

        return Ok(result);
    }

    // Somente Analyst/Admin
    [Authorize(Roles = "Analyst,Admin")]
    [HttpPatch("{id:guid}")]
    public async Task<ActionResult<object>> Update(Guid id, [FromBody] TicketUpdateRequest req)
    {
        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        const string sql = @"UPDATE dbo.Ticket
SET
StatusId = COALESCE(@StatusId, StatusId),
PriorityId = COALESCE(@PriorityId, PriorityId),
LevelId = COALESCE(@LevelId, LevelId),
AssigneeId = @AssigneeId,
UpdatedAt = SYSUTCDATETIME()
WHERE Id = @Id;

SELECT t.Id, t.Protocol, t.Title, t.Description, t.CreatedAt, t.UpdatedAt,
t.CategoryId, t.LevelId, t.PriorityId, t.StatusId, t.RequesterId, t.AssigneeId, t.Origin
FROM dbo.Ticket t
WHERE t.Id = @Id;";
        await using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = id });
        cmd.Parameters.Add(new SqlParameter("@StatusId", SqlDbType.Int) { Value = (object?)req.StatusId ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@PriorityId", SqlDbType.Int) { Value = (object?)req.PriorityId ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@LevelId", SqlDbType.Int) { Value = (object?)req.LevelId ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@AssigneeId", SqlDbType.UniqueIdentifier) { Value = (object?)req.AssigneeId ?? DBNull.Value });

        await using var rdr = await cmd.ExecuteReaderAsync();
        if (!rdr.HasRows)
            return NotFound();

        await rdr.ReadAsync();
        var result = new
        {
            Id = rdr.GetGuid(0),
            Protocol = rdr.GetString(1),
            Title = rdr.GetString(2),
            Description = rdr.IsDBNull(3) ? null : rdr.GetString(3),
            CreatedAt = rdr.GetDateTime(4),
            UpdatedAt = rdr.GetDateTime(5),
            CategoryId = rdr.GetInt32(6),
            LevelId = rdr.GetInt32(7),
            PriorityId = rdr.GetInt32(8),
            StatusId = rdr.GetInt32(9),
            RequesterId = rdr.GetGuid(10),
            AssigneeId = rdr.IsDBNull(11) ? (Guid?)null : rdr.GetGuid(11),
            Origin = rdr.GetString(12)
        };

        return Ok(result);
    }

    // Somente Analyst/Admin - lista geral (agora com filtro por origin)
    [Authorize(Roles = "Analyst,Admin")]
    [HttpGet]
    public async Task<ActionResult<object>> List(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        [FromQuery] string? status = null,
        [FromQuery] string? categoria = null,
        [FromQuery] string? nivel = null,
        [FromQuery] string? search = null,
        [FromQuery] string? origin = null)
    {
        if (page < 1) page = 1;
        if (pageSize < 1) pageSize = 20;
        if (pageSize > 100) pageSize = 100;

        var skip = (page - 1) * pageSize;
        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        const string sql = @"IF OBJECT_ID('tempdb..#base') IS NOT NULL DROP TABLE #base;
SELECT
t.Id, t.Protocol, t.Title, t.Description, t.CreatedAt,
s.Name AS Status,
c.Name AS Categoria,
l.Name AS Nivel,
p.Name AS Prioridade,
t.Origin
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
AND (@search IS NULL OR (t.Title LIKE '%' + @search + '%' OR t.Protocol LIKE '%' + @search + '%'));

SELECT COUNT(*) AS Total FROM #base;

SELECT *
FROM #base
ORDER BY CreatedAt DESC
OFFSET @skip ROWS FETCH NEXT @take ROWS ONLY;";
        await using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add(new SqlParameter("@status", SqlDbType.NVarChar, 50) { Value = (object?)status ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@categoria", SqlDbType.NVarChar, 80) { Value = (object?)categoria ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@nivel", SqlDbType.NVarChar, 10) { Value = (object?)nivel ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@origin", SqlDbType.NVarChar, 16) { Value = (object?)origin ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@search", SqlDbType.NVarChar, 255) { Value = (object?)search ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@skip", SqlDbType.Int) { Value = skip });
        cmd.Parameters.Add(new SqlParameter("@take", SqlDbType.Int) { Value = pageSize });

        int total = 0;
        var items = new List<object>();

        await using (var rdr = await cmd.ExecuteReaderAsync())
        {
            if (await rdr.ReadAsync())
                total = rdr.GetInt32(0);

            if (await rdr.NextResultAsync())
            {
                while (await rdr.ReadAsync())
                {
                    items.Add(new
                    {
                        Id = rdr.GetGuid(0),
                        Protocol = rdr.GetString(1),
                        Title = rdr.GetString(2),
                        Description = rdr.IsDBNull(3) ? null : rdr.GetString(3),
                        CreatedAt = rdr.GetDateTime(4),
                        Status = rdr.GetString(5),
                        Categoria = rdr.GetString(6),
                        Nivel = rdr.GetString(7),
                        Prioridade = rdr.GetString(8),
                        Origin = rdr.GetString(9)
                    });
                }
            }
        }

        return Ok(new { total, page, pageSize, items });
    }

    // Novo: lista apenas os chamados do usuário logado (qualquer autenticado)
    [Authorize(Roles = "User,Analyst,Admin")]
    [HttpGet("mine")]
    public async Task<ActionResult<object>> ListMine(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        [FromQuery] string? status = null,
        [FromQuery] string? categoria = null,
        [FromQuery] string? nivel = null,
        [FromQuery] string? search = null)
    {
        if (page < 1) page = 1;
        if (pageSize < 1) pageSize = 20;
        if (pageSize > 100) pageSize = 100;

        var skip = (page - 1) * pageSize;
        var userIdStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdStr, out var userId))
            return Unauthorized();

        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        const string sql = @"IF OBJECT_ID('tempdb..#base') IS NOT NULL DROP TABLE #base;
SELECT
t.Id, t.Protocol, t.Title, t.Description, t.CreatedAt,
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
WHERE t.RequesterId = @userId
AND (@status IS NULL OR s.Name = @status)
AND (@categoria IS NULL OR c.Name = @categoria)
AND (@nivel IS NULL OR l.Name = @nivel)
AND (@search IS NULL OR (t.Title LIKE '%' + @search + '%' OR t.Protocol LIKE '%' + @search + '%'));

SELECT COUNT(*) AS Total FROM #base;

SELECT *
FROM #base
ORDER BY CreatedAt DESC
OFFSET @skip ROWS FETCH NEXT @take ROWS ONLY;";
        await using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add(new SqlParameter("@userId", SqlDbType.UniqueIdentifier) { Value = userId });
        cmd.Parameters.Add(new SqlParameter("@status", SqlDbType.NVarChar, 50) { Value = (object?)status ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@categoria", SqlDbType.NVarChar, 80) { Value = (object?)categoria ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@nivel", SqlDbType.NVarChar, 10) { Value = (object?)nivel ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@search", SqlDbType.NVarChar, 255) { Value = (object?)search ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@skip", SqlDbType.Int) { Value = skip });
        cmd.Parameters.Add(new SqlParameter("@take", SqlDbType.Int) { Value = pageSize });

        int total = 0;
        var items = new List<object>();

        await using (var rdr = await cmd.ExecuteReaderAsync())
        {
            if (await rdr.ReadAsync())
                total = rdr.GetInt32(0);

            if (await rdr.NextResultAsync())
            {
                while (await rdr.ReadAsync())
                {
                    items.Add(new
                    {
                        Id = rdr.GetGuid(0),
                        Protocol = rdr.GetString(1),
                        Title = rdr.GetString(2),
                        Description = rdr.IsDBNull(3) ? null : rdr.GetString(3),
                        CreatedAt = rdr.GetDateTime(4),
                        Status = rdr.GetString(5),
                        Categoria = rdr.GetString(6),
                        Nivel = rdr.GetString(7),
                        Prioridade = rdr.GetString(8)
                    });
                }
            }
        }

        return Ok(new { total, page, pageSize, items });
    }

    // Somente Analyst/Admin
    [Authorize(Roles = "Analyst,Admin")]
    [HttpPost("{id:guid}/messages")]
    public async Task<ActionResult<object>> AddMessage(Guid id, [FromBody] TicketMessageRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.SenderType) || string.IsNullOrWhiteSpace(req.Content))
            return BadRequest("SenderType e Content são obrigatórios.");

        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        await using var cmd = new SqlCommand("dbo.sp_TicketMessages_Add", conn)
        {
            CommandType = CommandType.StoredProcedure
        };

        cmd.Parameters.Add(new SqlParameter("@TicketId", SqlDbType.UniqueIdentifier) { Value = id });
        cmd.Parameters.Add(new SqlParameter("@SenderType", SqlDbType.NVarChar, 16) { Value = req.SenderType });
        cmd.Parameters.Add(new SqlParameter("@SenderUserId", SqlDbType.UniqueIdentifier) { Value = (object?)req.SenderUserId ?? DBNull.Value });
        cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.NVarChar, -1) { Value = req.Content });

        long messageId = 0;
        await using (var rdr = await cmd.ExecuteReaderAsync())
        {
            if (await rdr.ReadAsync())
                messageId = Convert.ToInt64(rdr["MessageId"]);
        }

        return Ok(new { messageId });
    }

    // Novo: obter mensagens do chamado (User só pode ver se for o solicitante)
    [Authorize(Roles = "User,Analyst,Admin")]
    [HttpGet("{id:guid}/messages")]
    public async Task<ActionResult<object>> GetMessages(Guid id)
    {
        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        // primeiro, checar propriedade para usuários comuns
        var isPower = User.IsInRole("Analyst") || User.IsInRole("Admin");
        if (!isPower)
        {
            var selfStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(selfStr, out var selfId)) return Unauthorized();

            const string checkSql = @"SELECT RequesterId FROM dbo.Ticket WHERE Id=@Id";
            await using (var chk = new SqlCommand(checkSql, conn))
            {
                chk.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = id });
                var reqObj = await chk.ExecuteScalarAsync();
                if (reqObj == null) return NotFound();
                var requesterId = (Guid)reqObj;
                if (requesterId != selfId) return Forbid();
            }
        }

        const string sql = @"SELECT Id, TicketId, SenderType, SenderUserId, Content, CreatedAt
FROM dbo.TicketMessage
WHERE TicketId = @Id
ORDER BY CreatedAt ASC";
        var items = new List<object>();
        await using (var cmd = new SqlCommand(sql, conn))
        {
            cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = id });
            await using var rdr = await cmd.ExecuteReaderAsync();
            while (await rdr.ReadAsync())
            {
                items.Add(new
                {
                    Id = rdr.GetInt64(0),
                    TicketId = rdr.GetGuid(1),
                    SenderType = rdr.GetString(2),
                    SenderUserId = rdr.IsDBNull(3) ? (Guid?)null : rdr.GetGuid(3),
                    Content = rdr.GetString(4),
                    CreatedAt = rdr.GetDateTime(5)
                });
            }
        }

        return Ok(items);
    }
}




