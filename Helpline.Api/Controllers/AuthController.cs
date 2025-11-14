using System.Data;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace Helpline.Api.Controllers;

[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _cfg;

    public AuthController(IConfiguration cfg) => _cfg = cfg;

    // DTOs
    public record RegisterRequest(string Name, string Email, string Password, string Department = "Geral", string Role = "User", string? InviteToken = null, string? Origin = null);
    public record LoginRequest(string Email, string Password);
    public record AuthResponse(string Token, Guid UserId, string Name, string Email, string[] Roles);

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthResponse>> Register([FromBody] RegisterRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Email) ||
            string.IsNullOrWhiteSpace(req.Password) ||
            string.IsNullOrWhiteSpace(req.Name))
        {
            return BadRequest("Nome, e-mail e senha são obrigatórios.");
        }

        // Validação de convite para Analista/Admin
        if ((req.Role.Equals("Analyst", StringComparison.OrdinalIgnoreCase) ||
             req.Role.Equals("Admin", StringComparison.OrdinalIgnoreCase)) &&
            req.InviteToken != "SUPORTE4280")
        {
            return BadRequest("Convite inválido para a função solicitada.");
        }

        var origin = string.IsNullOrWhiteSpace(req.Origin) ? "mobile" : req.Origin;
        var department = string.IsNullOrWhiteSpace(req.Department) ? "Geral" : req.Department;

        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        // Verifica se e-mail já existe
        var checkCmd = new SqlCommand("SELECT COUNT(1) FROM dbo.Users WHERE Email=@Email", conn);
        checkCmd.Parameters.Add(new SqlParameter("@Email", SqlDbType.NVarChar, 255) { Value = req.Email });
        var exists = Convert.ToInt32(await checkCmd.ExecuteScalarAsync()) > 0;
        if (exists)
            return Conflict("E-mail já cadastrado.");

        // Gera salt + hash (PBKDF2 HMACSHA256)
        var salt = RandomNumberGenerator.GetBytes(32);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(req.Password),
            salt,
            100_000,
            HashAlgorithmName.SHA256,
            32);

        // Insere usuário com Origin
        var userId = Guid.NewGuid();
        var insertUser = new SqlCommand(@"
            INSERT INTO dbo.Users(Id, Name, Email, PasswordHash, PasswordSalt, Origin, Department)          VALUES(@Id, @Name, @Email, @Hash, @Salt, @Origin, @Department);", conn);
        insertUser.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = userId });
        insertUser.Parameters.Add(new SqlParameter("@Name", SqlDbType.NVarChar, 120) { Value = req.Name });
        insertUser.Parameters.Add(new SqlParameter("@Email", SqlDbType.NVarChar, 255) { Value = req.Email });
        insertUser.Parameters.Add(new SqlParameter("@Hash", SqlDbType.VarBinary, 64) { Value = hash });
        insertUser.Parameters.Add(new SqlParameter("@Salt", SqlDbType.VarBinary, 64) { Value = salt });
        insertUser.Parameters.Add(new SqlParameter("@Origin", SqlDbType.NVarChar, 16) { Value = origin });
        insertUser.Parameters.Add(new SqlParameter("@Department", SqlDbType.NVarChar, 100) { Value = department });



        await insertUser.ExecuteNonQueryAsync();

        // Vincula Role
        var roleName = req.Role switch
        {
            var r when r.Equals("Admin", StringComparison.OrdinalIgnoreCase) => "Admin",
            var r when r.Equals("Analyst", StringComparison.OrdinalIgnoreCase) => "Analyst",
            _ => "User"
        };

        var roleIdCmd = new SqlCommand("SELECT Id FROM dbo.Role WHERE Name=@Name", conn);
        roleIdCmd.Parameters.Add(new SqlParameter("@Name", SqlDbType.NVarChar, 50) { Value = roleName });
        var roleIdObj = await roleIdCmd.ExecuteScalarAsync();
        if (roleIdObj == null || roleIdObj is DBNull)
            return StatusCode(500, "Role não encontrada.");
        var roleId = Convert.ToInt32(roleIdObj);

        var linkRole = new SqlCommand("INSERT INTO dbo.UserRole(UserId, RoleId) VALUES(@U,@R)", conn);
        linkRole.Parameters.Add(new SqlParameter("@U", SqlDbType.UniqueIdentifier) { Value = userId });
        linkRole.Parameters.Add(new SqlParameter("@R", SqlDbType.Int) { Value = roleId });
        await linkRole.ExecuteNonQueryAsync();

        // Gera JWT
        var token = GenerateJwt(userId, req.Name, req.Email, new[] { roleName });
        return Created("", new AuthResponse(token, userId, req.Name, req.Email, new[] { roleName }));
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest req)
    {
        if (req is null ||
            string.IsNullOrWhiteSpace(req.Email) ||
            string.IsNullOrWhiteSpace(req.Password))
        {
            return BadRequest("E-mail e senha são obrigatórios.");
        }

        var cs = _cfg.GetConnectionString("DatabaseConnection");
        await using var conn = new SqlConnection(cs);
        await conn.OpenAsync();

        // Busca user
        var getUser = new SqlCommand(@"
            SELECT TOP 1 Id, Name, Email, PasswordHash, PasswordSalt
            FROM dbo.Users WHERE Email=@Email", conn);
        getUser.Parameters.Add(new SqlParameter("@Email", SqlDbType.NVarChar, 255) { Value = req.Email });

        Guid userId;
        string name, email;
        byte[] hash, salt;

        await using (var rdr = await getUser.ExecuteReaderAsync())
        {
            if (!await rdr.ReadAsync())
                return Unauthorized("E-mail ou senha inválidos.");

            userId = rdr.GetGuid(0);
            name = rdr.GetString(1);
            email = rdr.GetString(2);
            hash = (byte[])rdr.GetValue(3);
            salt = (byte[])rdr.GetValue(4);
        }

        // Verifica senha
        var checkHash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(req.Password),
            salt,
            100_000,
            HashAlgorithmName.SHA256,
            32);

        if (!CryptographicOperations.FixedTimeEquals(checkHash, hash))
            return Unauthorized("E-mail ou senha inválidos.");

        // Carrega roles
        var roles = new List<string>();
        var getRoles = new SqlCommand(@"
            SELECT r.Name
            FROM dbo.UserRole ur
            JOIN dbo.Role r ON r.Id = ur.RoleId
            WHERE ur.UserId=@U", conn);
        getRoles.Parameters.Add(new SqlParameter("@U", SqlDbType.UniqueIdentifier) { Value = userId });

        await using (var rdr = await getRoles.ExecuteReaderAsync())
        {
            while (await rdr.ReadAsync())
                roles.Add(rdr.GetString(0));
        }

        var token = GenerateJwt(userId, name, email, roles.ToArray());
        return Ok(new AuthResponse(token, userId, name, email, roles.ToArray()));
    }

    [HttpGet("me")]
    [Authorize]
    public ActionResult<object> Me()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var name = User.FindFirstValue(ClaimTypes.Name);
        var email = User.FindFirstValue(ClaimTypes.Email);
        var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();
        return Ok(new { userId, name, email, roles });
    }

    // Util: gerar JWT
    private string GenerateJwt(Guid userId, string name, string email, string[] roles)
    {
        var jwt = _cfg.GetSection("Jwt");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt["Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId.ToString()),
            new(ClaimTypes.Name, name),
            new(ClaimTypes.Email, email)
        };
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

        var token = new JwtSecurityToken(
            issuer: jwt["Issuer"],
            audience: jwt["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddHours(8),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}


