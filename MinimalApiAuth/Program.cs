using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MinimalApiAuth.Models;
using MinimalApiAuth.Repositories;

var key = Encoding.ASCII.GetBytes(Settings.Secret);


var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication(a =>
{
    a.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    a.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(jb =>
{
    jb.RequireHttpsMetadata = false;
    jb.SaveToken = true;
    jb.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false
    };
});

builder.Services.AddAuthorization(a =>
{
    a.AddPolicy("ListarUsuarios", p => p.RequireClaim(ClaimTypes.Role, "admin", "employee"));
    a.AddPolicy("ApagarUsuarios", p => p.RequireClaim(ClaimTypes.Role, "admin"));
    a.AddPolicy("Employee", p => p.RequireClaim(ClaimTypes.Role, "employee"));
    a.AddPolicy("Admin", p => p.RequireClaim(ClaimTypes.Role, "admin"));
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/login", ([FromBody] User user) =>
{
    var userDb = UserRepository.Get(user.Name, user.Password);
    if (userDb == null)
        return Results.NotFound("Usuário não encontrado");

    var token = TokenService.GenerateToken(userDb);
    userDb.Password = String.Empty;

    return Results.Ok(new { user = userDb, token = token });
}).AllowAnonymous();

app.MapGet("anonymous", () => Results.Ok("Anônimo")).AllowAnonymous();

app.MapGet("employee", (ClaimsPrincipal cp) => Results.Ok(value: $"Autenticado - {cp.Identity!.Name} - {cp.Identity.AuthenticationType} - {cp.Identity.IsAuthenticated}")).RequireAuthorization("Employee");

app.MapGet("admin", (ClaimsPrincipal cp) => Results.Ok(value: $"Autenticado - {cp.Identity!.Name} ")).RequireAuthorization("Admin");

app.MapGet("users", (ClaimsPrincipal cp) => Results.Ok(value: $"Autenticado - {cp.Identity!.Name} pode listar todos usuários")).RequireAuthorization("ListarUsuarios");

app.MapGet("users/delete", (ClaimsPrincipal cp) => Results.Ok(value: $"Autenticado - {cp.Identity!.Name} pode apagar usuário")).RequireAuthorization("ApagarUsuarios");

app.Run();
