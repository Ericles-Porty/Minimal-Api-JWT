using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using MinimalApiAuth.Models;

public static class TokenService
{
    public static string GenerateToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler(); // tokenHandle faz a manipulação do token
        var key = Encoding.ASCII.GetBytes(Settings.Secret); // chave de criptografia
        var tokenDescriptor = new SecurityTokenDescriptor // descrição do token
        {
            Subject = new ClaimsIdentity(new Claim[]{ // identidade do token
                new Claim(ClaimTypes.Name, user.Name.ToString()), // claim é uma informação sobre o usuário
                new Claim(ClaimTypes.Role, user.Role.ToString())
            }),
            Expires = DateTime.UtcNow.AddHours(2), // tempo de expiração do token
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature) // criptografia do token
        };
        var token = tokenHandler.CreateToken(tokenDescriptor); // criação do token
        return tokenHandler.WriteToken(token); // retorna o token como string
    }
}