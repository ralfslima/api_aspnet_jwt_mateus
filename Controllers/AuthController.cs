using JwtAuthApi.Models;
using JwtAuthApi.Services;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthApi.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly TokenService _tokenService;

    public AuthController(TokenService tokenService)
    {
        _tokenService = tokenService;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] UserModel user)
    {
        // Exemplo fixo de usuário
        if (user.Username == "admin" && user.Password == "123456")
        {
            var token = _tokenService.GenerateToken(user.Username);
            return Ok(new { token });
        }

        return Unauthorized("Usuário ou senha inválidos");
    }
}
