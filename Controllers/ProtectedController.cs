using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthApi.Controllers;

[ApiController]
[Route("[controller]")]
public class ProtectedController : ControllerBase
{
    [Authorize]
    [HttpGet("secret")]
    public IActionResult GetSecret()
    {
        var username = User.Identity?.Name ?? "usuário";
        return Ok($"Você acessou um recurso protegido, {username}!");
    }
}
