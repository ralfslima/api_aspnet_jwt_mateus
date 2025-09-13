# 🔐 ASP.NET Core 9 API - JWT Authentication

Este projeto demonstra como criar uma API simples com **ASP.NET Core 9** que:

- Autentica um usuário com login fixo
- Gera um token JWT
- Protege endpoints com autenticação
- É testável diretamente no **Thunder Client** (extensão do VSCode)

---

## ✅ Pré-requisitos

- [.NET 9 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/9.0)
- VSCode com:
  - Extensão C#
  - Extensão Thunder Client
- Terminal (VSCode, PowerShell ou Terminal do sistema)

---

## 1. Criando o Projeto

```bash
dotnet new webapi -n JwtAuthApi
```

---

## 2. Adicionar pacote responsável pelo JWT

```
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
```

---

## 3. Estrutura de Pastas e Arquivos

```
JwtAuthApi/
├── Controllers/
│   ├── AuthController.cs
│   └── ProtectedController.cs
├── Models/
│   └── UserModel.cs
├── Services/
│   └── TokenService.cs
├── appsettings.json
└── Program.cs
```

---

## 4. Configurar appsettings.json

```
"JwtSettings": {
  "SecretKey": "minha-chave-super-secreta-de-32caracteres!!",
  "Issuer": "JwtAuthApi",
  "Audience": "JwtAuthApiUser"
}
```

---

## 5. Criar Modelo de Usuário (Models/UserModel.cs)
```
namespace JwtAuthApi.Models;

public class UserModel
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}
```

---

## 6. Criar Serviço do Token (Services/TokenService.cs)
```
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuthApi.Services;

public class TokenService
{
    private readonly IConfiguration _configuration;

    public TokenService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public string GenerateToken(string username)
    {
        var jwtSettings = _configuration.GetSection("JwtSettings");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: jwtSettings["Issuer"],
            audience: jwtSettings["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddHours(2),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
```

---

## 7. Criar AuthController (Controllers/AuthController.cs)

```
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
        if (user.Username == "admin" && user.Password == "123456")
        {
            var token = _tokenService.GenerateToken(user.Username);
            return Ok(new { token });
        }

        return Unauthorized("Usuário ou senha inválidos");
    }
}
```

---

## 8. Criar Endpoint Protegido (Controllers/ProtectedController.cs)

```
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
```

---

## 9. Configurar o Program.cs

```
using System.Text;
using JwtAuthApi.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// 🔧 Registro do serviço de geração de token (injeção de dependência)
builder.Services.AddSingleton<TokenService>();

// 🧱 Adiciona os serviços de controladores (Controllers da API)
builder.Services.AddControllers();

// 🔐 Lê as configurações do JWT definidas no appsettings.json
var jwtSettings = builder.Configuration.GetSection("JwtSettings");

// 🔐 Converte a chave secreta (string) em bytes para uso com HMAC
var secretKey = Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]!);

// 🔐 Configura a autenticação JWT
builder.Services.AddAuthentication(options =>
{
    // Define o esquema padrão de autenticação como "Bearer"
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    // ⚠️ Apenas para desenvolvimento: não exige HTTPS (não recomendado em produção)
    options.RequireHttpsMetadata = false;

    // Salva o token no contexto da requisição
    options.SaveToken = true;

    // 🛡️ Define os parâmetros de validação do token JWT
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,            // Valida o emissor (Issuer)
        ValidateAudience = true,          // Valida o público (Audience)
        ValidateLifetime = true,          // Valida a expiração do token
        ValidateIssuerSigningKey = true,  // Valida a assinatura do token

        // Valores que serão comparados com os do token
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(secretKey)
    };
});

// 🚀 Cria a aplicação (pipeline configurado)
var app = builder.Build();

// ⛔ Ativa o middleware de autenticação (verifica token JWT)
app.UseAuthentication();

// ✅ Ativa o middleware de autorização (verifica permissões/políticas)
app.UseAuthorization();

// 🚪 Mapeia os controllers (rotas como /auth/login, /protected/secret)
app.MapControllers();

// ▶️ Inicia a aplicação
app.Run();
```

---

## 10. Executar aplicação
```
dotnet run
```