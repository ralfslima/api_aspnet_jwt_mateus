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
