using Microsoft.AspNetCore.Mvc;
using System.Text;
using System;
using Project42_JWT.Model;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace Project42_JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;  // DbContext sınıfınız
        private readonly IConfiguration _configuration;

        public AuthController(AppDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        // Kullanıcı girişini yapan metot
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            // Kullanıcıyı email ve şifre ile doğrulama
            var user = _context.Users
                .FirstOrDefault(u => u.Email == model.Email && u.Password == model.Password);

            if (user == null)
            {
                // Kullanıcı bulunamadıysa 401 Unauthorized döndürülür
                return Unauthorized();
            }

            // JWT oluşturuluyor
            var token = GenerateJwtToken(user);

            // Oluşturulan token geri döndürülür
            return Ok(new { Token = token });
        }

        // JWT token oluşturma
        private string GenerateJwtToken(User user)
        {
            // Kullanıcıya ait claim (kimlik bilgileri)
            var claims = new[]
            {
                new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, user.Id.ToString()),
                new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Email, user.Email)
            };

            // JWT imzalama anahtarı
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:SecretKey"]));

            // JWT oluşturma için gerekli imzalama parametreleri
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // JWT oluşturuluyor
            var token = new JwtSecurityToken(
                _configuration["JwtSettings:Issuer"],
                _configuration["JwtSettings:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(_configuration["JwtSettings:ExpirationMinutes"])),
                signingCredentials: credentials
            );

            // Token string olarak döndürülür
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
