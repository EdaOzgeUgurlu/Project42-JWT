# Pratik - JWT 🛠️

Aşağıdaki adımları takip ederek bir JWT (JSON Web Token) kimlik doğrulama sistemi oluşturun. 💻🔑

## 1. Kullanıcı Modeli Oluşturma 👤

Bir **User** sınıfı oluşturun. Bu sınıf aşağıdaki özelliklere sahip olmalıdır:

- **Id** (int, anahtar) 💡
- **Email** (string, benzersiz) 📧
- **Password** (string) 🔒

### Örnek:
```csharp
public class User
{
    public int Id { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }
}
```

## 2. Veritabanı Ayarları 🗄️

Entity Framework kullanarak bir **DbContext** sınıfı oluşturun ve **User** modelini bu sınıfa ekleyin. 

### Örnek:
```csharp
public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users { get; set; }
}
```

## 3. JWT Oluşturma 🧑‍💻

Aşağıdaki işlemleri gerçekleştirin:

- Bir **AuthController** sınıfı oluşturun. 
- Kullanıcının kimliğini doğrulamak için bir **Login** metodu yazın. Bu metot, **Email** ve **Password** almalı ve geçerli bir kullanıcı ise JWT oluşturmalıdır.
- Oluşturulan JWT, kullanıcıya döndürülmelidir.

### Örnek:
```csharp
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;

    public AuthController(AppDbContext context)
    {
        _context = context;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var user = _context.Users.FirstOrDefault(u => u.Email == request.Email && u.Password == request.Password);

        if (user == null)
        {
            return Unauthorized("Invalid credentials");
        }

        var token = GenerateJwtToken(user);
        return Ok(new { Token = token });
    }

    private string GenerateJwtToken(User user)
    {
        // JWT oluşturma işlemi (Örnek bir token kodu)
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes("your_secret_key");
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Email)
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
```

## 4. JWT Doğrulama ✅

JWT’nin her istekte doğrulanabilmesi için gerekli ayarları yapın. İsteklerde JWT doğrulaması yapmak üzere bir **Authorize** niteliği kullanın.

### Örnek:
```csharp
[Authorize]
[ApiController]
[Route("api/[controller]")]
public class ProtectedController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok("This is a protected resource.");
    }
}
```

### **Önemli Adımlar:**
- `AddAuthentication()` ve `AddJwtBearer()` metodları ile JWT doğrulama ayarlarını `Startup.cs` içinde yapılandırmayı unutmayın. ⚙️
- JWT token'ını her istekte `Authorization` başlığı ile göndermeyi unutmayın! 📬

---
