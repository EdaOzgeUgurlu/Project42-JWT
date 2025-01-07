using Microsoft.AspNetCore.Mvc;

namespace Project42_JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecureController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("This is a secure endpoint.");
        }
    }
}
