using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class TestController : ControllerBase
{

[Authorize]
[HttpGet]
public async Task<IActionResult> Get()
{
return Ok("You're authorized");
}

// Endepunkt kun for "admin"-rollen
    [Authorize(Roles = "admin")]
    [HttpGet("admin")]
    public async Task<IActionResult> GetAdmin()
    {
        return Ok("Welcome, admin!");
    }

}