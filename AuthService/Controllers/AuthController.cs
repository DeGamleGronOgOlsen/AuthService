using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{

    private readonly ILogger<AuthController> _logger;

    private readonly IConfiguration _config;

    private readonly HttpClient _httpClient;

    public AuthController(ILogger<AuthController> logger, IConfiguration config, HttpClient httpClient)
{
    _config = config;
    _logger = logger;
    _httpClient = httpClient;
}

// Generer JWT token
private string GenerateJwtToken(string username, string? role)
{
    var secret = _config["Secret"];
    var issuer = _config["Issuer"];

    if (string.IsNullOrEmpty(secret))
    {
        _logger.LogError("Secret er ikke defineret i konfigurationen.");
        throw new ArgumentNullException(nameof(secret), "Secret er ikke defineret i konfigurationen.");
    }

    if (string.IsNullOrEmpty(issuer))
    {
        _logger.LogError("Issuer er ikke defineret i konfigurationen.");
        throw new ArgumentNullException(nameof(issuer), "Issuer er ikke defineret i konfigurationen.");
    }

    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, username)
    };

    if (!string.IsNullOrEmpty(role))
    {
        claims.Add(new Claim(ClaimTypes.Role, role));
    }

    var token = new JwtSecurityToken(
        issuer,
        audience: "http://localhost",
        claims,
        expires: DateTime.Now.AddMinutes(15),
        signingCredentials: credentials);

    return new JwtSecurityTokenHandler().WriteToken(token);
}

private async Task<(bool IsValid, string? Role, string? UserId)> ValidateUserAsync(string username, string password)
{
    var userServiceUrl = _config["UserServiceUrl"];

    try
    {
        var response = await _httpClient.PostAsJsonAsync($"{userServiceUrl}/user/validate", new { Username = username, Password = password });

        if (response.IsSuccessStatusCode)
        {
            var result = await response.Content.ReadFromJsonAsync<ValidateUserResponse>();
            string? role = result?.Role;
            string? userId = result?.UserId;
            _logger.LogInformation("User validated successfully via UserService with role: {Role} and userId: {UserId}", role, userId);
            return (true, role, userId);
        }

        _logger.LogWarning("User validation failed via UserService. Status code: {StatusCode}", response.StatusCode);
        return (false, null, null);
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Error while communicating with UserService.");
        return (false, null, null);
    }
}

[AllowAnonymous]
[HttpPost("login")]
public async Task<IActionResult> Login([FromBody] LoginModel login)
{
    var (isValid, role,userId) = await ValidateUserAsync(login.Username, login.Password);

    if (isValid)
    {
        var token = GenerateJwtToken(login.Username, role);
        return Ok(new { token, username = login.Username, userId });
    }

    return Unauthorized(new { message = "Invalid username or password" });
}

public class ValidateUserResponse
{
    public string? Role { get; set; }
    public string? UserId { get; set; }
}

}


