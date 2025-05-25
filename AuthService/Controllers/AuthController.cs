using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthService.Models;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly IConfiguration _config;
    private readonly HttpClient _httpClient;
    private readonly string _serviceIp;

    public AuthController(ILogger<AuthController> logger, IConfiguration config, HttpClient httpClient)
    {
        _logger = logger;
        _config = config;
        _httpClient = httpClient;

        // Get and log the service IP address
        var hostName = System.Net.Dns.GetHostName();
        var ips = System.Net.Dns.GetHostAddresses(hostName);
        _serviceIp = ips.First().MapToIPv4().ToString();
        _logger.LogInformation("Auth Service responding from {ServiceIp}", _serviceIp);
    }

    // Generate JWT token
    private string GenerateJwtToken(string username, string? role)
    {
        var secret = _config["Secret"];
        var issuer = _config["Issuer"];

        if (string.IsNullOrEmpty(secret))
        {
            _logger.LogError("Secret is not defined in configuration.");
            throw new ArgumentNullException(nameof(secret), "Secret is not defined in configuration.");
        }

        if (string.IsNullOrEmpty(issuer))
        {
            _logger.LogError("Issuer is not defined in configuration.");
            throw new ArgumentNullException(nameof(issuer), "Issuer is not defined in configuration.");
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

        _logger.LogInformation("JWT token generated for user {Username} with role {Role}", username, role);

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
        _logger.LogInformation("Login attempt for user {Username} from {ServiceIp}", login.Username, _serviceIp);

        var (isValid, role, userId) = await ValidateUserAsync(login.Username, login.Password);

        if (isValid)
        {
            var token = GenerateJwtToken(login.Username, role);
            _logger.LogInformation("Login successful for user {Username}", login.Username);
            return Ok(new { token, username = login.Username, userId });
        }

        _logger.LogWarning("Login failed for user {Username}", login.Username);
        return Unauthorized(new { message = "Invalid username or password" });
    }

    public class ValidateUserResponse
    {
        public string? Role { get; set; }
        public string? UserId { get; set; }
    }
}