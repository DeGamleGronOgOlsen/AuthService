using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Net.Http;
using System.Net.Http.Json;
using AuthService.Models; // Add this using statement

// Assuming LoginModel is defined. If not, you'll need its definition.
// It might look like:
// public class LoginModel { public string Username { get; set; } public string Password { get; set; } }

namespace AuthService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly ILogger<AuthController> _logger;
        private readonly IConfiguration _config;
        private readonly HttpClient _httpClient; // General HttpClient from DI

        public AuthController(ILogger<AuthController> logger, IConfiguration config, HttpClient httpClient)
        {
            _config = config;
            _logger = logger;
            _httpClient = httpClient;
        }

        private string GenerateJwtToken(string username, string? role)
        {
            var secret = _config["JwtSettings:Secret"]; // Key used in Program.cs
            var issuer = _config["JwtSettings:Issuer"]; // Key used in Program.cs
            var audience = _config["JwtSettings:Audience"]; // Key used in Program.cs

            if (string.IsNullOrEmpty(secret))
            {
                _logger.LogError("AuthService: JWT Secret ('JwtSettings:Secret') is not defined in configuration for token generation.");
                throw new InvalidOperationException("JWT Secret is not configured for token generation.");
            }
            if (string.IsNullOrEmpty(issuer))
            {
                _logger.LogError("AuthService: JWT Issuer ('JwtSettings:Issuer') is not defined in configuration for token generation.");
                throw new InvalidOperationException("JWT Issuer is not configured for token generation.");
            }
            if (string.IsNullOrEmpty(audience))
            {
                _logger.LogError("AuthService: JWT Audience ('JwtSettings:Audience') is not defined in configuration for token generation.");
                throw new InvalidOperationException("JWT Audience is not configured for token generation.");
            }

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            if (!string.IsNullOrEmpty(role))
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(60), // Example: 60 minutes expiration
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task<(bool IsValid, string? Role, string? UserId)> ValidateUserAsync(string username, string password)
        {
            _logger.LogInformation("AuthService: Attempting to validate user '{Username}' via UserService.", username);
            
            // UserServiceUrl comes from IConfiguration, populated by docker-compose environment variable
            var userServiceUrl = _config["UserServiceUrl"]; 

            if (string.IsNullOrEmpty(userServiceUrl))
            {
                _logger.LogError("AuthService: UserServiceUrl is not configured (expected from environment variable 'UserServiceUrl'). Cannot call UserService.");
                return (false, null, null);
            }

            var validationEndpoint = $"{userServiceUrl.TrimEnd('/')}/User/validate";
            
            try
            {
                var validationPayload = new { Username = username, Password = password };
                _logger.LogInformation("AuthService: Calling UserService validation endpoint: {ValidationEndpoint}", validationEndpoint);

                // Using the injected general HttpClient
                var response = await _httpClient.PostAsJsonAsync(validationEndpoint, validationPayload);

                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content.ReadFromJsonAsync<ValidateUserResponse>();
                    string? role = result?.Role;
                    string? userId = result?.UserId;
                    _logger.LogInformation("AuthService: User '{Username}' validated successfully by UserService with role: {Role}, UserId: {UserId}", username, role, userId);
                    return (true, role, userId);
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogWarning("AuthService: User validation failed via UserService for '{Username}'. Status: {StatusCode}, Endpoint: {ValidationEndpoint}, Response: {ErrorContent}", 
                        username, response.StatusCode, validationEndpoint, errorContent);
                    return (false, null, null);
                }
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "AuthService: HttpRequestException while communicating with UserService at {ValidationEndpoint} for user '{Username}'. Ensure UserService is accessible.", validationEndpoint, username);
                return (false, null, null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AuthService: Unexpected error while communicating with UserService for user '{Username}'.", username);
                return (false, null, null);
            }
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel login)
        {
            if (login == null || string.IsNullOrEmpty(login.Username) || string.IsNullOrEmpty(login.Password))
            {
                return BadRequest(new { message = "Username and password are required." });
            }

            _logger.LogInformation("AuthService: Login attempt for user '{Username}'.", login.Username);
            var (isValid, role, userId) = await ValidateUserAsync(login.Username, login.Password);

            if (isValid)
            {
                var token = GenerateJwtToken(login.Username, role);
                _logger.LogInformation("AuthService: Token generated successfully for user '{Username}' with UserId: {UserId}.", login.Username, userId);
                return Ok(new LoginResponse 
                { 
                    Token = token,
                    UserId = userId ?? string.Empty
                });
            }

            _logger.LogWarning("AuthService: Unauthorized login attempt for '{Username}'.", login.Username);
            return Unauthorized(new { message = "Invalid username or password" });
        }
    }
}