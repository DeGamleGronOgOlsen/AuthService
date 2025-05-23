namespace AuthService.Models
{
    public class LoginModel
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    // DTO for deserializing the response from UserService's /User/validate endpoint
    public class ValidateUserResponse
    {
        public string? Role { get; set; }
        public string? UserId { get; set; }
    }

    // Response model for login endpoint
    public class LoginResponse
    {
        public string Token { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
    }
}