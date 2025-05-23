using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;
using VaultSharp.V1.AuthMethods;
using Microsoft.OpenApi.Models; // Required for Swagger

var builder = WebApplication.CreateBuilder(args);

// Using a simple logger for bootstrap, your NLog setup can be added via builder.Host.UseNLog()
var logger = LoggerFactory.Create(logBuilder => logBuilder.AddConsole()).CreateLogger("AuthService.Startup");

// Vault Client Configuration
var httpClientHandler = new HttpClientHandler();
string vaultAddress = builder.Configuration["Vault:Address"] ?? "https://vaulthost:8201"; // From docker-compose Vault__Address
logger.LogInformation($"AuthService: Using Vault Address: {vaultAddress}");

// WARNING: Bypassing SSL certificate validation. For DEVELOPMENT ONLY.
httpClientHandler.ServerCertificateCustomValidationCallback =
    (message, cert, chain, sslPolicyErrors) => 
    {
        logger.LogWarning("AuthService: Bypassing Vault SSL certificate validation. [Development ONLY]");
        return true; 
    };

string? vaultToken = builder.Configuration["Vault:Token"]; // From docker-compose Vault__Token
if (string.IsNullOrEmpty(vaultToken))
{
    logger.LogCritical("AuthService: Vault:Token is NOT configured. Ensure Vault__Token is set in docker-compose.yml for AuthService.");
    throw new InvalidOperationException("Vault token is not configured. Application cannot start.");
}

IAuthMethodInfo authMethod = new TokenAuthMethodInfo(vaultToken);
var vaultClientSettings = new VaultClientSettings(vaultAddress, authMethod)
{
    Namespace = "",
    MyHttpClientProviderFunc = handler => new HttpClient(httpClientHandler) { BaseAddress = new Uri(vaultAddress) }
};
IVaultClient vaultClient = new VaultClient(vaultClientSettings);

string jwtSecretKeyForSigning;
string jwtIssuerForSigning;
string jwtAudienceForSigning = "http://localhost"; // Default or get from config if you add it

try
{
    logger.LogInformation("AuthService: Fetching JWT signing parameters from Vault path 'secret/Secrets'...");
    Secret<SecretData> secretDataResult = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(
        path: "Secrets", 
        mountPoint: "secret"
    );

    jwtSecretKeyForSigning = secretDataResult.Data.Data["Secret"]?.ToString() 
        ?? throw new InvalidOperationException("JWT 'Secret' not found in Vault at secret/Secrets.");
    jwtIssuerForSigning = secretDataResult.Data.Data["Issuer"]?.ToString()
        ?? throw new InvalidOperationException("JWT 'Issuer' not found in Vault at secret/Secrets.");
    
    // Optionally fetch Audience if you added it to secret/Secrets in vault-init.sh
    // jwtAudienceForSigning = secretDataResult.Data.Data["Audience"]?.ToString() ?? "http://localhost";


    // Populate IConfiguration for AuthController (and JWT validation if needed)
    builder.Configuration["JwtSettings:Secret"] = jwtSecretKeyForSigning;
    builder.Configuration["JwtSettings:Issuer"] = jwtIssuerForSigning;
    builder.Configuration["JwtSettings:Audience"] = jwtAudienceForSigning; // Set explicitly for consistency

    logger.LogInformation("AuthService: JWT Secret and Issuer loaded from Vault.");

    // UserServiceUrl is NOT fetched from Vault here, as vault-init.sh doesn't store it for AuthService.
    // It will be read by AuthController directly from IConfiguration (populated by docker-compose environment).
}
catch (Exception ex)
{
    logger.LogCritical(ex, "AuthService: CRITICAL ERROR fetching secrets from Vault.");
    throw;
}

// Configure JWT Bearer Authentication (if AuthService itself has protected endpoints)
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuerForSigning,       // From Vault via variable
            ValidAudience = jwtAudienceForSigning, // From variable (defaulted or from Vault)
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecretKeyForSigning)) // From Vault via variable
        };
    });
logger.LogInformation("AuthService: JWT Authentication services configured.");

// Add services to the container.
builder.Services.AddHttpClient(); // For AuthController to call UserService
builder.Services.AddControllers();
builder.Services.AddAuthorization();

// Configure CORS policy to allow your frontend
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowCors", policy =>
    {
        policy.WithOrigins("http://localhost:8081", "http://localhost:8080", "http://localhost:4000", "http://localhost:5162", "http://localhost:8201") // Added 8081 first
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "AuthService API", Version = "v1" });
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header, Description = "Please enter JWT",
        Name = "Authorization", Type = SecuritySchemeType.Http,
        BearerFormat = "JWT", Scheme = "Bearer"
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// CORS must be before authentication/authorization
app.UseCors("AllowCors");

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "AuthService API v1"));
}

// app.UseHttpsRedirection(); // Optional, depending on your reverse proxy / ingress setup

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

logger.LogInformation("AuthService: Application starting...");
app.Run();