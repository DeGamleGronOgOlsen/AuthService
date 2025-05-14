using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;
using VaultSharp.V1.AuthMethods;


var builder = WebApplication.CreateBuilder(args);

// Tilføjer logging
var logger = builder.Services.BuildServiceProvider().GetRequiredService<ILoggerFactory>().CreateLogger("VaultLogger");

var httpClientHandler = new HttpClientHandler();
var EndPoint = "https://vault_dev:8201/";
httpClientHandler.ServerCertificateCustomValidationCallback =
(message, cert, chain, sslPolicyErrors) => { return true; };

// Konfigurer Vault klienten
// Du skal bruge en gyldig token til at autentificere dig mod Vault. Erstat med din token.
IAuthMethodInfo authMethod =
new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");
var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
{
    Namespace = "",
    MyHttpClientProviderFunc = handler
    => new HttpClient(httpClientHandler)
    {
        BaseAddress = new Uri(EndPoint)
    }
};
IVaultClient vaultClient = new VaultClient(vaultClientSettings);

try
{
    // Henter hemmeligheder fra Vault
    logger.LogInformation("Henter hemmeligheder fra Vault...");
    Secret<SecretData> secretData = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync("my-secret", mountPoint: "secret");

    string mySecret = secretData.Data.Data["Secret"]?.ToString() ?? throw new Exception("Secret er ikke fundet i Vault.");
    string myIssuer = secretData.Data.Data["Issuer"]?.ToString() ?? throw new Exception("Issuer er ikke fundet i Vault.");

    builder.Configuration["Secret"] = mySecret;
    builder.Configuration["Issuer"] = myIssuer;

    logger.LogInformation("Hemmeligheder hentet fra Vault:");
    logger.LogInformation($"Secret: {mySecret}");
    logger.LogInformation($"Issuer: {myIssuer}");


// Konfigurer JWT autentificering
    builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var secret = builder.Configuration["Secret"];
        var issuer = builder.Configuration["Issuer"];

        if (string.IsNullOrEmpty(secret))
        {
            logger.LogError("Secret er ikke defineret i konfigurationen.");
            throw new ArgumentNullException(nameof(secret), "Secret er ikke defineret i konfigurationen.");
        }

        if (string.IsNullOrEmpty(issuer))
        {
            logger.LogError("Issuer er ikke defineret i konfigurationen.");
            throw new ArgumentNullException(nameof(issuer), "Issuer er ikke defineret i konfigurationen.");
        }

        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = issuer,
            ValidAudience = "http://localhost",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret))
        };
    });
}
catch (Exception ex)
{
    logger.LogError($"Fejl under hentning af hemmeligheder fra Vault: {ex.Message}");
    throw;
}

// Tilføj services til containeren.
builder.Services.AddHttpClient();
builder.Services.AddControllers();

var app = builder.Build();


app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();