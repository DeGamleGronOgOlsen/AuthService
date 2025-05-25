using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using NLog;
using NLog.Web;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;
using VaultSharp.V1.AuthMethods;
using System.Text;

var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
logger.Debug("Starting AuthService");

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Logging.ClearProviders();
    builder.Host.UseNLog();

    var httpClientHandler = new HttpClientHandler();
    var EndPoint = "https://vaulthost:8201/";
    httpClientHandler.ServerCertificateCustomValidationCallback =
        (message, cert, chain, sslPolicyErrors) => true;

    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowFrontend", policy =>
        {
            policy.WithOrigins("http://localhost:8080")
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
        });
    });

    IAuthMethodInfo authMethod = new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");
    var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
    {
        Namespace = "",
        MyHttpClientProviderFunc = handler => new HttpClient(httpClientHandler)
        {
            BaseAddress = new Uri(EndPoint)
        }
    };
    IVaultClient vaultClient = new VaultClient(vaultClientSettings);

    try
    {
        logger.Info("Fetching secrets from Vault...");
        Secret<SecretData> secretData = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "Secrets", mountPoint: "secret");

        string mySecretKey = secretData.Data.Data["Secret"]?.ToString();
        if (string.IsNullOrEmpty(mySecretKey))
        {
            logger.Error("Secret is not defined in Vault.");
            throw new ArgumentNullException(nameof(mySecretKey), "Secret is not defined in Vault.");
        }

        string myIssuer = secretData.Data.Data["Issuer"]?.ToString();
        if (string.IsNullOrEmpty(myIssuer))
        {
            logger.Error("Issuer is not defined in Vault.");
            throw new ArgumentNullException(nameof(myIssuer), "Issuer is not defined in Vault.");
        }

        builder.Configuration["Secret"] = mySecretKey;
        builder.Configuration["Issuer"] = myIssuer;

        logger.Info("Secrets fetched from Vault:");
        logger.Info($"Secret: {mySecretKey}");
        logger.Info($"Issuer: {myIssuer}");

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
                    ValidIssuer = myIssuer,
                    ValidAudience = "http://localhost",
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecretKey))
                };
            });
    }
    catch (Exception ex)
    {
        logger.Error(ex, "Error fetching secrets from Vault");
        throw;
    }

    builder.Services.AddHttpClient();
    builder.Services.AddControllers();

    var app = builder.Build();

    app.UseCors("AllowFrontend");
    app.UseHttpsRedirection();
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapControllers();
    app.Run();
}
catch (Exception ex)
{
    logger.Error(ex, "Stopped program because of exception");
    throw;
}
finally
{
    NLog.LogManager.Shutdown();
}