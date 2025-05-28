using AuthService.Controllers;
using AuthService.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using Moq.Protected;
using NUnit.Framework;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace AuthService.Test
{
    [TestFixture]
    public class AuthControllerTests
    {
        private AuthController _controller = null!;
        private Mock<IConfiguration> _mockConfig = null!;
        private Mock<ILogger<AuthController>> _mockLogger = null!;
        private Mock<HttpMessageHandler> _mockHttpMessageHandler = null!;
        private HttpClient _httpClient = null!;

        [SetUp]
        public void Setup()
        {
            _mockConfig = new Mock<IConfiguration>();
            _mockLogger = new Mock<ILogger<AuthController>>();
            _mockHttpMessageHandler = new Mock<HttpMessageHandler>();

            // Setup configuration
            _mockConfig.Setup(c => c["Secret"]).Returns("your-test-secret-key-which-is-at-least-32-chars!");
            _mockConfig.Setup(c => c["Issuer"]).Returns("AuthService");
            _mockConfig.Setup(c => c["UserServiceUrl"]).Returns("http://localhost:5162");

            // Setup HttpClient to simulate a successful user validation
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"role": "admin", "userId": "123"}""")
            };

            _mockHttpMessageHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .ReturnsAsync(response);

            _httpClient = new HttpClient(_mockHttpMessageHandler.Object);
            _controller = new AuthController(_mockLogger.Object, _mockConfig.Object, _httpClient);
        }

        [TearDown]
        public void Cleanup()
        {
            _httpClient?.Dispose();
        }

        [Test]
        public async Task Login_WithValidCredentials_ReturnsOkWithToken()
        {
            // Arrange
            var loginModel = new LoginModel
            {
                Username = "admin",
                Password = "adminkodeord"
            };

            // Act
            var result = await _controller.Login(loginModel) as OkObjectResult;

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.StatusCode, Is.EqualTo((int)HttpStatusCode.OK));
            Assert.That(result.Value, Has.Property("token"));
        }

        [Test]
        public async Task Login_WithInvalidCredentials_ReturnsUnauthorized()
        {
            // Arrange
            var loginModel = new LoginModel
            {
                Username = "wronguser",
                Password = "wrongpass"
            };

            // Setup mock for invalid credentials
            var unauthorizedResponse = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            _mockHttpMessageHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.Is<HttpRequestMessage>(req => true),
                    ItExpr.IsAny<CancellationToken>()
                )
                .ReturnsAsync(unauthorizedResponse);

            // Act
            var result = await _controller.Login(loginModel) as UnauthorizedObjectResult;

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.StatusCode, Is.EqualTo((int)HttpStatusCode.Unauthorized));
        }
    }
}