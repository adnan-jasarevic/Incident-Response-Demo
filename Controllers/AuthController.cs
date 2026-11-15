using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using IncidentResponseDemo.Services;
using Microsoft.AspNetCore.Mvc;

namespace IncidentResponseDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public partial class AuthController : ControllerBase
{
    // DEMO ONLY: a hard-coded account stands in for a user database.
    // A real system stores salted password hashes (e.g. ASP.NET Core Identity).
    private const string DemoUsername = "admin";
    private const string DemoPassword = "password123";

    private readonly ILogger<AuthController> _logger;
    private readonly IncidentTrackerService _tracker;

    public AuthController(ILogger<AuthController> logger, IncidentTrackerService tracker)
    {
        _logger = logger;
        _tracker = tracker;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var username = Sanitize(request.Username);

        // Phase 3 (containment): a locked-out IP is refused before its
        // credentials are even checked.
        if (_tracker.GetRemainingLockout(clientIp) is { } remaining)
        {
            _logger.LogWarning(
                "SECURITY EVENT: Blocked IP {ClientIp} attempted to log in as '{Username}'. Lockout ends in {LockoutSeconds}s.",
                clientIp, username, (int)remaining.TotalSeconds);

            Response.Headers.RetryAfter = ((int)Math.Ceiling(remaining.TotalSeconds)).ToString();
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                Message = "Too many failed login attempts from your IP address. Try again later.",
            });
        }

        if (IsValidLogin(request))
        {
            _tracker.ResetAttempts(clientIp);
            _logger.LogInformation("Successful login for user '{Username}' from {ClientIp}", username, clientIp);
            return Ok(new { Message = "Login successful.", Token = "demo-token-not-a-real-jwt" });
        }

        // Phase 2 (detection and analysis): every failure is a structured
        // security event. Passwords are never logged.
        var (outcome, attemptCount) = _tracker.RegisterFailedAttempt(clientIp);

        _logger.LogWarning(
            "SECURITY EVENT: Failed login attempt {AttemptCount}/{MaxAttempts} for user '{Username}' from {ClientIp}",
            attemptCount, _tracker.MaxFailedAttempts, username, clientIp);

        if (outcome == FailedAttemptOutcome.LockedOut)
        {
            // Escalate to an incident, logged as Critical so a SIEM can alert on it.
            _logger.LogCritical(
                "INCIDENT ALERT: Possible brute-force attack from {ClientIp}. Targeted account: '{Username}'. IP locked out.",
                clientIp, username);
        }

        // Same response whether the username or the password was wrong, so
        // attackers can't use it to discover valid usernames.
        return Unauthorized(new { Message = "Invalid username or password." });
    }

    private static bool IsValidLogin(LoginRequest request)
    {
        // Constant-time comparison, so response timing reveals nothing about
        // how much of the input was correct. Both checks always run.
        var userOk = FixedTimeEquals(request.Username, DemoUsername);
        var passwordOk = FixedTimeEquals(request.Password, DemoPassword);
        return userOk & passwordOk;
    }

    private static bool FixedTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    // Strip control characters such as newlines so an attacker cannot forge
    // extra lines in the log file through the username field.
    private static string Sanitize(string value) => ControlCharacters().Replace(value, "?");

    [GeneratedRegex(@"\p{Cc}")]
    private static partial Regex ControlCharacters();
}

public class LoginRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}
