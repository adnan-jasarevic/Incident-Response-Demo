using IncidentResponseDemo.Services;
using Microsoft.AspNetCore.Mvc;

namespace IncidentResponseDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
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
        string clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown_IP";

        // faza 3 : provjera da li je napadac blokiran
        if (_tracker.IsIpBlocked(clientIp))
        {
            _logger.LogWarning("SECURITY EVENT: Blokirani IP {ClientIp} se pokusao ulogovati.", clientIp);
            return StatusCode(403, "Vaša IP adresa je blokirana zbog sumnjivih aktivnosti. CSIRT tim je obaviješten.");
        }

        // Simulacija baze: tačni podaci su admin / password123
        if (request.Username == "admin" && request.Password == "password123")
        {
            _tracker.ResetAttempts(clientIp);
            _logger.LogInformation("Prijava uspješna za korisnika {Username} sa IP {ClientIp}", request.Username, clientIp);
            return Ok(new { Message = "Uspješna prijava", Token = "fake-jwt-token-123" });
        }

        // Pogrešni podaci: biljezi se neuspjesan pokusan
        _tracker.RegisterFailedAttempt(clientIp);
        int attemptsCount = _tracker.GetFailedAttempts(clientIp);

        // faza 2 : detekcija i analiza - Strukturirano logiranje incidenata
        _logger.LogWarning("SECURITY EVENT: Neuspješan login pokušaj {AttemptCount}/5 za korisnika '{Username}' sa IP {ClientIp}", 
            attemptsCount, request.Username, clientIp);

        // Ako je dostigao maksimum, proglašavamo INCIDENT (generiše se Critical log za SIEM sistem)
        if (attemptsCount >= 5)
        {
            _logger.LogCritical("INCIDENT ALERT: Potencijalni Brute-force napad detektovan sa IP {ClientIp}. Ciljani account: '{Username}'. IP je blokirana.", 
                clientIp, request.Username);
        }

        return Unauthorized(new { Message = "Pogrešno korisničko ime ili lozinka." });
    }
}

public class LoginRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}