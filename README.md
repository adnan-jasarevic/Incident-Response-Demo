# Brute-Force Incident Response Demo

> **Note:** This is a teaching demo. The login uses a hard-coded account and a fake token. Do not deploy it or reuse its code in production.

A small ASP.NET Core (.NET 10) API that walks through the incident response lifecycle (NIST SP 800-61) for a brute-force login attack. It was built as the practical part of a seminar paper on incident response planning, illustrating secure-by-design principles and proper security logging.

## What it demonstrates

`POST /api/auth/login` checks credentials and tracks failed attempts per client IP in `IncidentTrackerService`:

- **Detection and analysis (phase 2):** every failed login is logged as a structured security event with the IP address, the targeted username and the attempt count. Passwords are never logged.
- **Escalation:** when one IP fails **5 times within 15 minutes**, the event is escalated to a **Critical** incident log entry, the kind of signal a SIEM would alert on.
- **Containment (phase 3):** that IP is then locked out for **15 minutes**. Every request from it gets `429 Too Many Requests` with a `Retry-After` header, even with the correct password. The lockout expires on its own.

A few secure-by-design details worth pointing out:

- The same `401` message is returned for a wrong username and a wrong password, so attackers can't use it to discover valid accounts.
- Credentials are compared in constant time, so response timing doesn't leak information.
- Control characters such as newlines are removed from logged usernames, so an attacker can't forge entries in the log.
- The tracker is thread-safe, which matters because brute-force attacks send requests in parallel. Expired entries are cleaned up so memory doesn't grow forever.

The limits are configurable in `appsettings.json`:

```json
"BruteForceProtection": {
  "MaxFailedAttempts": 5,
  "FailureWindow": "00:15:00",
  "LockoutDuration": "00:15:00"
}
```

## Running it

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```bash
dotnet run
```

The API listens on `http://localhost:5085`. The demo account is `admin` / `password123`.

Open `IncidentResponseDemo.http` in Visual Studio, Rider, or VS Code (with the REST Client extension):

| # | Request | Expected result |
|---|---|---|
| 1 | Correct credentials | `200`, login successful |
| 2 | Wrong password, sent 5 times | `401` each time; the 5th logs a Critical incident |
| 3 | Correct credentials again | `429` with `Retry-After`: the IP is locked out |

Then open `security_incidents<date>.log` in the project folder to see the structured incident record that would be forwarded to a SIEM and the incident response team (CSIRT) in a real environment.

## Known limitations

These are deliberate simplifications and good discussion points:

- **Per-IP tracking only.** An attacker using many IP addresses (a botnet), or trying one common password against many accounts (password spraying, credential stuffing), stays under the limit. Real systems also track per account and use signals such as CAPTCHA, MFA and breached-password checks.
- **Shared IPs.** Users behind the same NAT or corporate proxy share one IP, so one attacker can lock out all of them. Behind a reverse proxy, the app would also need forwarded-headers middleware to see real client IPs.
- **In-memory state.** Counters are lost on restart and aren't shared between multiple app instances. A production system would use a shared store such as Redis.
- **No real authentication.** One hard-coded account and a placeholder token stand in for a user database with hashed passwords and real JWTs.

## Project structure

```
Program.cs                          App setup, logging, dependency injection
Controllers/AuthController.cs       Login endpoint, security logging, lockout response
Services/IncidentTrackerService.cs  Thread-safe failed-attempt tracking and lockouts
IncidentResponseDemo.http           Ready-made demo requests
```
