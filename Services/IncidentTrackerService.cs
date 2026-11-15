using System.Collections.Concurrent;
using Microsoft.Extensions.Options;

namespace IncidentResponseDemo.Services;

public class BruteForceOptions
{
    public const string SectionName = "BruteForceProtection";

    /// <summary>Failed logins allowed from one IP within <see cref="FailureWindow"/>.</summary>
    public int MaxFailedAttempts { get; set; } = 5;

    /// <summary>How far back failed attempts are counted.</summary>
    public TimeSpan FailureWindow { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How long an IP stays blocked once it is locked out.</summary>
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);
}

public enum FailedAttemptOutcome
{
    /// <summary>Recorded; the IP is still under the limit.</summary>
    Counted,

    /// <summary>This attempt reached the limit and started a lockout.</summary>
    LockedOut,
}

/// <summary>
/// Tracks failed logins per IP address and locks an IP out after too many
/// failures in a short window. Thread-safe: login requests arrive in parallel,
/// especially during a brute-force attack.
/// </summary>
public class IncidentTrackerService
{
    private readonly ConcurrentDictionary<string, AttemptState> _states = new();
    private readonly BruteForceOptions _options;
    private readonly TimeProvider _time;
    private long _lastCleanupTicks;

    public IncidentTrackerService(IOptions<BruteForceOptions> options, TimeProvider time)
    {
        _options = options.Value;
        _time = time;
        _lastCleanupTicks = time.GetUtcNow().UtcTicks;
    }

    public int MaxFailedAttempts => _options.MaxFailedAttempts;

    /// <summary>Returns how long the IP remains blocked, or null if it is not blocked.</summary>
    public TimeSpan? GetRemainingLockout(string ipAddress)
    {
        if (!_states.TryGetValue(ipAddress, out var state) || state.LockedUntil is not { } lockedUntil)
        {
            return null;
        }

        var remaining = lockedUntil - _time.GetUtcNow();
        return remaining > TimeSpan.Zero ? remaining : null;
    }

    public (FailedAttemptOutcome Outcome, int AttemptCount) RegisterFailedAttempt(string ipAddress)
    {
        var now = _time.GetUtcNow();
        RemoveExpiredEntries(now);

        // AddOrUpdate may call the update function more than once under
        // contention, so it must be a pure function of the old state.
        var state = _states.AddOrUpdate(
            ipAddress,
            _ => Next(AttemptState.Empty, now),
            (_, old) => Next(old, now));

        // Each atomic increment yields a unique count, so exactly one request
        // sees the count that started the lockout.
        var outcome = state.LockedUntil is not null && state.FailedCount == _options.MaxFailedAttempts
            ? FailedAttemptOutcome.LockedOut
            : FailedAttemptOutcome.Counted;

        return (outcome, state.FailedCount);
    }

    public void ResetAttempts(string ipAddress) => _states.TryRemove(ipAddress, out _);

    private AttemptState Next(AttemptState old, DateTimeOffset now)
    {
        // A finished lockout, or failures older than the window, start fresh.
        var windowExpired = now - old.WindowStart > _options.FailureWindow;
        var lockoutExpired = old.LockedUntil is { } until && now >= until;
        var current = windowExpired || lockoutExpired ? AttemptState.Empty with { WindowStart = now } : old;

        var count = current.FailedCount + 1;
        if (count >= _options.MaxFailedAttempts && current.LockedUntil is null)
        {
            return current with { FailedCount = count, LockedUntil = now + _options.LockoutDuration };
        }

        return current with { FailedCount = count };
    }

    // Without cleanup the dictionary would grow forever, one entry for every IP
    // that ever failed a login. Sweep at most once a minute.
    private void RemoveExpiredEntries(DateTimeOffset now)
    {
        var last = Interlocked.Read(ref _lastCleanupTicks);
        if (now.UtcTicks - last < TimeSpan.TicksPerMinute ||
            Interlocked.CompareExchange(ref _lastCleanupTicks, now.UtcTicks, last) != last)
        {
            return;
        }

        foreach (var (ip, state) in _states)
        {
            var stale = state.LockedUntil is { } until
                ? now >= until
                : now - state.WindowStart > _options.FailureWindow;

            if (stale)
            {
                // Only removes the entry if no other request changed it meanwhile.
                _states.TryRemove(new KeyValuePair<string, AttemptState>(ip, state));
            }
        }
    }

    private sealed record AttemptState(int FailedCount, DateTimeOffset WindowStart, DateTimeOffset? LockedUntil)
    {
        public static readonly AttemptState Empty = new(0, DateTimeOffset.MinValue, null);
    }
}
