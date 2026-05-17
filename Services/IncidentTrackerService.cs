namespace IncidentResponseDemo.Services;

public class IncidentTrackerService
{
    private readonly Dictionary<string, int> _failedAttempts = new();
    private readonly int _maxAttempts = 5;

    public void RegisterFailedAttempt(string ipAddress)
    {
        if (_failedAttempts.ContainsKey(ipAddress))
            _failedAttempts[ipAddress]++;
        else
            _failedAttempts[ipAddress] = 1;
    }

    public void ResetAttempts(string ipAddress)
    {
        if (_failedAttempts.ContainsKey(ipAddress))
            _failedAttempts.Remove(ipAddress);
    }

    public int GetFailedAttempts(string ipAddress)
    {
        return _failedAttempts.ContainsKey(ipAddress) ? _failedAttempts[ipAddress] : 0;
    }

    public bool IsIpBlocked(string ipAddress)
    {
        return GetFailedAttempts(ipAddress) >= _maxAttempts;
    }
}