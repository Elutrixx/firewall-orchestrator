namespace FWO.Services.RulePositioning.Diagnostics;

/// <summary>
/// Provides best-effort ambient forensic capture for one rule-positioning attempt.
/// </summary>
public static class RulePositioningForensicCapture
{
    private const string kDefaultArtifactRoot = "/usr/local/fworch/tmp/rule-positioning-forensics";
    private static readonly AsyncLocal<RulePositioningForensicSession?> kCurrentSession = new();
    private static string artifactRoot = kDefaultArtifactRoot;

    internal static string ArtifactRoot
    {
        get => artifactRoot;
        set => artifactRoot = value;
    }

    /// <summary>Starts one isolated capture and makes it ambient for the current asynchronous flow.</summary>
    public static RulePositioningForensicSession Begin(
        long implementationTaskId,
        long requestTaskId,
        long ticketId,
        int? gatewayId)
    {
        RulePositioningForensicSession? previousSession = kCurrentSession.Value;
        RulePositioningForensicSession session = RulePositioningForensicSession.Create(
            artifactRoot,
            implementationTaskId,
            requestTaskId,
            ticketId,
            gatewayId,
            previousSession);
        kCurrentSession.Value = session;
        return session;
    }

    /// <summary>Records one event for the active capture, or does nothing when no capture is active.</summary>
    public static void Record(string stage, string eventName, object? payload)
    {
        try
        {
            kCurrentSession.Value?.Record(stage, eventName, payload);
        }
        catch
        {
            // Temporary forensic capture must never affect positioning.
        }
    }

    /// <summary>Records an explicit stage status for the active capture.</summary>
    public static void MarkStage(string stage, string status, string? reason = null)
    {
        Record(stage, "stage-status", new RulePositioningForensicStageStatus(status, reason));
    }

    internal static void Restore(
        RulePositioningForensicSession session,
        RulePositioningForensicSession? previousSession)
    {
        if (ReferenceEquals(kCurrentSession.Value, session))
        {
            kCurrentSession.Value = previousSession;
        }
    }

    internal static void ResetForTests()
    {
        kCurrentSession.Value = null;
        artifactRoot = kDefaultArtifactRoot;
    }
}
