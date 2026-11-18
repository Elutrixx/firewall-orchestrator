using FWO.Services.RulePositioning.Diagnostics;
using Newtonsoft.Json.Linq;

namespace FWO.Test;

/// <summary>Creates one isolated temporary forensic artifact for focused tests.</summary>
internal sealed class ForensicCaptureTestScope : IDisposable
{
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        $"fwo-positioning-forensics-{Guid.NewGuid():N}");
    private readonly RulePositioningForensicSession session;
    private bool completed;

    internal ForensicCaptureTestScope()
    {
        RulePositioningForensicCapture.ArtifactRoot = root;
        session = RulePositioningForensicCapture.Begin(101, 202, 303, 404);
    }

    internal List<JObject> CompleteAndRead()
    {
        session.Complete("COMPLETE");
        completed = true;
        return File.ReadAllLines(session.EventFilePath)
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .Select(JObject.Parse)
            .ToList();
    }

    public void Dispose()
    {
        if (!completed)
        {
            session.Complete("INCOMPLETE");
        }
        session.Dispose();
        RulePositioningForensicCapture.ResetForTests();
        if (Directory.Exists(root))
        {
            Directory.Delete(root, true);
        }
    }
}
