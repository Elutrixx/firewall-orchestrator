using FWO.Services.RulePositioning.Diagnostics;
using Newtonsoft.Json.Linq;
using NUnit.Framework;

namespace FWO.Test;

[TestFixture]
[NonParallelizable]
public class RulePositioningForensicCaptureTest
{
    private string testRoot = "";

    [SetUp]
    public void SetUp()
    {
        testRoot = Path.Combine(
            Path.GetTempPath(),
            $"fwo-positioning-forensics-{Guid.NewGuid():N}");
        RulePositioningForensicCapture.ArtifactRoot = testRoot;
    }

    [TearDown]
    public void TearDown()
    {
        RulePositioningForensicCapture.ResetForTests();
        if (Directory.Exists(testRoot))
        {
            Directory.Delete(testRoot, true);
        }
        else if (File.Exists(testRoot))
        {
            File.Delete(testRoot);
        }
    }

    [Test]
    public void Begin_WritesOrderedCorrelatedManifestAndCompletion()
    {
        using RulePositioningForensicSession session = RulePositioningForensicCapture.Begin(
            101,
            202,
            303,
            404);

        RulePositioningForensicCapture.Record("snapshot", "mapped", new { rulebaseCount = 7 });
        session.Complete("COMPLETE", new { outcome = "Stored" });

        List<JObject> events = ReadEvents(session.EventFilePath);
        Assert.That(events, Has.Count.EqualTo(3));
        Assert.That(events.Select(EventSequence), Is.EqualTo(new List<long> { 1, 2, 3 }));
        Assert.That(events.All(item => item.Value<long>("implementationTaskId") == 101), Is.True);
        Assert.That(events.All(item => item.Value<long>("requestTaskId") == 202), Is.True);
        Assert.That(events.All(item => item.Value<long>("ticketId") == 303), Is.True);
        Assert.That(events.All(item => item.Value<int>("gatewayId") == 404), Is.True);
        Assert.That(events[0].Value<string>("eventName"), Is.EqualTo("manifest"));
        Assert.That(events[0]["payload"]?.Value<int>("processId"), Is.GreaterThan(0));
        Assert.That(events[0]["payload"]?.Value<string>("runtimeVersion"), Is.Not.Empty);
        Assert.That(events[1].Value<string>("stage"), Is.EqualTo("snapshot"));
        Assert.That(events[1]["payload"]?.Value<int>("rulebaseCount"), Is.EqualTo(7));
        Assert.That(events[2].Value<string>("eventName"), Is.EqualTo("complete"));
        Assert.That(events[2]["payload"]?.Value<string>("status"), Is.EqualTo("COMPLETE"));
    }

    [Test]
    public async Task Record_AmbientSessionFlowsAcrossAwait()
    {
        using RulePositioningForensicSession session = RulePositioningForensicCapture.Begin(11, 12, 13, 14);

        await Task.Yield();
        RulePositioningForensicCapture.Record("workflow", "after-await", new { reached = true });
        session.Complete("COMPLETE");

        List<JObject> events = ReadEvents(session.EventFilePath);
        Assert.That(events.Any(item => item.Value<string>("eventName") == "after-await"), Is.True);
    }

    [Test]
    public void Record_WithoutSessionDoesNotCreateArtifacts()
    {
        RulePositioningForensicCapture.Record("workflow", "ignored", new { value = 1 });

        Assert.That(Directory.Exists(testRoot), Is.False);
    }

    [Test]
    public void Dispose_WithoutCompletionWritesIncompleteTerminalEvent()
    {
        RulePositioningForensicSession session = RulePositioningForensicCapture.Begin(21, 22, 23, 24);
        string eventFilePath = session.EventFilePath;

        session.Dispose();

        JObject terminal = ReadEvents(eventFilePath).Last();
        Assert.That(terminal.Value<string>("eventName"), Is.EqualTo("complete"));
        Assert.That(terminal["payload"]?.Value<string>("status"), Is.EqualTo("INCOMPLETE"));
        Assert.That(terminal["payload"]?.Value<string>("reason"), Is.EqualTo("SessionDisposedWithoutCompletion"));
    }

    [Test]
    public void Record_WithUnserializablePayloadDoesNotEscapeAndRecordsStableError()
    {
        using RulePositioningForensicSession session = RulePositioningForensicCapture.Begin(31, 32, 33, 34);
        SelfReferencingPayload payload = new();
        payload.Reference = payload;

        Assert.DoesNotThrow(() =>
            RulePositioningForensicCapture.Record("workflow", "cyclic", payload));
        session.Complete("INCOMPLETE");

        JObject error = ReadEvents(session.EventFilePath)
            .Single(item => item.Value<string>("eventName") == "capture-error");
        Assert.That(error["payload"]?.Value<string>("category"), Is.EqualTo("SerializationFailed"));
        Assert.That(error.ToString(), Does.Not.Contain(nameof(SelfReferencingPayload)));
    }

    [Test]
    public void Begin_WhenRootCannotBeCreatedDoesNotEscape()
    {
        File.WriteAllText(testRoot, "not a directory");

        RulePositioningForensicSession? session = null;
        Assert.DoesNotThrow(() =>
            session = RulePositioningForensicCapture.Begin(41, 42, 43, 44));
        Assert.DoesNotThrow(() =>
            RulePositioningForensicCapture.Record("workflow", "ignored", new { value = 1 }));
        Assert.DoesNotThrow(() => session!.Dispose());
    }

    [Test]
    public async Task ConcurrentAttemptsUseDifferentDirectoriesAndSequences()
    {
        List<Task<string>> attempts =
        [
            WriteAttemptAsync(51),
            WriteAttemptAsync(51)
        ];

        string[] paths = await Task.WhenAll(attempts);

        Assert.That(paths.Distinct().Count(), Is.EqualTo(2));
        foreach (string path in paths)
        {
            Assert.That(ReadEvents(path).Select(EventSequence), Is.EqualTo(new List<long> { 1, 2, 3 }));
        }
    }

    [Test]
    public void Begin_OnUnixRestrictsDirectoryAndEventFileModes()
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.Ignore("Unix mode bits are not available on Windows.");
            return;
        }

        using RulePositioningForensicSession session = RulePositioningForensicCapture.Begin(61, 62, 63, 64);

        Assert.That(
            File.GetUnixFileMode(session.AttemptDirectory),
            Is.EqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute));
        Assert.That(
            File.GetUnixFileMode(session.EventFilePath),
            Is.EqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite));
    }

    private static async Task<string> WriteAttemptAsync(long implementationTaskId)
    {
        using RulePositioningForensicSession session = RulePositioningForensicCapture.Begin(
            implementationTaskId,
            52,
            53,
            54);
        await Task.Yield();
        RulePositioningForensicCapture.Record("workflow", "attempt", new { implementationTaskId });
        session.Complete("COMPLETE");
        return session.EventFilePath;
    }

    private static List<JObject> ReadEvents(string eventFilePath)
    {
        return File.ReadAllLines(eventFilePath)
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .Select(JObject.Parse)
            .ToList();
    }

    private static long EventSequence(JObject item) => item.Value<long>("sequence");

    private sealed class SelfReferencingPayload
    {
        public SelfReferencingPayload? Reference { get; set; }
    }
}
