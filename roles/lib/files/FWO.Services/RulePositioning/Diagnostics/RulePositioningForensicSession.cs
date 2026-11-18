using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace FWO.Services.RulePositioning.Diagnostics;

/// <summary>Owns the append-only artifacts for one rule-positioning attempt.</summary>
public sealed class RulePositioningForensicSession : IDisposable
{
    private const int kSchemaVersion = 1;
    private const string kEventFileName = "events.jsonl";
    private static readonly JsonSerializerSettings kSerializerSettings = new()
    {
        Formatting = Formatting.None,
        NullValueHandling = NullValueHandling.Include,
        ReferenceLoopHandling = ReferenceLoopHandling.Error
    };
    private static readonly Lazy<string?> kAssemblySha256 = new(CalculateAssemblySha256);
    private readonly object writeLock = new();
    private readonly RulePositioningForensicIdentity identity;
    private readonly RulePositioningForensicSession? previousSession;
    private readonly Stopwatch elapsed = Stopwatch.StartNew();
    private readonly FileStream? eventStream;
    private readonly StreamWriter? eventWriter;
    private long sequence;
    private int completed;
    private int disposed;
    private int writerClosed;

    private RulePositioningForensicSession(
        RulePositioningForensicIdentity identity,
        string attemptDirectory,
        string eventFilePath,
        FileStream? eventStream,
        StreamWriter? eventWriter,
        RulePositioningForensicSession? previousSession)
    {
        this.identity = identity;
        AttemptDirectory = attemptDirectory;
        EventFilePath = eventFilePath;
        this.eventStream = eventStream;
        this.eventWriter = eventWriter;
        this.previousSession = previousSession;
    }

    /// <summary>Gets the unique identifier for this capture attempt.</summary>
    public string CaptureId => identity.CaptureId;

    /// <summary>Gets the implementation task being captured.</summary>
    public long ImplementationTaskId => identity.ImplementationTaskId;

    /// <summary>Gets the request task being captured.</summary>
    public long RequestTaskId => identity.RequestTaskId;

    /// <summary>Gets the ticket being captured.</summary>
    public long TicketId => identity.TicketId;

    /// <summary>Gets the target gateway when it was known at capture start.</summary>
    public int? GatewayId => identity.GatewayId;

    /// <summary>Gets the attempt-specific artifact directory, or an empty string when initialization failed.</summary>
    public string AttemptDirectory { get; }

    /// <summary>Gets the JSON Lines event path, or an empty string when initialization failed.</summary>
    public string EventFilePath { get; }

    internal static RulePositioningForensicSession Create(
        string artifactRoot,
        long implementationTaskId,
        long requestTaskId,
        long ticketId,
        int? gatewayId,
        RulePositioningForensicSession? previousSession)
    {
        string captureId = $"{DateTimeOffset.UtcNow:yyyyMMddTHHmmss.fffffffZ}-{Guid.NewGuid():N}";
        RulePositioningForensicIdentity identity = new(
            captureId,
            implementationTaskId,
            requestTaskId,
            ticketId,
            gatewayId);
        try
        {
            string implementationTaskDirectory = Path.Combine(
                artifactRoot,
                $"impltask-{implementationTaskId}");
            string attemptDirectory = Path.Combine(
                implementationTaskDirectory,
                $"attempt-{captureId}");
            CreateRestrictedDirectory(artifactRoot);
            CreateRestrictedDirectory(implementationTaskDirectory);
            CreateRestrictedDirectory(attemptDirectory);
            string eventFilePath = Path.Combine(attemptDirectory, kEventFileName);
            FileStream stream = CreateRestrictedEventStream(eventFilePath);
            StreamWriter writer = new(stream, new UTF8Encoding(false));
            RulePositioningForensicSession session = new(
                identity,
                attemptDirectory,
                eventFilePath,
                stream,
                writer,
                previousSession);
            session.WriteManifest();
            return session;
        }
        catch
        {
            return new RulePositioningForensicSession(
                identity,
                "",
                "",
                null,
                null,
                previousSession);
        }
    }

    /// <summary>Writes the terminal record once. Subsequent calls do nothing.</summary>
    public void Complete(string status, object? payload = null)
    {
        if (Interlocked.CompareExchange(ref completed, 1, 0) != 0)
        {
            return;
        }

        RulePositioningForensicTerminal terminal = new(
            status,
            null,
            elapsed.ElapsedMilliseconds,
            AttemptDirectory,
            payload);
        WriteEvent("capture", "complete", terminal);
        CloseWriter();
    }

    internal void Record(string stage, string eventName, object? payload)
    {
        if (Volatile.Read(ref completed) != 0)
        {
            return;
        }
        WriteEvent(stage, eventName, payload);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0)
        {
            return;
        }

        if (Volatile.Read(ref completed) == 0)
        {
            CompleteIncomplete();
        }

        CloseWriter();
        RulePositioningForensicCapture.Restore(this, previousSession);
    }

    private void CompleteIncomplete()
    {
        if (Interlocked.CompareExchange(ref completed, 1, 0) != 0)
        {
            return;
        }

        RulePositioningForensicTerminal terminal = new(
            "INCOMPLETE",
            "SessionDisposedWithoutCompletion",
            elapsed.ElapsedMilliseconds,
            AttemptDirectory,
            null);
        WriteEvent("capture", "complete", terminal);
        CloseWriter();
    }

    private void WriteManifest()
    {
        Assembly assembly = typeof(RulePositioningForensicSession).Assembly;
        RulePositioningForensicManifest manifest = new(
            AttemptDirectory,
            Environment.ProcessId,
            RuntimeInformation.FrameworkDescription,
            assembly.GetName().Version?.ToString() ?? "unknown",
            kAssemblySha256.Value);
        WriteEvent("capture", "manifest", manifest);
    }

    private void WriteEvent(string stage, string eventName, object? payload)
    {
        if (eventWriter == null || eventStream == null)
        {
            return;
        }

        try
        {
            RulePositioningForensicEvent forensicEvent = CreateEvent(stage, eventName, payload);
            string json = JsonConvert.SerializeObject(forensicEvent, kSerializerSettings);
            WriteLine(json);
        }
        catch (JsonException)
        {
            WriteSerializationError(stage, eventName);
        }
        catch
        {
            // Temporary forensic capture must never affect positioning.
        }
    }

    private RulePositioningForensicEvent CreateEvent(string stage, string eventName, object? payload)
    {
        return new RulePositioningForensicEvent(
            kSchemaVersion,
            Interlocked.Increment(ref sequence),
            DateTimeOffset.UtcNow,
            CaptureId,
            ImplementationTaskId,
            RequestTaskId,
            TicketId,
            GatewayId,
            stage,
            eventName,
            payload);
    }

    private void WriteSerializationError(string stage, string eventName)
    {
        try
        {
            RulePositioningForensicCaptureError payload = new(
                "SerializationFailed",
                stage,
                eventName);
            RulePositioningForensicEvent forensicEvent = CreateEvent(
                "capture",
                "capture-error",
                payload);
            string json = JsonConvert.SerializeObject(forensicEvent, kSerializerSettings);
            WriteLine(json);
        }
        catch
        {
            // No further fallback can safely write this event.
        }
    }

    private void WriteLine(string json)
    {
        lock (writeLock)
        {
            eventWriter!.WriteLine(json);
            eventWriter.Flush();
            eventStream!.Flush(true);
        }
    }

    private void CloseWriter()
    {
        if (Interlocked.CompareExchange(ref writerClosed, 1, 0) != 0)
        {
            return;
        }

        lock (writeLock)
        {
            try
            {
                eventWriter?.Dispose();
                eventStream?.Dispose();
            }
            catch
            {
                // Temporary forensic capture must never affect positioning.
            }
        }
    }

    private static void CreateRestrictedDirectory(string path)
    {
        Directory.CreateDirectory(path);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static FileStream CreateRestrictedEventStream(string path)
    {
        FileStreamOptions options = new()
        {
            Access = FileAccess.Write,
            Mode = FileMode.CreateNew,
            Share = FileShare.Read,
            Options = FileOptions.WriteThrough
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }
        return new FileStream(path, options);
    }

    private static string? CalculateAssemblySha256()
    {
        try
        {
            string location = typeof(RulePositioningForensicSession).Assembly.Location;
            if (string.IsNullOrWhiteSpace(location) || !File.Exists(location))
            {
                return null;
            }
            using FileStream stream = File.OpenRead(location);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }
}
