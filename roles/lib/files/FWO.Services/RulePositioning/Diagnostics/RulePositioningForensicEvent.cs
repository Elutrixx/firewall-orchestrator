using Newtonsoft.Json;

namespace FWO.Services.RulePositioning.Diagnostics;

internal sealed record RulePositioningForensicIdentity(
    string CaptureId,
    long ImplementationTaskId,
    long RequestTaskId,
    long TicketId,
    int? GatewayId);

internal sealed record RulePositioningForensicEvent(
    [property: JsonProperty("schemaVersion")] int SchemaVersion,
    [property: JsonProperty("sequence")] long Sequence,
    [property: JsonProperty("timestampUtc")] DateTimeOffset TimestampUtc,
    [property: JsonProperty("captureId")] string CaptureId,
    [property: JsonProperty("implementationTaskId")] long ImplementationTaskId,
    [property: JsonProperty("requestTaskId")] long RequestTaskId,
    [property: JsonProperty("ticketId")] long TicketId,
    [property: JsonProperty("gatewayId")] int? GatewayId,
    [property: JsonProperty("stage")] string Stage,
    [property: JsonProperty("eventName")] string EventName,
    [property: JsonProperty("payload")] object? Payload);

internal sealed record RulePositioningForensicManifest(
    [property: JsonProperty("artifactPath")] string ArtifactPath,
    [property: JsonProperty("processId")] int ProcessId,
    [property: JsonProperty("runtimeVersion")] string RuntimeVersion,
    [property: JsonProperty("assemblyVersion")] string AssemblyVersion,
    [property: JsonProperty("assemblySha256")] string? AssemblySha256);

internal sealed record RulePositioningForensicStageStatus(
    [property: JsonProperty("status")] string Status,
    [property: JsonProperty("reason")] string? Reason);

internal sealed record RulePositioningForensicTerminal(
    [property: JsonProperty("status")] string Status,
    [property: JsonProperty("reason")] string? Reason,
    [property: JsonProperty("elapsedMilliseconds")] long ElapsedMilliseconds,
    [property: JsonProperty("artifactPath")] string ArtifactPath,
    [property: JsonProperty("data")] object? Data);

internal sealed record RulePositioningForensicCaptureError(
    [property: JsonProperty("category")] string Category,
    [property: JsonProperty("stage")] string Stage,
    [property: JsonProperty("eventName")] string EventName);
