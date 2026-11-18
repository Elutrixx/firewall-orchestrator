namespace FWO.Data.RulePositioning;

/// <summary>Bounded technical detail retained for middleware diagnostics.</summary>
public sealed class RulePositioningFailureDetail
{
    private const int kMaxLogSummaryLength = 512;

    /// <summary>Gets the calculation stage that produced the failure.</summary>
    public string Stage { get; }
    /// <summary>Gets the most specific available failure category.</summary>
    public string SpecificCategory { get; }
    /// <summary>Gets the concise technical diagnostic.</summary>
    public string Diagnostic { get; }
    /// <summary>Gets the originating positioning block kind, when applicable.</summary>
    public string? OriginatingBlockKind { get; }
    /// <summary>Gets the unexpected exception retained for debug output only.</summary>
    public Exception? Exception { get; }

    private RulePositioningFailureDetail(
        string stage,
        string specificCategory,
        string diagnostic,
        string? originatingBlockKind,
        Exception? exception)
    {
        Stage = NormalizeRequired(stage, nameof(stage));
        SpecificCategory = NormalizeRequired(specificCategory, nameof(specificCategory));
        Diagnostic = NormalizeRequired(diagnostic, nameof(diagnostic));
        OriginatingBlockKind = NormalizeOptional(originatingBlockKind);
        Exception = exception;
    }

    /// <summary>Creates detail for an expected typed calculation failure.</summary>
    public static RulePositioningFailureDetail ForKnownFailure(
        string stage,
        Enum specificCategory,
        string diagnostic,
        string? originatingBlockKind = null,
        Exception? exception = null)
    {
        ArgumentNullException.ThrowIfNull(specificCategory);
        return new RulePositioningFailureDetail(
            stage,
            specificCategory.ToString(),
            diagnostic,
            originatingBlockKind,
            exception);
    }

    /// <summary>Creates detail for an unexpected exception without expanding its stack in normal logs.</summary>
    public static RulePositioningFailureDetail ForUnexpectedException(
        string stage,
        Exception exception,
        string? originatingBlockKind = null)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return new RulePositioningFailureDetail(
            stage,
            exception.GetType().Name,
            "An unexpected exception interrupted rule-position calculation.",
            originatingBlockKind,
            exception);
    }

    /// <summary>Formats one bounded, single-line summary for the normal middleware log.</summary>
    public string ToLogSummary()
    {
        string block = OriginatingBlockKind == null ? "" : $" / {OriginatingBlockKind}";
        string summary = $"{Stage}{block} / {SpecificCategory}: {Diagnostic}";
        return summary.Length <= kMaxLogSummaryLength
            ? summary
            : summary[..kMaxLogSummaryLength];
    }

    private static string NormalizeRequired(string value, string parameterName)
    {
        string normalized = NormalizeOptional(value) ?? "";
        return normalized.Length > 0
            ? normalized
            : throw new ArgumentException("Diagnostic fields must not be empty.", parameterName);
    }

    private static string? NormalizeOptional(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? null
            : string.Join(' ', value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
    }
}
