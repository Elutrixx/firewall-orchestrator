using System.Collections.ObjectModel;
using System.Text;
using Newtonsoft.Json;

namespace FWO.Services.RulePositioning.Diagnostics;

/// <summary>Creates lossless string evidence for temporary rule-positioning diagnostics.</summary>
internal static class RulePositioningForensicStringProjection
{
    /// <summary>Projects one value without normalizing away diagnostic evidence.</summary>
    internal static RulePositioningForensicStringValue Project(string? value)
    {
        string text = value ?? string.Empty;
        List<int> codeUnits = text.Select(character => (int)character).ToList();
        List<int> scalars = text.EnumerateRunes().Select(rune => rune.Value).ToList();
        List<int> utf8Bytes = Encoding.UTF8.GetBytes(text).Select(item => (int)item).ToList();
        return new RulePositioningForensicStringValue(
            value == null,
            value,
            value?.Trim(),
            value?.ToUpperInvariant(),
            text.Length,
            new ReadOnlyCollection<int>(codeUnits),
            new ReadOnlyCollection<int>(scalars),
            new ReadOnlyCollection<int>(utf8Bytes));
    }

    /// <summary>Compares two values ordinally and identifies their first UTF-16 difference.</summary>
    internal static RulePositioningForensicStringComparison Compare(string? expected, string? actual)
    {
        RulePositioningForensicStringValue expectedProjection = Project(expected);
        RulePositioningForensicStringValue actualProjection = Project(actual);
        bool ordinalEqual = string.Equals(expected, actual, StringComparison.Ordinal);
        int? differenceIndex = ordinalEqual ? null : FirstDifferenceIndex(expected, actual);
        return new RulePositioningForensicStringComparison(
            expectedProjection,
            actualProjection,
            ordinalEqual,
            differenceIndex,
            CodeUnitAt(expected, differenceIndex),
            CodeUnitAt(actual, differenceIndex));
    }

    private static int FirstDifferenceIndex(string? expected, string? actual)
    {
        string expectedText = expected ?? string.Empty;
        string actualText = actual ?? string.Empty;
        int commonLength = Math.Min(expectedText.Length, actualText.Length);
        for (int index = 0; index < commonLength; index++)
        {
            if (expectedText[index] != actualText[index])
            {
                return index;
            }
        }
        return commonLength;
    }

    private static int? CodeUnitAt(string? value, int? index)
    {
        return index.HasValue && value != null && index.Value < value.Length
            ? value[index.Value]
            : null;
    }
}

/// <summary>Lossless representations of one string.</summary>
internal sealed record RulePositioningForensicStringValue(
    [property: JsonProperty("isNull")] bool IsNull,
    [property: JsonProperty("raw")] string? Raw,
    [property: JsonProperty("trimmed")] string? Trimmed,
    [property: JsonProperty("invariantUppercase")] string? InvariantUppercase,
    [property: JsonProperty("utf16Length")] int Utf16Length,
    [property: JsonProperty("utf16CodeUnits")] IReadOnlyList<int> Utf16CodeUnits,
    [property: JsonProperty("unicodeScalarValues")] IReadOnlyList<int> UnicodeScalarValues,
    [property: JsonProperty("utf8Bytes")] IReadOnlyList<int> Utf8Bytes);

/// <summary>Ordinal comparison plus lossless evidence for both values.</summary>
internal sealed record RulePositioningForensicStringComparison(
    [property: JsonProperty("expected")] RulePositioningForensicStringValue Expected,
    [property: JsonProperty("actual")] RulePositioningForensicStringValue Actual,
    [property: JsonProperty("ordinalEqual")] bool OrdinalEqual,
    [property: JsonProperty("firstDifferingUtf16Index")] int? FirstDifferingUtf16Index,
    [property: JsonProperty("expectedCodeUnitAtDifference")] int? ExpectedCodeUnitAtDifference,
    [property: JsonProperty("actualCodeUnitAtDifference")] int? ActualCodeUnitAtDifference);
