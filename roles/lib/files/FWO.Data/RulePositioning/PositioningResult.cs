using System.Diagnostics.CodeAnalysis;

namespace FWO.Data.RulePositioning;

/// <summary>Represents either one successful positioning value or one categorized failure.</summary>
public sealed class PositioningResult<TValue, TFailureCategory>
    where TValue : class
    where TFailureCategory : struct, Enum
{
    /// <summary>Gets whether this result contains a successful value.</summary>
    public bool IsSuccess { get; }

    /// <summary>Gets the successful value, or <see langword="null"/> for a failure.</summary>
    public TValue? Value { get; }

    /// <summary>Gets the failure category, or <see langword="null"/> for a success.</summary>
    public TFailureCategory? FailureCategory { get; }

    /// <summary>Gets an unexpected exception retained for boundary diagnostics only.</summary>
    public Exception? Exception { get; }

    /// <summary>Creates a successful result.</summary>
    private PositioningResult(TValue value)
    {
        Value = value;
        IsSuccess = true;
    }

    /// <summary>Creates a failed result.</summary>
    private PositioningResult(TFailureCategory failureCategory, Exception? exception)
    {
        FailureCategory = failureCategory;
        Exception = exception;
    }

    /// <summary>Creates a successful result containing a non-null value.</summary>
    public static PositioningResult<TValue, TFailureCategory> Success(TValue value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new PositioningResult<TValue, TFailureCategory>(value);
    }

    /// <summary>Creates a failed result containing only its safe domain category.</summary>
    public static PositioningResult<TValue, TFailureCategory> Failure(TFailureCategory category) =>
        new(category, null);

    /// <summary>Creates a failed result retaining an unexpected exception for debug-only boundary logging.</summary>
    public static PositioningResult<TValue, TFailureCategory> Failure(
        TFailureCategory category,
        Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return new PositioningResult<TValue, TFailureCategory>(category, exception);
    }

    /// <summary>Tries to get the successful value.</summary>
    public bool TryGetValue([NotNullWhen(true)] out TValue? value)
    {
        value = Value;
        return IsSuccess;
    }

    /// <summary>Tries to get the failure category.</summary>
    public bool TryGetFailure(out TFailureCategory category)
    {
        if (FailureCategory.HasValue)
        {
            category = FailureCategory.Value;
            return true;
        }

        category = default;
        return false;
    }
}
