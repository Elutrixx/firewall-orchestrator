using FWO.Services.RulePositioning.Diagnostics;
using NUnit.Framework;

namespace FWO.Test;

[TestFixture]
public class RulePositioningForensicStringProjectionTest
{
    private static readonly List<int> kSupplementaryUtf16 = [65, 55357, 56832, 66];
    private static readonly List<int> kSupplementaryScalars = [65, 128512, 66];
    private static readonly List<int> kSupplementaryUtf8 = [65, 240, 159, 152, 128, 66];

    [Test]
    public void Compare_IdenticalValuesReportsEveryRepresentation()
    {
        RulePositioningForensicStringComparison comparison =
            RulePositioningForensicStringProjection.Compare("[Source] < [Destination]", "[Source] < [Destination]");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(comparison.OrdinalEqual, Is.True);
            Assert.That(comparison.FirstDifferingUtf16Index, Is.Null);
            Assert.That(comparison.Expected.Raw, Is.EqualTo("[Source] < [Destination]"));
            Assert.That(comparison.Expected.Trimmed, Is.EqualTo("[Source] < [Destination]"));
            Assert.That(comparison.Expected.InvariantUppercase, Is.EqualTo("[SOURCE] < [DESTINATION]"));
            Assert.That(comparison.Expected.Utf16Length, Is.EqualTo(24));
            Assert.That(comparison.Expected.Utf16CodeUnits, Has.Count.EqualTo(24));
            Assert.That(comparison.Expected.UnicodeScalarValues, Has.Count.EqualTo(24));
            Assert.That(comparison.Expected.Utf8Bytes, Is.EqualTo(comparison.Actual.Utf8Bytes));
        }
    }

    [TestCase("[A] < [B]", "[A] -> [B]", 4, 60, 45)]
    [TestCase("SECTION", " SECTION ", 0, 83, 32)]
    [TestCase("caf\u00E9", "cafe\u0301", 3, 233, 101)]
    [TestCase("A B", "A\u00A0B", 1, 32, 160)]
    [TestCase("AB", "A\u200BB", 1, 66, 8203)]
    [TestCase("Section", "SECTION", 1, 101, 69)]
    public void Compare_ReportsExactFirstUtf16Difference(
        string expected,
        string actual,
        int expectedIndex,
        int expectedCodeUnit,
        int actualCodeUnit)
    {
        RulePositioningForensicStringComparison comparison =
            RulePositioningForensicStringProjection.Compare(expected, actual);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(comparison.OrdinalEqual, Is.False);
            Assert.That(comparison.FirstDifferingUtf16Index, Is.EqualTo(expectedIndex));
            Assert.That(comparison.ExpectedCodeUnitAtDifference, Is.EqualTo(expectedCodeUnit));
            Assert.That(comparison.ActualCodeUnitAtDifference, Is.EqualTo(actualCodeUnit));
            Assert.That(comparison.Expected.Utf8Bytes, Is.Not.EqualTo(comparison.Actual.Utf8Bytes));
        }
    }

    [Test]
    public void Project_SupplementaryCharacterDistinguishesUtf16UnitsFromUnicodeScalars()
    {
        RulePositioningForensicStringValue value = RulePositioningForensicStringProjection.Project("A\U0001F600B");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(value.Utf16Length, Is.EqualTo(4));
            Assert.That(value.Utf16CodeUnits, Is.EqualTo(kSupplementaryUtf16));
            Assert.That(value.UnicodeScalarValues, Is.EqualTo(kSupplementaryScalars));
            Assert.That(value.Utf8Bytes, Is.EqualTo(kSupplementaryUtf8));
        }
    }

    [Test]
    public void Compare_NullAndEmptyRemainDistinctAndSerializable()
    {
        RulePositioningForensicStringComparison comparison =
            RulePositioningForensicStringProjection.Compare(null, string.Empty);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(comparison.OrdinalEqual, Is.False);
            Assert.That(comparison.Expected.IsNull, Is.True);
            Assert.That(comparison.Actual.IsNull, Is.False);
            Assert.That(comparison.FirstDifferingUtf16Index, Is.EqualTo(0));
            Assert.That(comparison.ExpectedCodeUnitAtDifference, Is.Null);
            Assert.That(comparison.ActualCodeUnitAtDifference, Is.Null);
        }
    }
}
