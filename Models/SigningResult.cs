namespace KySoHangLoat.WinForms.Models;

internal sealed record SigningResult(
    string SourcePath,
    string OutputPath,
    DateTimeOffset SignedAt,
    TimeSpan Elapsed,
    SignatureAppearanceVerification Appearance,
    TimestampResult? Timestamp);
