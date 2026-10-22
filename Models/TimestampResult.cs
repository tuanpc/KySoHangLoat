namespace KySoHangLoat.WinForms.Models;

internal enum TsaTrustStatus
{
    TrustedByWindows,
    NotTrustedByWindows,
    TrustCouldNotBeEvaluated
}

/// <summary>
/// Technical token validity is independent from the local Windows trust decision.
/// </summary>
internal sealed record TimestampResult(
    DateTimeOffset GeneratedAt,
    string TsaSubject,
    string TsaUrl,
    TsaTrustStatus TrustStatus,
    string TrustDetails);
