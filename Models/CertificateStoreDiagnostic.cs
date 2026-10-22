namespace KySoHangLoat.WinForms.Models;

/// <summary>
/// Read-only explanation of how a certificate was evaluated for display.
/// A diagnostic record never asserts that a USB Token is connected or usable.
/// </summary>
internal sealed record CertificateStoreDiagnostic(
    string StoreName,
    string SubjectName,
    string Thumbprint,
    bool IsSigningStore,
    CertificateReadiness Readiness,
    string EvaluationSummary,
    string ProviderName,
    uint? ProviderType,
    uint? KeySpec,
    bool HasPrivateKey,
    bool IsUsableForSigning,
    bool IsStoreError = false);
