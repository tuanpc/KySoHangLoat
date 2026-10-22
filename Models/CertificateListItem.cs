using System.Security.Cryptography.X509Certificates;

namespace KySoHangLoat.WinForms.Models;

internal enum TokenVerificationStatus
{
    HardwareVerified,
    SoftwareVerified,
    Unverified,
    PrivateKeyUnavailable
}

internal enum ProviderLinkStatus
{
    SmartCardProviderLinked,
    SoftwareProviderLinked,
    ProviderLinkedUnclassified,
    NoProviderMetadata
}

internal enum CertificateReadiness
{
    Ready,
    Warning,
    Unknown
}

internal sealed record KeyStorageInfo(
    string KeyType,
    string ProviderName,
    string ContainerName,
    uint? ProviderType,
    uint? KeySpec,
    ProviderLinkStatus ProviderLinkStatus,
    TokenVerificationStatus VerificationStatus,
    bool? IsAccessible,
    bool? IsRemovable,
    string Detail);

internal sealed record CertificateListItem(
    X509Certificate2 Certificate,
    string StoreName,
    string SubjectName,
    string IssuerName,
    DateTime NotBefore,
    DateTime NotAfter,
    bool HasPrivateKey,
    bool AllowsDigitalSignature,
    bool IsUsableForSigning,
    KeyStorageInfo KeyStorage)
{
    public bool IsCurrentlyValid => NotBefore <= DateTime.Now && NotAfter >= DateTime.Now;

    public IReadOnlyList<string> EvaluationReasons
    {
        get
        {
            var reasons = new List<string>();
            var now = DateTime.Now;
            if (now < NotBefore)
            {
                reasons.Add($"Chứng thư chưa có hiệu lực đến {NotBefore:yyyy-MM-dd}.");
            }
            if (now > NotAfter)
            {
                reasons.Add($"Chứng thư đã hết hạn từ {NotAfter:yyyy-MM-dd}.");
            }
            if (!HasPrivateKey)
            {
                reasons.Add("Windows Certificate Store không liên kết khóa riêng.");
            }
            if (!AllowsDigitalSignature)
            {
                reasons.Add("Key Usage không có DigitalSignature hoặc NonRepudiation.");
            }
            if (KeyStorage.ProviderLinkStatus == ProviderLinkStatus.SoftwareProviderLinked)
            {
                reasons.Add("Metadata provider cho biết khóa phần mềm; ứng dụng không dùng để ký USB Token.");
            }
            return reasons;
        }
    }

    public CertificateReadiness InitialReadiness => EvaluationReasons.Count > 0
        ? CertificateReadiness.Warning
        : HasSupportedSignerPath
            ? CertificateReadiness.Ready
            : CertificateReadiness.Unknown;

    // Legacy CSP metadata uses a non-zero provider type and AT_SIGNATURE/AT_KEYEXCHANGE.
    // A zero or CERT_NCRYPT_KEY_SPEC value belongs to the KSP/CNG form and needs its own signer path.
    public bool UsesCngKeyStorage => KeyStorage.ProviderType is 0
        || KeyStorage.KeySpec is 0 or uint.MaxValue;

    public bool UsesLegacyCspKeyStorage => KeyStorage.ProviderType is > 0
        && KeyStorage.KeySpec is > 0 and not uint.MaxValue;

    // This establishes only that the application's signer branch matches the metadata. It does
    // not establish that a token is connected, that a PIN is available, or that a signature will succeed.
    public bool HasSupportedSignerPath => IsRsaCertificate &&
        ((UsesLegacyCspKeyStorage && KeyStorage.ProviderLinkStatus == ProviderLinkStatus.SmartCardProviderLinked)
            || (UsesCngKeyStorage && KeyStorage.ProviderLinkStatus == ProviderLinkStatus.SmartCardProviderLinked));

    private bool IsRsaCertificate => string.Equals(
        Certificate.PublicKey.Oid.Value,
        "1.2.840.113549.1.1.1",
        StringComparison.Ordinal);

    public string ReadinessText => InitialReadiness switch
    {
        CertificateReadiness.Ready when UsesCngKeyStorage => "Sẵn sàng thử ký",
        CertificateReadiness.Ready => "Đủ điều kiện kiểm tra ban đầu",
        CertificateReadiness.Warning => "Không đủ điều kiện ký",
        _ => "Chưa xác định khả năng ký"
    };

    // Only explicit software-provider metadata is hidden from the compact default list.
    // Validity, Key Usage, Subject and issuer never determine default visibility.
    public bool IsPreferredForDefaultList => KeyStorage.ProviderLinkStatus is not ProviderLinkStatus.SoftwareProviderLinked;

    public string DisplayText => $"{SubjectName} · {ReadinessText}";
}
