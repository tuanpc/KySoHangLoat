using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using KySoHangLoat.WinForms.Models;

namespace KySoHangLoat.WinForms.Services;

internal sealed class CertificateStoreService
{
    public IReadOnlyList<CertificateListItem> ListSigningCertificates()
    {
        var certificates = new List<CertificateListItem>();
        AddFromStore(certificates, StoreLocation.CurrentUser, "CurrentUser\\My");

        return certificates
            .OrderBy(item => item.KeyStorage.VerificationStatus switch
            {
                TokenVerificationStatus.HardwareVerified => 0,
                TokenVerificationStatus.Unverified => 1,
                TokenVerificationStatus.SoftwareVerified => 2,
                _ => 3
            })
            .ThenBy(item => item.SubjectName, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(item => item.NotAfter)
            .ToArray();
    }

    /// <summary>
    /// Reads certificate metadata from both Personal stores without opening a private-key handle.
    /// CurrentUser\My remains the signing scope; LocalMachine\My is diagnostic only.
    /// </summary>
    public IReadOnlyList<CertificateStoreDiagnostic> DiagnosePersonalStores()
    {
        var diagnostics = new List<CertificateStoreDiagnostic>();
        AddDiagnostics(diagnostics, StoreLocation.CurrentUser, "CurrentUser\\My", isSigningStore: true);
        AddDiagnostics(diagnostics, StoreLocation.LocalMachine, "LocalMachine\\My", isSigningStore: false);
        return diagnostics;
    }

    public CertificateListItem Revalidate(CertificateListItem selected)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        var current = store.Certificates
            .Find(X509FindType.FindByThumbprint, selected.Certificate.Thumbprint, validOnly: false)
            .OfType<X509Certificate2>()
            .FirstOrDefault();

        if (current is null)
        {
            throw new InvalidOperationException("Chứng thư không còn trong CurrentUser\\My. Token có thể đã bị rút hoặc middleware không sẵn sàng.");
        }

        var item = CreateItem(current, "CurrentUser\\My");
        if (!item.IsCurrentlyValid || !item.IsUsableForSigning)
        {
            throw new InvalidOperationException("Chứng thư không còn hiệu lực, không có khóa riêng hoặc không có mục đích ký số.");
        }

        if (item.KeyStorage.VerificationStatus == TokenVerificationStatus.PrivateKeyUnavailable)
        {
            throw new InvalidOperationException("Windows Certificate Store không còn khóa riêng cho chứng thư. Kiểm tra USB Token và middleware.");
        }

        return item;
    }

    private static void AddFromStore(List<CertificateListItem> destination, StoreLocation location, string storeName)
    {
        using var store = new X509Store(StoreName.My, location);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        foreach (var certificate in store.Certificates)
        {
            destination.Add(CreateItem(certificate, storeName));
        }
    }

    private static void AddDiagnostics(
        List<CertificateStoreDiagnostic> destination,
        StoreLocation location,
        string storeName,
        bool isSigningStore)
    {
        try
        {
            using var store = new X509Store(StoreName.My, location);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            foreach (var certificate in store.Certificates)
            {
                var item = CreateItem(certificate, storeName);
                destination.Add(new CertificateStoreDiagnostic(
                    storeName,
                    item.SubjectName,
                    item.Certificate.Thumbprint ?? string.Empty,
                    isSigningStore,
                    item.InitialReadiness,
                    GetEvaluationSummary(item),
                    item.KeyStorage.ProviderName,
                    item.KeyStorage.ProviderType,
                    item.KeyStorage.KeySpec,
                    item.HasPrivateKey,
                    item.IsUsableForSigning));
            }
        }
        catch (Exception exception)
        {
            destination.Add(new CertificateStoreDiagnostic(
                storeName,
                "(không thể đọc kho)",
                string.Empty,
                isSigningStore,
                CertificateReadiness.Unknown,
                $"Không thể mở kho chỉ đọc: {exception.GetType().Name}; {exception.Message}",
                string.Empty,
                null,
                null,
                false,
                false,
                IsStoreError: true));
        }
    }

    private static CertificateListItem CreateItem(X509Certificate2 certificate, string storeName)
    {
        var subject = GetName(certificate, X509NameType.SimpleName, false, certificate.Subject);
        var issuer = GetName(certificate, X509NameType.SimpleName, true, certificate.Issuer);
        var hasPrivateKey = certificate.HasPrivateKey;
        var storage = CreateSafeKeyStorageInfo(certificate, hasPrivateKey);

        return new CertificateListItem(
            certificate,
            storeName,
            subject,
            issuer,
            certificate.NotBefore,
            certificate.NotAfter,
            hasPrivateKey,
            AllowsDigitalSignature(certificate),
            hasPrivateKey && AllowsDigitalSignature(certificate),
            storage);
    }

    private static string GetName(X509Certificate2 certificate, X509NameType nameType, bool forIssuer, string fallback)
    {
        var name = certificate.GetNameInfo(nameType, forIssuer);
        return string.IsNullOrWhiteSpace(name) ? fallback : name;
    }

    private static KeyStorageInfo CreateSafeKeyStorageInfo(X509Certificate2 certificate, bool hasPrivateKey)
    {
        if (!hasPrivateKey)
        {
            return new KeyStorageInfo("Không có", "Không có", "Không có", null, null, ProviderLinkStatus.NoProviderMetadata, TokenVerificationStatus.PrivateKeyUnavailable, false, null,
                "Windows Certificate Store không có khóa riêng cho chứng thư này.");
        }

        var algorithm = certificate.PublicKey.Oid.FriendlyName ?? certificate.PublicKey.Oid.Value ?? "Không xác định";
        if (TryReadKeyProviderInfo(certificate, out var providerInfo, out var error))
        {
            var linkStatus = ClassifyProvider(providerInfo.ProviderName);
            return new KeyStorageInfo(
                algorithm,
                providerInfo.ProviderName,
                providerInfo.ContainerName,
                providerInfo.ProviderType,
                providerInfo.KeySpec,
                linkStatus,
                TokenVerificationStatus.Unverified,
                null,
                null,
                $"Đã đọc CERT_KEY_PROV_INFO_PROP_ID từ Certificate Store; không mở private-key handle. {DescribeProviderLink(linkStatus)}");
        }

        return new KeyStorageInfo(
            algorithm,
            "Không có CERT_KEY_PROV_INFO",
            "Không có",
            null,
            null,
            ProviderLinkStatus.NoProviderMetadata,
            TokenVerificationStatus.Unverified,
            null,
            null,
            $"Windows Certificate Store không trả metadata provider ({error}). Trạng thái thiết bị chưa xác minh; không mở khóa riêng để kiểm tra.");
    }

    private static ProviderLinkStatus ClassifyProvider(string providerName)
    {
        // A hardware indicator takes precedence over generic CSP wording. Some token
        // middleware names contain both vendor/Smart Card text and generic RSA/AES text.
        // This is classification only, not proof that the device is currently connected.
        if (providerName.Contains("smart card", StringComparison.OrdinalIgnoreCase)
            || providerName.Contains("smartcard", StringComparison.OrdinalIgnoreCase)
            || providerName.Contains("bit4id", StringComparison.OrdinalIgnoreCase)
            || providerName.Contains("safenet", StringComparison.OrdinalIgnoreCase)
            || providerName.Contains("etoken", StringComparison.OrdinalIgnoreCase))
        {
            return ProviderLinkStatus.SmartCardProviderLinked;
        }

        if (providerName.Contains("software key storage provider", StringComparison.OrdinalIgnoreCase)
            || providerName.Contains("enhanced rsa and aes cryptographic provider", StringComparison.OrdinalIgnoreCase)
            || providerName.Contains("microsoft strong cryptographic provider", StringComparison.OrdinalIgnoreCase)
            || providerName.Contains("microsoft rsa schannel cryptographic provider", StringComparison.OrdinalIgnoreCase))
        {
            return ProviderLinkStatus.SoftwareProviderLinked;
        }

        return ProviderLinkStatus.ProviderLinkedUnclassified;
    }

    private static string DescribeProviderLink(ProviderLinkStatus status) => status switch
    {
        ProviderLinkStatus.SmartCardProviderLinked => "Liên kết Smart Card - chưa xác minh kết nối.",
        ProviderLinkStatus.SoftwareProviderLinked => "Provider cho biết khóa phần mềm.",
        ProviderLinkStatus.ProviderLinkedUnclassified => "Có provider nhưng chưa thuộc quy tắc Smart Card.",
        _ => "Không có metadata provider."
    };

    private static bool TryReadKeyProviderInfo(X509Certificate2 certificate, out NativeKeyProviderInfo info, out string error)
    {
        const uint certKeyProvInfoPropId = 2;
        uint byteCount = 0;
        if (!CertGetCertificateContextProperty(certificate.Handle, certKeyProvInfoPropId, IntPtr.Zero, ref byteCount))
        {
            info = default;
            error = $"Win32 0x{Marshal.GetLastWin32Error():X8}";
            return false;
        }

        var buffer = Marshal.AllocHGlobal(checked((int)byteCount));
        try
        {
            if (!CertGetCertificateContextProperty(certificate.Handle, certKeyProvInfoPropId, buffer, ref byteCount))
            {
                info = default;
                error = $"Win32 0x{Marshal.GetLastWin32Error():X8}";
                return false;
            }

            var native = Marshal.PtrToStructure<CryptKeyProvInfo>(buffer);
            info = new NativeKeyProviderInfo(
                Marshal.PtrToStringUni(native.ContainerName) ?? "(rỗng)",
                Marshal.PtrToStringUni(native.ProviderName) ?? "(rỗng)",
                native.ProviderType,
                native.KeySpec);
            error = string.Empty;
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptKeyProvInfo
    {
        public IntPtr ContainerName;
        public IntPtr ProviderName;
        public uint ProviderType;
        public uint Flags;
        public uint ParameterCount;
        public IntPtr Parameters;
        public uint KeySpec;
    }

    private readonly record struct NativeKeyProviderInfo(string ContainerName, string ProviderName, uint ProviderType, uint KeySpec);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertGetCertificateContextProperty(
        IntPtr certificateContext,
        uint propertyId,
        IntPtr data,
        ref uint dataSize);

    private static bool AllowsDigitalSignature(X509Certificate2 certificate)
    {
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (usage is null)
        {
            return true;
        }

        const X509KeyUsageFlags accepted = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation;
        return (usage.KeyUsages & accepted) != 0;
    }

    private static string GetEvaluationSummary(CertificateListItem item)
    {
        if (item.EvaluationReasons.Count > 0)
        {
            return string.Join(" ", item.EvaluationReasons);
        }

        return item.InitialReadiness switch
        {
            CertificateReadiness.Ready => "Đủ điều kiện kiểm tra ban đầu; trạng thái Token chưa được xác minh bằng truy cập khóa riêng.",
            _ => "Metadata provider chưa đủ để xác định khả năng ký; trạng thái Token chưa được xác minh."
        };
    }
}
