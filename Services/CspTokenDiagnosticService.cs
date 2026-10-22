using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KySoHangLoat.WinForms.Models;

namespace KySoHangLoat.WinForms.Services;

internal sealed class CspTokenDiagnosticService
{
    private static readonly byte[] ProbeData = "KySoHangLoat.CspTokenDiagnostic.v1"u8.ToArray();

    public void CheckSigning(CertificateListItem certificate, Action<string> report)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(report);

        var key = certificate.KeyStorage;
        if (!certificate.HasPrivateKey || key.ProviderType is null || key.KeySpec is null
            || string.IsNullOrWhiteSpace(key.ProviderName) || string.IsNullOrWhiteSpace(key.ContainerName)
            || key.ProviderName.StartsWith("Không có", StringComparison.Ordinal))
        {
            throw new CspDiagnosticException("Đọc metadata CSP", new InvalidOperationException(
                "Chứng thư không có đủ ProviderName, ContainerName, ProviderType và KeySpec để mở CSP hiện có."));
        }

        if (key.ProviderType > int.MaxValue || key.KeySpec > int.MaxValue)
        {
            throw new CspDiagnosticException("Đọc metadata CSP", new InvalidOperationException("ProviderType hoặc KeySpec nằm ngoài miền CSP hợp lệ."));
        }

        var stage = "Mở CSP hiện có";
        try
        {
            report("Kiểm tra Token: mở CSP hiện có theo ProviderName, ContainerName, ProviderType và KeySpec.");
            var parameters = new CspParameters((int)key.ProviderType, key.ProviderName, key.ContainerName)
            {
                KeyNumber = (int)key.KeySpec,
                Flags = CspProviderFlags.UseExistingKey
            };

            using var privateKey = new RSACryptoServiceProvider(parameters);

            stage = "Truy cập khóa CSP";
            report("Kiểm tra Token: đã yêu cầu truy cập khóa CSP hiện có; middleware có thể yêu cầu PIN tại đây hoặc khi ký.");
            _ = privateKey.KeySize;

            stage = "Ký SHA-256 bằng CSP";
            report("Kiểm tra Token: ký SHA-256 trên dữ liệu thử nghiệm cố định, không chứa dữ liệu PDF hay PIN.");
            var signature = privateKey.SignData(ProbeData, CryptoConfig.MapNameToOID("SHA256")!);

            stage = "Xác minh bằng public key chứng thư";
            report("Kiểm tra Token: xác minh chữ ký bằng public key của chứng thư.");
            using var publicKey = certificate.Certificate.GetRSAPublicKey()
                ?? throw new CryptographicException("Chứng thư không cung cấp RSA public key.");
            if (!publicKey.VerifyData(ProbeData, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
            {
                throw new CryptographicException("Chữ ký CSP không xác minh được bằng public key của chứng thư.");
            }

            report("Kiểm tra Token: thành công. Không lưu chữ ký thử nghiệm.");
        }
        catch (CspDiagnosticException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new CspDiagnosticException(stage, exception);
        }
    }
}

internal sealed class CspDiagnosticException(string stage, Exception innerException) : Exception($"Lỗi tại giai đoạn: {stage}.", innerException)
{
    public string Stage { get; } = stage;
}
