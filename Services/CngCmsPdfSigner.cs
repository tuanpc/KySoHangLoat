using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using KySoHangLoat.WinForms.Models;
using PdfSharp.Pdf.Signatures;

namespace KySoHangLoat.WinForms.Services;

/// <summary>
/// Creates detached CMS signatures with the RSA key exposed by a CNG/KSP certificate.
/// The private-key handle is deferred until PDFsharp requests the final ByteRange signature.
/// </summary>
internal sealed class CngCmsPdfSigner : IDigitalSigner, ITimestampAwareSigner, IDisposable
{
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    private readonly X509Certificate2 _certificate;
    private readonly CmsTimestampService? _timestampService;
    private readonly string? _tsaUrl;
    private RSA? _privateKey;
    private bool _disposed;

    public CngCmsPdfSigner(X509Certificate2 certificate, string? tsaUrl = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        _certificate = certificate;
        _tsaUrl = string.IsNullOrWhiteSpace(tsaUrl) ? null : tsaUrl;
        _timestampService = _tsaUrl is null ? null : new CmsTimestampService();
        CertificateName = certificate.GetNameInfo(X509NameType.SimpleName, false);
        if (string.IsNullOrWhiteSpace(CertificateName))
        {
            CertificateName = certificate.Subject;
        }
    }

    public string CertificateName { get; }
    public TimestampResult? LastTimestamp { get; private set; }

    public Task<int> GetSignatureSizeAsync()
    {
        // Do not sign PDFsharp's dummy byte just to discover the CMS length. Some KSPs prompt
        // for PIN on every operation. The final CMS is checked against this reservation below.
        return Task.FromResult(CmsTimestampService.TimestampedCmsReservationBytes);
    }

    public async Task<byte[]> GetSignatureAsync(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ThrowIfDisposed();

        using var content = new MemoryStream();
        stream.Position = 0;
        var buffer = new byte[81_920];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) != 0)
        {
            content.Write(buffer, 0, read);
        }

        if (content.Length == 0)
        {
            throw new InvalidDataException("PDFsharp không cung cấp dữ liệu ByteRange để tạo chữ ký CMS.");
        }

        LastTimestamp = null;
        var cms = CreateDetachedCms(content.ToArray());
        if (_timestampService is null || _tsaUrl is null)
        {
            EnsureFitsReservation(cms);
            return cms;
        }

        TimestampedCmsResult timestamped;
        try
        {
            timestamped = await _timestampService.AddTimestampAsync(cms, _tsaUrl, CancellationToken.None).ConfigureAwait(false);
        }
        catch (TsaTimestampException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new TsaTimestampException("Không thể lấy hoặc xác minh timestamp RFC 3161 từ TSA.", exception);
        }

        EnsureFitsReservation(timestamped.Cms);
        LastTimestamp = timestamped.Timestamp;
        return timestamped.Cms;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _privateKey?.Dispose();
        _disposed = true;
    }

    private byte[] CreateDetachedCms(byte[] content)
    {
        var cms = new SignedCms(new ContentInfo(content), detached: true);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, _certificate, GetPrivateKey())
        {
            DigestAlgorithm = new Oid(Sha256Oid),
            IncludeOption = X509IncludeOption.EndCertOnly
        };
        cms.ComputeSignature(signer, silent: false);
        return cms.Encode();
    }

    private RSA GetPrivateKey()
    {
        ThrowIfDisposed();
        return _privateKey ??= _certificate.GetRSAPrivateKey()
            ?? throw new CryptographicException("Không lấy được private key RSA từ KSP. Kiểm tra USB Token, middleware và chứng thư được chọn.");
    }

    private static void EnsureFitsReservation(byte[] cms)
    {
        if (cms.Length > CmsTimestampService.TimestampedCmsReservationBytes)
        {
            throw new CryptographicException(
                $"CMS dài {cms.Length} byte, vượt vùng /Contents đã dự trữ {CmsTimestampService.TimestampedCmsReservationBytes} byte.");
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(CngCmsPdfSigner));
    }
}
