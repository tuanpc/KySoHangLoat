using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using KySoHangLoat.WinForms.Models;
using PdfSharp.Pdf.Signatures;

namespace KySoHangLoat.WinForms.Services;

/// <summary>
/// Creates detached CMS signatures with an explicitly opened legacy CSP key.
/// This avoids SignedCms selecting the certificate private key through CNG.
/// </summary>
internal sealed class CspCmsPdfSigner : IDigitalSigner, ITimestampAwareSigner, IDisposable
{
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    private readonly X509Certificate2 _certificate;
    private readonly RSACryptoServiceProvider _privateKey;
    private readonly CmsTimestampService? _timestampService;
    private readonly string? _tsaUrl;
    private int? _signatureSize;

    public CspCmsPdfSigner(X509Certificate2 certificate, KeyStorageInfo keyStorage, string? tsaUrl = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(keyStorage);
        _certificate = certificate;
        _privateKey = OpenExistingCspKey(keyStorage);
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
        // Timestamp tokens vary in size. Reserve a bounded byte capacity instead of requesting a TSA
        // token, or repeatedly opening the Token, just to sign PDFsharp's dummy content.
        _signatureSize ??= _timestampService is null
            ? CreateDetachedCms([0]).Length
            : CmsTimestampService.TimestampedCmsReservationBytes;
        return Task.FromResult(_signatureSize.Value);
    }

    public async Task<byte[]> GetSignatureAsync(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using var content = new MemoryStream();
        // PDFsharp supplies a RangedStream. Its CanSeek getter intentionally throws, while
        // Stream.CopyToAsync reads that property to choose its buffer size. RangedStream
        // exposes its signed ranges through its synchronous Read implementation. It is
        // handed to the signer after PDFsharp has written the document, so rewind it
        // explicitly without querying CanSeek.
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

        if (timestamped.Cms.Length > _signatureSize.GetValueOrDefault(CmsTimestampService.TimestampedCmsReservationBytes))
        {
            throw new TsaTimestampException(
                $"CMS có timestamp dài {timestamped.Cms.Length} byte, vượt vùng /Contents đã dự trữ {_signatureSize} byte.");
        }

        LastTimestamp = timestamped.Timestamp;
        return timestamped.Cms;
    }

    public void Dispose() => _privateKey.Dispose();

    private byte[] CreateDetachedCms(byte[] content)
    {
        var cms = new SignedCms(new ContentInfo(content), detached: true);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, _certificate, _privateKey)
        {
            DigestAlgorithm = new Oid(Sha256Oid),
            IncludeOption = X509IncludeOption.EndCertOnly
        };
        cms.ComputeSignature(signer, silent: false);
        return cms.Encode();
    }

    private static RSACryptoServiceProvider OpenExistingCspKey(KeyStorageInfo keyStorage)
    {
        if (keyStorage.ProviderType is null || keyStorage.KeySpec is null
            || string.IsNullOrWhiteSpace(keyStorage.ProviderName)
            || string.IsNullOrWhiteSpace(keyStorage.ContainerName)
            || keyStorage.ProviderName.StartsWith("Không có", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Không có đủ metadata CSP để mở private key hiện có.");
        }

        if (keyStorage.ProviderType > int.MaxValue || keyStorage.KeySpec > int.MaxValue)
        {
            throw new InvalidOperationException("ProviderType hoặc KeySpec không hợp lệ cho CspParameters.");
        }

        var parameters = new CspParameters((int)keyStorage.ProviderType, keyStorage.ProviderName, keyStorage.ContainerName)
        {
            KeyNumber = (int)keyStorage.KeySpec,
            Flags = CspProviderFlags.UseExistingKey
        };
        return new RSACryptoServiceProvider(parameters);
    }
}
