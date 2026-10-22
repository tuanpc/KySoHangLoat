using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using KySoHangLoat.WinForms.Models;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;

namespace KySoHangLoat.WinForms.Services;

/// <summary>
/// Adds and verifies RFC 3161 signature timestamps without accessing the document signer's private key.
/// </summary>
internal sealed class CmsTimestampService
{
    internal const int TimestampedCmsReservationBytes = 65_536;

    private const string SignatureTimestampTokenOid = "1.2.840.113549.1.9.16.2.14";
    private const int MaximumTsaResponseBytes = 2 * 1024 * 1024;
    private static readonly HttpClient TimestampClient = new() { Timeout = TimeSpan.FromSeconds(30) };
    private static readonly Org.BouncyCastle.Asn1.DerObjectIdentifier SignatureTimestampTokenAttribute =
        new(SignatureTimestampTokenOid);

    public async Task<TimestampedCmsResult> AddTimestampAsync(
        byte[] detachedCms,
        string tsaUrl,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(detachedCms);
        ArgumentException.ThrowIfNullOrWhiteSpace(tsaUrl);

        var signedData = new CmsSignedData(detachedCms);
        var signer = GetSingleSigner(signedData);
        var signatureValue = signer.GetSignature();
        var signatureHash = SHA256.HashData(signatureValue);

        var requestGenerator = new TimeStampRequestGenerator();
        requestGenerator.SetCertReq(true);
        var nonceBytes = new byte[20];
        RandomNumberGenerator.Fill(nonceBytes);
        var request = requestGenerator.Generate(TspAlgorithms.Sha256, signatureHash, new BigInteger(1, nonceBytes));
        var responseBytes = await SendTimestampRequestAsync(tsaUrl, request.GetEncoded(), cancellationToken).ConfigureAwait(false);

        var response = new TimeStampResponse(responseBytes);
        if (response.Status != (int)PkiStatus.Granted && response.Status != (int)PkiStatus.GrantedWithMods)
        {
            var status = response.GetStatusString();
            throw new TsaTimestampException($"TSA từ chối yêu cầu RFC 3161. Mã trạng thái={response.Status}{(string.IsNullOrWhiteSpace(status) ? string.Empty : $"; {status}")}.");
        }

        response.Validate(request);
        var timestampToken = response.TimeStampToken
            ?? throw new TsaTimestampException("TSA trả trạng thái thành công nhưng không kèm timestamp token.");
        var tokenCms = timestampToken.GetEncoded(Asn1Encodable.Der);
        var verification = VerifyToken(tokenCms, signatureValue);

        var unsignedAttributes = signer.UnsignedAttributes ?? new AttributeTable(new Asn1EncodableVector());
        if (unsignedAttributes.HasAny(SignatureTimestampTokenAttribute))
        {
            throw new TsaTimestampException("CMS đã có signature timestamp token; không ghi đè token hiện có.");
        }

        var updatedUnsignedAttributes = unsignedAttributes.Add(
            SignatureTimestampTokenAttribute,
            Asn1Object.FromByteArray(tokenCms));
        var updatedSigner = SignerInformation.ReplaceUnsignedAttributes(signer, updatedUnsignedAttributes);
        var timestampedCms = CmsSignedData.ReplaceSigners(
            signedData,
            new SignerInformationStore(updatedSigner)).GetEncoded();

        VerifyEmbeddedTimestamp(timestampedCms);
        return new TimestampedCmsResult(timestampedCms, verification with { TsaUrl = tsaUrl });
    }

    public static TimestampResult VerifyEmbeddedTimestamp(byte[] detachedCms)
    {
        ArgumentNullException.ThrowIfNull(detachedCms);

        var signedData = new CmsSignedData(detachedCms);
        var signer = GetSingleSigner(signedData);
        var unsignedAttributes = signer.UnsignedAttributes;
        if (unsignedAttributes is null
            || !unsignedAttributes.TryGetFirst(SignatureTimestampTokenAttribute, out var timestampAttribute)
            || timestampAttribute.AttrValues.Count != 1)
        {
            throw new TsaTimestampException("CMS không có đúng một unsigned attribute signature timestamp token RFC 3161.");
        }

        var tokenCms = timestampAttribute.AttrValues[0].GetEncoded();
        return VerifyToken(tokenCms, signer.GetSignature());
    }

    private static SignerInformation GetSingleSigner(CmsSignedData signedData)
    {
        var signers = signedData.GetSignerInfos().GetSigners();
        if (signers.Count != 1)
        {
            throw new TsaTimestampException($"CMS phải có đúng một signer để gắn timestamp; nhận được {signers.Count} signer.");
        }

        return signers[0];
    }

    private static async Task<byte[]> SendTimestampRequestAsync(string tsaUrl, byte[] requestBytes, CancellationToken cancellationToken)
    {
        using var content = new ByteArrayContent(requestBytes);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");
        using var request = new HttpRequestMessage(HttpMethod.Post, tsaUrl) { Content = content };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/timestamp-reply"));
        using var response = await TimestampClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new TsaTimestampException($"TSA trả HTTP {(int)response.StatusCode} ({response.ReasonPhrase}).");
        }

        if (response.Content.Headers.ContentLength is long contentLength && contentLength > MaximumTsaResponseBytes)
        {
            throw new TsaTimestampException("Phản hồi TSA vượt giới hạn 2 MiB.");
        }

        await using var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var responseBuffer = new MemoryStream();
        var buffer = new byte[81_920];
        while (true)
        {
            var read = await responseStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            if (responseBuffer.Length + read > MaximumTsaResponseBytes)
            {
                throw new TsaTimestampException("Phản hồi TSA vượt giới hạn 2 MiB.");
            }

            responseBuffer.Write(buffer, 0, read);
        }

        return responseBuffer.ToArray();
    }

    private static TimestampResult VerifyToken(byte[] tokenCms, byte[] signatureValue)
    {
        if (!Rfc3161TimestampToken.TryDecode(tokenCms, out var platformToken, out var bytesConsumed)
            || platformToken is null
            || bytesConsumed != tokenCms.Length)
        {
            throw new TsaTimestampException("Timestamp token không phải DER ContentInfo RFC 3161 hợp lệ.");
        }

        if (!platformToken.VerifySignatureForData(signatureValue, out var tsaCertificate)
            || tsaCertificate is null)
        {
            throw new TsaTimestampException("Timestamp token không xác minh được chữ ký TSA, EKU time-stamping hoặc message imprint.");
        }

        using (tsaCertificate)
        {
            // VerifySignatureForData has already made the technical checks mandatory: token
            // structure, TSA signature, RFC 3161 time-stamping EKU, and the imprint of the
            // document CMS signatureValue. Windows chain trust is reported separately so an
            // internal TSA can still be used without importing its CA into Windows.
            var trust = EvaluateTsaTrust(platformToken, tsaCertificate);
            return new TimestampResult(
                platformToken.TokenInfo.Timestamp,
                tsaCertificate.Subject,
                string.Empty,
                trust.Status,
                trust.Details);
        }
    }

    private static TsaTrustEvaluation EvaluateTsaTrust(Rfc3161TimestampToken timestampToken, X509Certificate2 tsaCertificate)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = timestampToken.TokenInfo.Timestamp.LocalDateTime;
            chain.ChainPolicy.ExtraStore.AddRange(timestampToken.AsSignedCms().Certificates);
            if (chain.Build(tsaCertificate))
            {
                return new TsaTrustEvaluation(TsaTrustStatus.TrustedByWindows, "Chuỗi TSA được Windows tin cậy tại genTime.");
            }

            var statuses = string.Join("; ", chain.ChainStatus
                .Select(status => $"{status.Status}: {status.StatusInformation.Trim()}")
                .Where(status => !string.IsNullOrWhiteSpace(status)));
            return new TsaTrustEvaluation(
                TsaTrustStatus.NotTrustedByWindows,
                string.IsNullOrWhiteSpace(statuses)
                    ? "Windows không xây dựng được chuỗi tin cậy TSA tại genTime."
                    : $"Windows không tin cậy chuỗi TSA tại genTime: {statuses}");
        }
        catch (Exception exception) when (exception is CryptographicException or InvalidOperationException)
        {
            return new TsaTrustEvaluation(
                TsaTrustStatus.TrustCouldNotBeEvaluated,
                $"Không đánh giá được trust chain TSA: {exception.Message}");
        }
    }
}

internal sealed record TimestampedCmsResult(byte[] Cms, TimestampResult Timestamp);
internal sealed record TsaTrustEvaluation(TsaTrustStatus Status, string Details);

internal sealed class TsaTimestampException : CryptographicException
{
    public TsaTimestampException(string message) : base(message)
    {
    }

    public TsaTimestampException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
