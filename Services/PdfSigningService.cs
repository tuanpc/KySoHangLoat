using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using KySoHangLoat.WinForms.Models;
using PdfSharp.Drawing;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;
using PdfSharp.Pdf.Signatures;

namespace KySoHangLoat.WinForms.Services;

internal sealed class PdfSigningService
{
    private const double SignatureMarginPoints = 8;

    public SigningSession CreateSession(CertificateListItem certificateItem, bool useTsaTimestamp, string tsaUrl)
    {
        ArgumentNullException.ThrowIfNull(certificateItem);
        if (!certificateItem.HasPrivateKey)
        {
            throw new InvalidOperationException("Chứng thư được chọn không có khóa riêng khả dụng trong Windows Certificate Store.");
        }

        try
        {
            if (certificateItem.UsesLegacyCspKeyStorage)
            {
                return new SigningSession(
                    new CspCmsPdfSigner(
                        certificateItem.Certificate,
                        certificateItem.KeyStorage,
                        useTsaTimestamp ? tsaUrl : null),
                    certificateItem.Certificate.Subject,
                    useTsaTimestamp);
            }

            if (certificateItem.UsesCngKeyStorage && certificateItem.HasSupportedSignerPath)
            {
                return new SigningSession(
                    new CngCmsPdfSigner(certificateItem.Certificate, useTsaTimestamp ? tsaUrl : null),
                    certificateItem.Certificate.Subject,
                    useTsaTimestamp);
            }

            if (useTsaTimestamp)
            {
                throw new NotSupportedException("Không nhận diện được nhánh CSP hoặc CNG/KSP được hỗ trợ cho chứng thư này.");
            }

            return new SigningSession(
                new PdfSharpDefaultSigner(certificateItem.Certificate, PdfMessageDigestType.SHA256),
                certificateItem.Certificate.Subject,
                timestampingEnabled: false);
        }
        catch (Exception exception)
        {
            throw new SigningStageException("Khởi tạo bộ ký PDF/CSP", exception);
        }
    }

    public async Task<SigningResult> SignAsync(
        string sourcePath,
        string outputDirectory,
        SigningSession session,
        string displayName,
        bool uppercaseSignatureText,
        bool addSignedSuffix,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

        cancellationToken.ThrowIfCancellationRequested();
        Directory.CreateDirectory(outputDirectory);
        var started = Stopwatch.StartNew();
        var signedAt = DateTimeOffset.MinValue;
        var temporaryPath = string.Empty;

        try
        {
            try
            {
                // Saving through PDFsharp rewrites the document. Do not enter Modify mode for a
                // PDF that may already contain a signature revision.
                PdfExistingSignatureDetector.EnsureSafeToModify(sourcePath);
            }
            catch (PdfSignatureProtectionException)
            {
                throw;
            }
            catch (Exception exception)
            {
                throw new SigningStageException("Kiểm tra chữ ký số có sẵn trong PDF nguồn", exception);
            }

            PdfDocument document;
            try
            {
                document = PdfReader.Open(sourcePath, PdfDocumentOpenMode.Modify);
            }
            catch (Exception exception)
            {
                throw new SigningStageException("Mở PDF nguồn", exception);
            }

            using (document)
            {
            if (document.PageCount == 0)
            {
                throw new InvalidDataException("PDF không có trang để ký.");
            }

            var page = document.Pages[0];
            // Keep the displayed time as close as possible to PDFsharp's signature-dictionary creation.
            signedAt = DateTimeOffset.Now;
            var appearance = SaoYAppearanceHandler.Create(
                displayName,
                signedAt,
                uppercaseSignatureText,
                new XSize(page.Width.Point, page.Height.Point));
            var requiredSize = appearance.GetRequiredSize();
            if (requiredSize.Width + SignatureMarginPoints * 2 > page.Width.Point
                || requiredSize.Height + SignatureMarginPoints * 2 > page.Height.Point)
            {
                throw new InvalidDataException("Trang PDF không đủ chỗ cho dòng chữ ký SAO Y Times New Roman 12 pt.");
            }

            // PDF default-page coordinates start at the bottom-left. The field itself is sized to the text only.
            var rectangle = new XRect(
                page.Width.Point - SignatureMarginPoints - requiredSize.Width,
                page.Height.Point - SignatureMarginPoints - requiredSize.Height,
                requiredSize.Width,
                requiredSize.Height);

            var options = new DigitalSignatureOptions
            {
                // Omit optional metadata entirely; Subject/Issuer must not be repurposed as contact information.
                AppName = "KySoHangLoat",
                PageIndex = 0,
                Rectangle = rectangle,
                AppearanceHandler = appearance
            };

                try
                {
                    _ = DigitalSignatureHandler.ForDocument(
                        document,
                        session.Signer,
                        options);
                }
                catch (Exception exception)
                {
                    throw new SigningStageException("Tạo signature field và appearance", exception);
                }

                temporaryPath = Path.Combine(outputDirectory, $".{Guid.NewGuid():N}.signing");
                try
                {
                    await using var temporaryStream = new FileStream(
                        temporaryPath,
                        FileMode.CreateNew,
                        FileAccess.ReadWrite,
                        FileShare.None,
                        bufferSize: 4096,
                        useAsync: true);
                    await document.SaveAsync(temporaryStream, closeStream: false).ConfigureAwait(true);
                    await temporaryStream.FlushAsync(cancellationToken).ConfigureAwait(true);
                }
                catch (Exception exception)
                {
                    throw new SigningStageException("PDFsharp SaveAsync: dummy signing hoặc ký CMS bằng CSP", exception);
                }
            }

            // Saving is not proof of a valid signature. Verify the detached CMS against the PDF ByteRange first.
            try
            {
                PdfSignatureVerifier.VerifyIntegrity(temporaryPath);
            }
            catch (Exception exception)
            {
                throw new SigningStageException("Xác minh CMS/ByteRange PDF đầu ra", exception);
            }

            SignatureAppearanceVerification appearanceVerification;
            try
            {
                appearanceVerification = PdfSignatureVerifier.VerifySignatureAppearance(temporaryPath);
            }
            catch (Exception exception)
            {
                throw new SigningStageException("Xác minh signature widget và appearance PDF đầu ra", exception);
            }

            TimestampResult? timestamp = null;
            if (session.TimestampingEnabled)
            {
                try
                {
                    PdfSignatureVerifier.VerifyTimestamp(temporaryPath);
                    timestamp = (session.Signer as ITimestampAwareSigner)?.LastTimestamp
                        ?? throw new TsaTimestampException("PDF có timestamp nhưng bộ ký không trả trạng thái TSA cho file hiện tại.");
                }
                catch (Exception exception)
                {
                    throw new SigningStageException("Xác minh timestamp RFC 3161 của PDF đầu ra", exception);
                }
            }

            string outputPath;
            try
            {
                outputPath = MoveToExclusiveOutput(temporaryPath, outputDirectory, sourcePath, addSignedSuffix);
            }
            catch (Exception exception)
            {
                throw new SigningStageException("Đổi tên PDF đã xác minh", exception);
            }
            temporaryPath = string.Empty;
            started.Stop();

            return new SigningResult(sourcePath, outputPath, signedAt, started.Elapsed, appearanceVerification, timestamp);
        }
        catch
        {
            if (!string.IsNullOrWhiteSpace(temporaryPath))
            {
                TryDelete(temporaryPath);
            }
            throw;
        }
    }

    private static string MoveToExclusiveOutput(string temporaryPath, string outputDirectory, string sourcePath, bool addSignedSuffix)
    {
        var stem = Path.GetFileNameWithoutExtension(sourcePath);
        if (addSignedSuffix && !stem.EndsWith(".signed", StringComparison.OrdinalIgnoreCase))
        {
            stem += ".signed";
        }

        for (var index = 0; index < 10_000; index++)
        {
            var name = index == 0 ? $"{stem}.pdf" : $"{stem} ({index}).pdf";
            var path = Path.Combine(outputDirectory, name);
            try
            {
                File.Move(temporaryPath, path, overwrite: false);
                return path;
            }
            catch (IOException) when (File.Exists(path))
            {
                // Another process used the candidate name; keep the verified temporary file and try the next name.
            }
        }

        throw new IOException("Không thể tạo tên PDF đầu ra không trùng.");
    }

    private static void TryDelete(string outputPath)
    {
        try
        {
            if (File.Exists(outputPath))
            {
                File.Delete(outputPath);
            }
        }
        catch
        {
            // Preserve the original signing error; a partial output is never reported as success.
        }
    }

    internal sealed class SigningSession : IDisposable
    {
        internal SigningSession(IDigitalSigner signer, string certificateSubject, bool timestampingEnabled)
        {
            Signer = signer;
            CertificateSubject = certificateSubject;
            TimestampingEnabled = timestampingEnabled;
        }

        internal IDigitalSigner Signer { get; }
        internal string CertificateSubject { get; }
        internal bool TimestampingEnabled { get; }

        public void Dispose()
        {
            if (Signer is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }
}

internal sealed class SigningStageException(string stage, Exception innerException) : Exception($"Lỗi tại giai đoạn: {stage}.", innerException)
{
    public string Stage { get; } = stage;
}
