using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.Text.RegularExpressions;
using KySoHangLoat.WinForms.Models;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;

namespace KySoHangLoat.WinForms.Services;

internal static partial class PdfSignatureVerifier
{
    private static readonly Regex ByteRangePattern = ByteRangeRegex();
    private static readonly Regex ContentsPattern = ContentsRegex();
    private static readonly Regex BareHexPattern = BareHexRegex();

    public static void VerifyIntegrity(string pdfPath)
    {
        var pdfBytes = File.ReadAllBytes(pdfPath);
        var text = Encoding.Latin1.GetString(pdfBytes);
        var byteRange = ByteRangePattern.Matches(text).Cast<Match>().LastOrDefault()
            ?? throw new InvalidDataException("Không tìm thấy ByteRange của chữ ký PDF.");

        var start = ParseOffset(byteRange.Groups[1].Value);
        var firstLength = ParseOffset(byteRange.Groups[2].Value);
        var secondStart = ParseOffset(byteRange.Groups[3].Value);
        var secondLength = ParseOffset(byteRange.Groups[4].Value);
        if (start != 0 || firstLength > pdfBytes.LongLength || secondStart < firstLength
            || secondStart > pdfBytes.LongLength || secondLength > pdfBytes.LongLength - secondStart)
        {
            throw new InvalidDataException("ByteRange của chữ ký PDF không hợp lệ.");
        }

        var excludedLength = checked((int)(secondStart - firstLength));
        var excludedText = Encoding.Latin1.GetString(pdfBytes, checked((int)firstLength), excludedLength);
        var cmsBytes = DecodeHex(ExtractCmsHex(excludedText));
        var signedBytes = new byte[checked((int)(firstLength + secondLength))];
        Buffer.BlockCopy(pdfBytes, 0, signedBytes, 0, checked((int)firstLength));
        Buffer.BlockCopy(pdfBytes, checked((int)secondStart), signedBytes, checked((int)firstLength), checked((int)secondLength));

        var cms = new SignedCms(new ContentInfo(signedBytes), detached: true);
        cms.Decode(TrimToDerObject(cmsBytes));
        cms.CheckSignature(verifySignatureOnly: true);
        if (cms.SignerInfos.Count == 0)
        {
            throw new CryptographicException("CMS không chứa signer info.");
        }
    }

    public static void VerifyTimestamp(string pdfPath)
    {
        var pdfBytes = File.ReadAllBytes(pdfPath);
        var text = Encoding.Latin1.GetString(pdfBytes);
        var byteRange = ByteRangePattern.Matches(text).Cast<Match>().LastOrDefault()
            ?? throw new InvalidDataException("Không tìm thấy ByteRange của chữ ký PDF.");

        var start = ParseOffset(byteRange.Groups[1].Value);
        var firstLength = ParseOffset(byteRange.Groups[2].Value);
        var secondStart = ParseOffset(byteRange.Groups[3].Value);
        var secondLength = ParseOffset(byteRange.Groups[4].Value);
        if (start != 0 || firstLength > pdfBytes.LongLength || secondStart < firstLength
            || secondStart > pdfBytes.LongLength || secondLength > pdfBytes.LongLength - secondStart)
        {
            throw new InvalidDataException("ByteRange của chữ ký PDF không hợp lệ.");
        }

        var excludedLength = checked((int)(secondStart - firstLength));
        var excludedText = Encoding.Latin1.GetString(pdfBytes, checked((int)firstLength), excludedLength);
        var cmsBytes = TrimToDerObject(DecodeHex(ExtractCmsHex(excludedText)));
        var signedBytes = new byte[checked((int)(firstLength + secondLength))];
        Buffer.BlockCopy(pdfBytes, 0, signedBytes, 0, checked((int)firstLength));
        Buffer.BlockCopy(pdfBytes, checked((int)secondStart), signedBytes, checked((int)firstLength), checked((int)secondLength));

        var cms = new SignedCms(new ContentInfo(signedBytes), detached: true);
        cms.Decode(cmsBytes);
        cms.CheckSignature(verifySignatureOnly: true);
        _ = CmsTimestampService.VerifyEmbeddedTimestamp(cmsBytes);
    }

    /// <summary>
    /// Verifies only structural facts that can be read from the saved PDF. A valid appearance
    /// stream still cannot guarantee identical rendering in every PDF viewer.
    /// </summary>
    public static SignatureAppearanceVerification VerifySignatureAppearance(string pdfPath)
    {
        var expectedCms = ExtractLastSignatureCms(pdfPath);
        using var document = PdfReader.Open(pdfPath, PdfDocumentOpenMode.ReadOnly);
        if (document.PageCount == 0)
        {
            throw new InvalidDataException("PDF đầu ra không có trang để kiểm tra widget chữ ký.");
        }

        var firstPage = document.Pages[0];
        var annotations = firstPage.Elements.GetArray("/Annots")
            ?? throw new InvalidDataException("Trang đầu không có /Annots chứa signature widget.");
        var visibleBox = firstPage.CropBoxReadOnly;
        if (visibleBox.IsEmpty)
        {
            visibleBox = firstPage.MediaBoxReadOnly;
        }
        if (visibleBox.IsEmpty)
        {
            throw new InvalidDataException("Trang đầu không có CropBox hoặc MediaBox hợp lệ.");
        }

        for (var index = 0; index < annotations.Elements.Count; index++)
        {
            var widget = annotations.Elements.GetDictionary(index);
            if (widget is null || !string.Equals(widget.Elements.GetName("/Subtype"), "/Widget", StringComparison.Ordinal))
            {
                continue;
            }

            var signature = widget.Elements.GetDictionary("/V");
            if (signature is null || !SignatureMatchesCms(signature, expectedCms))
            {
                continue;
            }

            var rectangle = widget.Elements.GetRectangle("/Rect")
                ?? throw new InvalidDataException("Signature widget liên kết CMS không có /Rect.");
            var left = Math.Min(rectangle.X1, rectangle.X2);
            var right = Math.Max(rectangle.X1, rectangle.X2);
            var bottom = Math.Min(rectangle.Y1, rectangle.Y2);
            var top = Math.Max(rectangle.Y1, rectangle.Y2);
            if (right <= left || top <= bottom)
            {
                throw new InvalidDataException("/Rect của signature widget có kích thước không hợp lệ.");
            }

            if (!IntersectsVisibleBox(left, bottom, right, top, visibleBox))
            {
                throw new InvalidDataException("/Rect của signature widget không giao với CropBox/MediaBox của trang đầu.");
            }

            var appearance = widget.Elements.GetDictionary("/AP")
                ?? throw new InvalidDataException("Signature widget không có appearance dictionary /AP.");
            var normalAppearance = appearance.Elements.GetDictionary("/N")
                ?? throw new InvalidDataException("Signature widget không có normal appearance /AP /N.");
            var stream = normalAppearance.Stream;
            if (stream is null || stream.Value.Length == 0 || !stream.Value.Any(value => !char.IsWhiteSpace((char)value)))
            {
                throw new InvalidDataException("Appearance stream /AP /N trống.");
            }

            // /Type is optional for an XObject in practice; /Subtype /Form and a positive
            // bounding box are the structural facts needed for this signature appearance.
            if (!string.Equals(normalAppearance.Elements.GetName("/Subtype"), "/Form", StringComparison.Ordinal))
            {
                throw new InvalidDataException("/AP /N không phải Form XObject hợp lệ.");
            }

            var boundingBox = normalAppearance.Elements.GetRectangle("/BBox");
            if (boundingBox is null || boundingBox.Width <= 0 || boundingBox.Height <= 0)
            {
                throw new InvalidDataException("Appearance stream /AP /N không có /BBox hợp lệ.");
            }

            return new SignatureAppearanceVerification(index, left, bottom, right - left, top - bottom, stream.Value.Length);
        }

        throw new InvalidDataException("Không tìm thấy signature widget trên trang đầu liên kết với CMS đã xác minh.");
    }

    private static bool SignatureMatchesCms(PdfDictionary signature, byte[] expectedCms)
    {
        if (signature.Elements.GetArray("/ByteRange") is null)
        {
            return false;
        }

        var contents = signature.Elements.GetString("/Contents");
        if (string.IsNullOrEmpty(contents))
        {
            return false;
        }

        try
        {
            var candidateCms = TrimToDerObject(Encoding.Latin1.GetBytes(contents));
            return candidateCms.AsSpan().SequenceEqual(expectedCms);
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    private static bool IntersectsVisibleBox(double left, double bottom, double right, double top, PdfRectangle visibleBox)
    {
        var visibleLeft = Math.Min(visibleBox.X1, visibleBox.X2);
        var visibleRight = Math.Max(visibleBox.X1, visibleBox.X2);
        var visibleBottom = Math.Min(visibleBox.Y1, visibleBox.Y2);
        var visibleTop = Math.Max(visibleBox.Y1, visibleBox.Y2);
        return left < visibleRight && right > visibleLeft && bottom < visibleTop && top > visibleBottom;
    }

    private static byte[] ExtractLastSignatureCms(string pdfPath)
    {
        var pdfBytes = File.ReadAllBytes(pdfPath);
        var text = Encoding.Latin1.GetString(pdfBytes);
        var byteRange = ByteRangePattern.Matches(text).Cast<Match>().LastOrDefault()
            ?? throw new InvalidDataException("Không tìm thấy ByteRange của chữ ký PDF.");
        var firstLength = ParseOffset(byteRange.Groups[2].Value);
        var secondStart = ParseOffset(byteRange.Groups[3].Value);
        var secondLength = ParseOffset(byteRange.Groups[4].Value);
        if (firstLength > pdfBytes.LongLength || secondStart < firstLength
            || secondStart > pdfBytes.LongLength || secondLength > pdfBytes.LongLength - secondStart)
        {
            throw new InvalidDataException("ByteRange của chữ ký PDF không hợp lệ.");
        }

        var excludedLength = checked((int)(secondStart - firstLength));
        var excludedText = Encoding.Latin1.GetString(pdfBytes, checked((int)firstLength), excludedLength);
        return TrimToDerObject(DecodeHex(ExtractCmsHex(excludedText)));
    }

    private static long ParseOffset(string value) => long.TryParse(value, out var result) && result >= 0
        ? result
        : throw new InvalidDataException("ByteRange chứa giá trị không hợp lệ.");

    private static byte[] DecodeHex(string value)
    {
        var hex = string.Concat(value.Where(character => !char.IsWhiteSpace(character)));
        if (hex.Length == 0 || hex.Length % 2 != 0 || !hex.All(Uri.IsHexDigit))
        {
            throw new InvalidDataException("Contents của chữ ký PDF không phải chuỗi hex hợp lệ.");
        }

        return Convert.FromHexString(hex);
    }

    private static string ExtractCmsHex(string excludedText)
    {
        var wrapped = ContentsPattern.Matches(excludedText)
            .Cast<Match>()
            .OrderByDescending(match => match.Groups[1].Length)
            .FirstOrDefault();
        if (wrapped is { Success: true })
        {
            return wrapped.Groups[1].Value;
        }

        // Some producers make ByteRange exclude only the hex payload, not its angle brackets.
        var bare = BareHexPattern.Matches(excludedText)
            .Cast<Match>()
            .OrderByDescending(match => match.Length)
            .FirstOrDefault();
        return bare is { Success: true }
            ? bare.Value
            : throw new InvalidDataException("Không tìm thấy CMS Contents trong vùng chữ ký PDF.");
    }

    private static byte[] TrimToDerObject(byte[] value)
    {
        if (value.Length < 2 || value[0] != 0x30)
        {
            throw new InvalidDataException("CMS không bắt đầu bằng DER SEQUENCE.");
        }

        var lengthFirstByte = value[1];
        var headerLength = 2;
        int payloadLength;
        if ((lengthFirstByte & 0x80) == 0)
        {
            payloadLength = lengthFirstByte;
        }
        else
        {
            var lengthByteCount = lengthFirstByte & 0x7f;
            if (lengthByteCount is 0 or > 4 || value.Length < 2 + lengthByteCount)
            {
                throw new InvalidDataException("Độ dài DER của CMS không hợp lệ.");
            }

            payloadLength = 0;
            for (var index = 0; index < lengthByteCount; index++)
            {
                payloadLength = checked((payloadLength << 8) | value[headerLength + index]);
            }
            headerLength += lengthByteCount;
        }

        var totalLength = checked(headerLength + payloadLength);
        if (totalLength > value.Length)
        {
            throw new InvalidDataException("CMS bị cắt ngắn.");
        }

        return value.AsSpan(0, totalLength).ToArray();
    }

    [GeneratedRegex(@"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", RegexOptions.CultureInvariant)]
    private static partial Regex ByteRangeRegex();

    [GeneratedRegex(@"<([0-9A-Fa-f\s]+)>", RegexOptions.CultureInvariant)]
    private static partial Regex ContentsRegex();

    [GeneratedRegex(@"[0-9A-Fa-f]{32,}", RegexOptions.CultureInvariant)]
    private static partial Regex BareHexRegex();
}
