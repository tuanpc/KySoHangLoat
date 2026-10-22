using System.Text;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;

namespace KySoHangLoat.WinForms.Services;

/// <summary>
/// Detects existing PDF signatures before a document is opened for modification.
/// PDFsharp 6.2.4 rewrites a saved document, so modifying an already signed PDF is unsafe
/// until the application has an incremental-update signing path.
/// </summary>
internal static class PdfExistingSignatureDetector
{
    private const string ExistingSignatureMessage =
        "PDF đã có chữ ký số. Phiên bản hiện tại chưa hỗ trợ ký bổ sung mà vẫn bảo toàn chữ ký gốc.";

    private static readonly byte[] ByteRangeMarker = Encoding.ASCII.GetBytes("/ByteRange");

    public static void EnsureSafeToModify(string pdfPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pdfPath);

        try
        {
            var evidence = InspectPdfStructure(pdfPath);
            if (evidence.Count > 0)
            {
                throw new PdfSignatureProtectionException(ExistingSignatureMessage, evidence);
            }

            // A ByteRange not reachable through the parsed AcroForm/annotation structure is not
            // enough to prove a valid signature, but it is unsafe to rewrite the document.
            if (ContainsByteRangeMarker(pdfPath))
            {
                throw new PdfSignatureProtectionException(
                    "Không thể xác định an toàn trạng thái chữ ký số của PDF vì phát hiện /ByteRange " +
                    "không liên kết được với cấu trúc chữ ký. File không được ký để tránh làm hỏng chữ ký hiện có.",
                    ["Phát hiện /ByteRange thô ngoài cấu trúc AcroForm/Widget mà PDFsharp đọc được."]);
            }
        }
        catch (PdfSignatureProtectionException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new PdfSignatureProtectionException(
                "Không thể xác định an toàn trạng thái chữ ký số của PDF. File không được ký để tránh làm hỏng chữ ký hiện có.",
                [exception.Message],
                exception);
        }
    }

    private static List<string> InspectPdfStructure(string pdfPath)
    {
        var evidence = new List<string>();
        var visited = new HashSet<PdfDictionary>();

        using var document = PdfReader.Open(pdfPath, PdfDocumentOpenMode.ReadOnly);
        // PdfDocument.Catalog is not exposed by the PDFsharp-GDI 6.2.4 target consumed by
        // this project. PdfInternals.Catalog is the supported access point for the parsed catalog.
        var acroForm = document.Internals.Catalog.Elements.GetDictionary("/AcroForm");
        if (acroForm is not null)
        {
            var fields = acroForm.Elements.GetArray("/Fields");
            if (fields is not null)
            {
                for (var index = 0; index < fields.Elements.Count; index++)
                {
                    var field = fields.Elements.GetDictionary(index);
                    if (field is null)
                    {
                        throw new InvalidDataException($"AcroForm /Fields[{index}] không phải dictionary hợp lệ.");
                    }

                    InspectFieldOrWidget(field, $"AcroForm /Fields[{index}]", inheritedFieldType: null, visited, evidence);
                }
            }
        }

        for (var pageIndex = 0; pageIndex < document.PageCount; pageIndex++)
        {
            var annotations = document.Pages[pageIndex].Elements.GetArray("/Annots");
            if (annotations is null)
            {
                continue;
            }

            for (var annotationIndex = 0; annotationIndex < annotations.Elements.Count; annotationIndex++)
            {
                var annotation = annotations.Elements.GetDictionary(annotationIndex);
                if (annotation is null)
                {
                    throw new InvalidDataException($"Trang {pageIndex + 1} có /Annots[{annotationIndex}] không phải dictionary hợp lệ.");
                }

                if (string.Equals(annotation.Elements.GetName("/Subtype"), "/Widget", StringComparison.Ordinal))
                {
                    InspectFieldOrWidget(annotation, $"Trang {pageIndex + 1} /Annots[{annotationIndex}]", inheritedFieldType: null, visited, evidence);
                }
            }
        }

        return evidence;
    }

    private static void InspectFieldOrWidget(
        PdfDictionary dictionary,
        string path,
        string? inheritedFieldType,
        HashSet<PdfDictionary> visited,
        List<string> evidence)
    {
        if (!visited.Add(dictionary))
        {
            return;
        }

        var fieldType = dictionary.Elements.GetName("/FT") ?? inheritedFieldType;
        var value = dictionary.Elements.GetDictionary("/V");
        var isSignatureField = string.Equals(fieldType, "/Sig", StringComparison.Ordinal);

        if (value is not null)
        {
            InspectSignatureDictionary(value, $"{path} /V", isSignatureField, evidence);
        }
        else if (isSignatureField && dictionary.Elements.GetArray("/ByteRange") is not null)
        {
            // A malformed signature field still must not be rewritten.
            evidence.Add($"{path}: trường /FT /Sig có /ByteRange nhưng không có /V dictionary hợp lệ.");
        }

        // A page annotation can inherit /FT and /V from its parent field. Follow the parent as
        // well as /Kids; the visited set prevents the normal parent/child cycle from recursing.
        var parent = dictionary.Elements.GetDictionary("/Parent");
        if (parent is not null)
        {
            InspectFieldOrWidget(parent, $"{path} /Parent", inheritedFieldType, visited, evidence);
        }

        var kids = dictionary.Elements.GetArray("/Kids");
        if (kids is null)
        {
            return;
        }

        for (var index = 0; index < kids.Elements.Count; index++)
        {
            var child = kids.Elements.GetDictionary(index)
                ?? throw new InvalidDataException($"{path} /Kids[{index}] không phải dictionary hợp lệ.");
            InspectFieldOrWidget(child, $"{path} /Kids[{index}]", fieldType, visited, evidence);
        }
    }

    private static void InspectSignatureDictionary(PdfDictionary dictionary, string path, bool belongsToSignatureField, List<string> evidence)
    {
        var type = dictionary.Elements.GetName("/Type");
        var hasByteRange = dictionary.Elements.GetArray("/ByteRange") is not null;
        var hasContents = !string.IsNullOrEmpty(dictionary.Elements.GetString("/Contents"));
        var isSignatureDictionary = string.Equals(type, "/Sig", StringComparison.Ordinal) || hasByteRange;

        if (isSignatureDictionary)
        {
            evidence.Add($"{path}: signature dictionary ({(string.Equals(type, "/Sig", StringComparison.Ordinal) ? "/Type /Sig" : "/ByteRange")}).");
            return;
        }

        if (belongsToSignatureField)
        {
            var detail = hasContents ? "có /Contents" : "không có /Type /Sig hoặc /ByteRange";
            evidence.Add($"{path}: /FT /Sig có /V bất thường ({detail}).");
        }
    }

    private static bool ContainsByteRangeMarker(string pdfPath)
    {
        var bytes = File.ReadAllBytes(pdfPath);
        return bytes.AsSpan().IndexOf(ByteRangeMarker) >= 0;
    }
}

internal sealed class PdfSignatureProtectionException : Exception
{
    public PdfSignatureProtectionException(string message, IReadOnlyList<string> evidence, Exception? innerException = null)
        : base(message, innerException)
    {
        Evidence = evidence;
    }

    public IReadOnlyList<string> Evidence { get; }
}
