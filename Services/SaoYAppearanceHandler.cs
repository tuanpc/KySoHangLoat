using PdfSharp.Drawing;
using PdfSharp.Pdf.Annotations;

namespace KySoHangLoat.WinForms.Services;

internal sealed class SaoYAppearanceHandler : IAnnotationAppearanceHandler
{
    internal const double FontSizePoints = 12;
    internal const double PaddingPoints = 4;

    private readonly string _text;
    private readonly XSize _textSize;

    private SaoYAppearanceHandler(string text, XSize textSize)
    {
        _text = text;
        _textSize = textSize;
    }

    internal static SaoYAppearanceHandler Create(
        string displayName,
        DateTimeOffset signedAt,
        bool uppercase,
        XSize pageSize)
    {
        var text = $"SAO Y; {displayName}; Thời gian ký: {signedAt:yyyy-MM-ddTHH:mm:sszzz}";
        if (uppercase)
        {
            text = text.ToUpperInvariant();
        }

        using var graphics = XGraphics.CreateMeasureContext(
            pageSize,
            XGraphicsUnit.Point,
            XPageDirection.Downwards,
            null);
        var font = new XFont("Times New Roman", FontSizePoints, XFontStyleEx.Regular);
        return new SaoYAppearanceHandler(text, graphics.MeasureString(text, font));
    }

    internal XSize GetRequiredSize() => new(
        _textSize.Width + PaddingPoints * 2,
        _textSize.Height + PaddingPoints * 2);

    public void DrawAppearance(XGraphics graphics, XRect rectangle)
    {
        // The appearance stream has its own coordinate space; (0, 0) is its top-left corner.
        var localRectangle = new XRect(0, 0, rectangle.Width, rectangle.Height);
        var font = new XFont("Times New Roman", FontSizePoints, XFontStyleEx.Regular);
        var measured = graphics.MeasureString(_text, font);
        var availableWidth = localRectangle.Width - PaddingPoints * 2;
        var availableHeight = localRectangle.Height - PaddingPoints * 2;
        if (measured.Width > availableWidth || measured.Height > availableHeight)
        {
            throw new InvalidOperationException("Dòng hiển thị SAO Y không vừa vùng chữ ký đã tính.");
        }

        graphics.DrawString(
            _text,
            font,
            XBrushes.Black,
            new XRect(PaddingPoints, PaddingPoints, availableWidth, availableHeight),
            XStringFormats.TopRight);
    }
}
