namespace KySoHangLoat.WinForms.Models;

/// <summary>
/// Structural evidence for the visual signature widget in the saved PDF.
/// It does not guarantee identical rendering in every PDF viewer.
/// </summary>
internal sealed record SignatureAppearanceVerification(
    int AnnotationIndex,
    double Left,
    double Bottom,
    double Width,
    double Height,
    int AppearanceStreamLength);
