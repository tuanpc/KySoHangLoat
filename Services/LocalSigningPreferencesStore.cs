using System.Text.Json;

namespace KySoHangLoat.WinForms.Services;

internal sealed class LocalSigningPreferencesStore
{
    internal const string DefaultTsaUrl = "http://tsa.ca.gov.vn";
    private const string FileName = "signing-preferences.json";

    public SigningPreferences Load()
    {
        try
        {
            var path = GetPath();
            if (!File.Exists(path))
            {
                return new SigningPreferences(false, DefaultTsaUrl, false);
            }

            var stored = JsonSerializer.Deserialize<SigningPreferences>(File.ReadAllText(path));
            return stored is null || string.IsNullOrWhiteSpace(stored.TsaUrl)
                ? new SigningPreferences(stored?.UppercaseSignatureText ?? false, DefaultTsaUrl, stored?.UseTsaTimestamp ?? false)
                : stored;
        }
        catch
        {
            return new SigningPreferences(false, DefaultTsaUrl, false);
        }
    }

    public void Save(SigningPreferences preferences)
    {
        ArgumentNullException.ThrowIfNull(preferences);
        var path = GetPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(preferences));
    }

    private static string GetPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "KySoHangLoat",
        FileName);
}

internal sealed record SigningPreferences(bool UppercaseSignatureText, string TsaUrl, bool UseTsaTimestamp);
