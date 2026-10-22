using KySoHangLoat.WinForms.Models;

namespace KySoHangLoat.WinForms.Services;

internal interface ITimestampAwareSigner
{
    TimestampResult? LastTimestamp { get; }
}
