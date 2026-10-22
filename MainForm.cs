using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using KySoHangLoat.WinForms.Models;
using KySoHangLoat.WinForms.Services;

namespace KySoHangLoat.WinForms;

internal sealed class MainForm : Form
{
    private readonly CertificateStoreService _certificateStore = new();
    private readonly PdfSigningService _pdfSigning = new();
    private readonly CspTokenDiagnosticService _cspDiagnostic = new();
    private readonly LocalSigningPreferencesStore _preferencesStore = new();
    private readonly TextBox _folderText = new() { ReadOnly = true, Dock = DockStyle.Fill };
    private readonly ComboBox _certificateList = new() { DropDownStyle = ComboBoxStyle.DropDownList, DrawMode = DrawMode.OwnerDrawFixed, ItemHeight = 38, Dock = DockStyle.Fill };
    private readonly CheckBox _addSignedSuffix = new() { Text = "Thêm .signed vào tên file sau khi ký", AutoSize = true, Checked = true };
    private readonly CheckBox _uppercaseSignatureText = new() { Text = "In hoa nội dung SAO Y", AutoSize = true };
    private readonly Label _folderStatus = new() { AutoSize = true };
    private readonly Label _totalValue = new() { AutoSize = true, Text = "0" };
    private readonly Label _successValue = new() { AutoSize = true, Text = "0" };
    private readonly Label _failureValue = new() { AutoSize = true, Text = "0" };
    private readonly Label _progressStatus = new() { AutoSize = true, Text = "Chọn thư mục PDF để bắt đầu." };
    private readonly Button _browseButton = new() { Text = "Chọn thư mục", AutoSize = true };
    private readonly Button _reloadCertificatesButton = new() { Text = "Tải lại", AutoSize = true };
    private readonly Button _certificateInfoButton = new()
    {
        Image = CreateCertificateInfoIcon(),
        AccessibleName = "Thông tin chứng thư số",
        AccessibleDescription = "Mở thông tin chi tiết của chứng thư số.",
        AutoSize = false,
        Size = new Size(32, 30),
        ImageAlign = ContentAlignment.MiddleCenter,
        TextImageRelation = TextImageRelation.Overlay,
        BackColor = Color.FromArgb(232, 245, 233),
        FlatStyle = FlatStyle.Flat,
        UseVisualStyleBackColor = false
    };
    private readonly Button _signButton = new() { Text = "Ký tất cả PDF", AutoSize = true, Enabled = false };
    private readonly Button _stopButton = new() { Text = "Dừng", AutoSize = true, Enabled = false };
    private readonly Button _openOutputButton = new() { Text = "Mở thư mục kết quả", AutoSize = true, Enabled = false };
    private readonly Button _advancedButton = new() { Text = "⚙", AutoSize = true, AccessibleName = "Cài đặt nâng cao" };
    private readonly Button _viewLogButton = new() { Text = "Log", AutoSize = true };
    private readonly ToolTip _toolTip = new();
    private readonly StringBuilder _logBuffer = new();
    private string? _folder;
    private bool _showAllWindowsCertificates;
    private bool _signing;
    private bool _checkingToken;
    private bool _stopRequested;
    private int _sourceCount;
    private int _successCount;
    private int _failureCount;

    public MainForm()
    {
        Text = "Ký sao y PDF hàng loạt";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(760, 430);
        Size = new Size(820, 500);
        Font = new Font("Segoe UI", 9F);
        Controls.Add(BuildLayout());
        _toolTip.SetToolTip(_advancedButton, "Cài đặt nâng cao");
        _toolTip.SetToolTip(_certificateInfoButton, "Thông tin chứng thư số");
        _certificateInfoButton.FlatAppearance.BorderColor = Color.FromArgb(165, 214, 167);
        _certificateInfoButton.FlatAppearance.MouseOverBackColor = Color.FromArgb(200, 230, 201);
        _certificateInfoButton.FlatAppearance.MouseDownBackColor = Color.FromArgb(165, 214, 167);
        Load += (_, _) =>
        {
            _uppercaseSignatureText.Checked = _preferencesStore.Load().UppercaseSignatureText;
            Log($"Ứng dụng chạy kiến trúc {RuntimeInformation.ProcessArchitecture}. Middleware/CSP của Token phải có cùng kiến trúc và đưa chứng thư vào CurrentUser\\My.");
            ReloadCertificates();
        };
        _certificateList.SelectedIndexChanged += (_, _) => UpdateControls();
        _certificateList.DrawItem += CertificateList_DrawItem;
        _browseButton.Click += (_, _) => ChooseFolder();
        _reloadCertificatesButton.Click += (_, _) => ReloadCertificates();
        _certificateInfoButton.Click += (_, _) => ShowCertificateDetails();
        _signButton.Click += async (_, _) => await SignAllFilesAsync();
        _stopButton.Click += (_, _) => RequestStop();
        _openOutputButton.Click += (_, _) => OpenOutputFolder();
        _advancedButton.Click += (_, _) => ShowAdvancedDialog();
        _viewLogButton.Click += (_, _) => ShowLogDialog();
    }

    private Control BuildLayout()
    {
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(20), ColumnCount = 3, RowCount = 8 };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        for (var row = 0; row < 8; row++) root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles[6] = new RowStyle(SizeType.Percent, 100);

        var title = new Label { Text = "Ký sao y PDF hàng loạt", Font = new Font(Font, FontStyle.Bold), AutoSize = true, Margin = new Padding(0, 0, 0, 12) };
        root.Controls.Add(title, 0, 0); root.SetColumnSpan(title, 3);
        root.Controls.Add(new Label { Text = "Chứng thư số", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 1);
        root.Controls.Add(_certificateList, 1, 1);
        var certificateActions = CreateActions(_reloadCertificatesButton, _certificateInfoButton); certificateActions.Margin = new Padding(6, 0, 0, 0); root.Controls.Add(certificateActions, 2, 1);
        root.Controls.Add(new Label { Text = "Thư mục PDF", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 2);
        root.Controls.Add(_folderText, 1, 2); root.Controls.Add(_browseButton, 2, 2);
        root.Controls.Add(_folderStatus, 1, 3); root.SetColumnSpan(_folderStatus, 2);

        var options = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Margin = new Padding(0, 8, 0, 8) };
        options.Controls.Add(_addSignedSuffix); options.Controls.Add(_uppercaseSignatureText);
        root.Controls.Add(options, 1, 4); root.SetColumnSpan(options, 2);

        var progress = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 6, Margin = new Padding(0, 4, 0, 6) };
        for (var column = 0; column < 6; column++) progress.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        progress.Controls.Add(new Label { Text = "Tổng số:", AutoSize = true }, 0, 0); progress.Controls.Add(_totalValue, 1, 0);
        progress.Controls.Add(new Label { Text = "Thành công:", AutoSize = true, Margin = new Padding(20, 3, 3, 3) }, 2, 0); progress.Controls.Add(_successValue, 3, 0);
        progress.Controls.Add(new Label { Text = "Thất bại:", AutoSize = true, Margin = new Padding(20, 3, 3, 3) }, 4, 0); progress.Controls.Add(_failureValue, 5, 0);
        root.Controls.Add(progress, 1, 5); root.SetColumnSpan(progress, 2);
        root.Controls.Add(_progressStatus, 1, 6); root.SetColumnSpan(_progressStatus, 2);
        var bottomActions = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 2, Margin = new Padding(0, 8, 0, 0) };
        bottomActions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        bottomActions.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var primaryActions = CreateActions(_signButton, _stopButton, _openOutputButton);
        var utilityActions = new FlowLayoutPanel { AutoSize = true, Anchor = AnchorStyles.Right, FlowDirection = FlowDirection.RightToLeft, WrapContents = false };
        _advancedButton.Margin = new Padding(0, 3, 8, 3);
        _viewLogButton.Margin = new Padding(0, 3, 0, 3);
        utilityActions.Controls.Add(_viewLogButton);
        utilityActions.Controls.Add(_advancedButton);
        bottomActions.Controls.Add(primaryActions, 0, 0);
        bottomActions.Controls.Add(utilityActions, 1, 0);
        root.Controls.Add(bottomActions, 0, 7); root.SetColumnSpan(bottomActions, 3);
        return root;
    }

    private static FlowLayoutPanel CreateActions(params Control[] controls)
    {
        var panel = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
        panel.Controls.AddRange(controls);
        return panel;
    }

    private static Image CreateCertificateInfoIcon()
    {
        var image = new Bitmap(20, 20);
        using var graphics = Graphics.FromImage(image);
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        graphics.Clear(Color.Transparent);
        using var circleBrush = new SolidBrush(Color.ForestGreen);
        graphics.FillEllipse(circleBrush, 1, 1, 18, 18);
        using var textBrush = new SolidBrush(Color.White);
        using var font = new Font("Segoe UI", 12F, FontStyle.Bold, GraphicsUnit.Pixel);
        using var format = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
        graphics.DrawString("i", font, textBrush, new RectangleF(0, -0.5F, 20, 20), format);
        return image;
    }

    private void ChooseFolder()
    {
        using var dialog = new FolderBrowserDialog { Description = "Chọn thư mục chứa PDF nguồn" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        _folder = dialog.SelectedPath; _folderText.Text = _folder;
        try
        {
            _sourceCount = GetSourcePdfs(_folder).Count; _successCount = 0; _failureCount = 0;
            _folderStatus.Text = $"Tìm thấy {_sourceCount} PDF trong thư mục gốc; thư mục con signed không được quét.";
            _progressStatus.Text = _sourceCount == 0 ? "Không có PDF để ký." : "Sẵn sàng ký tuần tự.";
        }
        catch (Exception exception)
        {
            _sourceCount = 0; _folderStatus.Text = "Không thể đọc thư mục PDF."; _progressStatus.Text = "Không thể quét PDF.";
            LogExceptionDetails("Quét thư mục PDF", exception);
        }
        UpdateProgress(); UpdateControls();
    }

    private void ReloadCertificates()
    {
        var allCertificates = Array.Empty<CertificateListItem>();
        _certificateList.BeginUpdate();
        try
        {
            _certificateList.Items.Clear(); allCertificates = _certificateStore.ListSigningCertificates().ToArray();
            var visibleCertificates = _showAllWindowsCertificates
                ? allCertificates
                : allCertificates.Where(item => item.IsPreferredForDefaultList).ToArray();
            foreach (var certificate in visibleCertificates) _certificateList.Items.Add(certificate);
            _certificateList.DisplayMember = nameof(CertificateListItem.DisplayText);
            if (_certificateList.Items.Count > 0)
            {
                var preferredIndex = Array.FindIndex(visibleCertificates, item => item.InitialReadiness == CertificateReadiness.Ready);
                _certificateList.SelectedIndex = preferredIndex >= 0 ? preferredIndex : 0;
            }
        }
        catch (Exception exception) { LogExceptionDetails("Đọc Windows Certificate Store", exception); }
        finally { _certificateList.EndUpdate(); }
        var mode = _showAllWindowsCertificates
            ? "tất cả chứng thư Windows"
            : "ưu tiên chứng thư không có metadata provider phần mềm";
        Log($"Đã hiển thị {_certificateList.Items.Count}/{allCertificates.Length} chứng thư từ CurrentUser\\My ({mode}).");
        LogCertificateStoreDiagnostics();
        UpdateControls();
    }

    private void LogCertificateStoreDiagnostics()
    {
        foreach (var diagnostic in _certificateStore.DiagnosePersonalStores())
        {
            if (diagnostic.IsStoreError)
            {
                Log($"Chẩn đoán kho {diagnostic.StoreName}: {diagnostic.EvaluationSummary}");
                continue;
            }

            var scope = diagnostic.IsSigningStore ? "kho ký hiện tại" : "chỉ chẩn đoán, chưa là kho ký";
            Log($"Chẩn đoán chứng thư | Kho={diagnostic.StoreName} ({scope}) | Subject={diagnostic.SubjectName} | Trạng thái={diagnostic.Readiness} | HasPrivateKey={diagnostic.HasPrivateKey} | Ký số={diagnostic.IsUsableForSigning} | Provider={diagnostic.ProviderName}; Type={FormatNativeValue(diagnostic.ProviderType)}; KeySpec={FormatNativeValue(diagnostic.KeySpec)} | {diagnostic.EvaluationSummary}");
        }
    }

    private void CertificateList_DrawItem(object? sender, DrawItemEventArgs e)
    {
        e.DrawBackground();
        if (e.Index < 0 || _certificateList.Items[e.Index] is not CertificateListItem item)
        {
            return;
        }

        var selected = (e.State & DrawItemState.Selected) == DrawItemState.Selected;
        var color = selected ? SystemColors.HighlightText : GetReadinessColor(item.InitialReadiness);
        var status = item.ReadinessText;
        var statusSize = TextRenderer.MeasureText(status, Font);
        var iconBounds = new Rectangle(e.Bounds.Left + 7, e.Bounds.Top + 12, 12, 12);
        var ownerBounds = new Rectangle(iconBounds.Right + 7, e.Bounds.Top + 3, Math.Max(0, e.Bounds.Width - statusSize.Width - 40), 17);
        var statusBounds = new Rectangle(e.Bounds.Right - statusSize.Width - 7, e.Bounds.Top + 3, statusSize.Width, 17);
        var detailBounds = new Rectangle(iconBounds.Right + 7, e.Bounds.Top + 20, Math.Max(0, e.Bounds.Width - iconBounds.Right - 14), 16);
        using var iconBrush = new SolidBrush(selected ? SystemColors.HighlightText : color);
        e.Graphics.FillEllipse(iconBrush, iconBounds);
        TextRenderer.DrawText(e.Graphics, item.SubjectName, Font, ownerBounds, color, TextFormatFlags.EndEllipsis | TextFormatFlags.VerticalCenter);
        TextRenderer.DrawText(e.Graphics, status, Font, statusBounds, color, TextFormatFlags.Right | TextFormatFlags.EndEllipsis | TextFormatFlags.VerticalCenter);
        TextRenderer.DrawText(e.Graphics, $"Hết hạn: {item.NotAfter:yyyy-MM-dd}", Font, detailBounds, selected ? SystemColors.HighlightText : SystemColors.GrayText, TextFormatFlags.EndEllipsis | TextFormatFlags.VerticalCenter);
        e.DrawFocusRectangle();
    }

    private static Color GetReadinessColor(CertificateReadiness readiness) => readiness switch
    {
        CertificateReadiness.Ready => Color.ForestGreen,
        CertificateReadiness.Warning => Color.DarkOrange,
        _ => SystemColors.GrayText
    };

    private async Task SignAllFilesAsync()
    {
        if (_signing || _folder is null || _certificateList.SelectedItem is not CertificateListItem item) return;
        IReadOnlyList<string> sources;
        try { sources = GetSourcePdfs(_folder); }
        catch (Exception exception)
        {
            LogExceptionDetails("Quét thư mục PDF trước khi ký", exception);
            MessageBox.Show(this, "Không thể đọc danh sách PDF. Xem nhật ký để biết chi tiết.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); return;
        }
        if (sources.Count == 0) { MessageBox.Show(this, "Không có PDF ở thư mục gốc để ký.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        var displayName = ResolveDisplayName(item);
        if (string.IsNullOrWhiteSpace(displayName))
        {
            MessageBox.Show(this, "Không đọc được CN của chứng thư để tạo nội dung SAO Y. Hãy chọn chứng thư có Subject chứa CN.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information); return;
        }
        var preferences = _preferencesStore.Load();
        if (preferences.UseTsaTimestamp && !TryValidateTsaUrl(preferences.TsaUrl, out var tsaValidationError)) { MessageBox.Show(this, tsaValidationError, Text, MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        _preferencesStore.Save(new SigningPreferences(_uppercaseSignatureText.Checked, preferences.TsaUrl, preferences.UseTsaTimestamp));
        if (item.InitialReadiness != CertificateReadiness.Ready)
        {
            var reason = item.EvaluationReasons.Count > 0
                ? string.Join(Environment.NewLine, item.EvaluationReasons)
                : "Metadata provider chưa đủ để xác định khả năng ký.";
            MessageBox.Show(this, $"Chứng thư không đủ điều kiện ký:{Environment.NewLine}{reason}", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); return;
        }
        _signing = true; _stopRequested = false; _sourceCount = sources.Count; _successCount = 0; _failureCount = 0; UpdateProgress(); UpdateControls();
        var destination = Path.Combine(_folder, "signed"); Log($"Bắt đầu ký {_sourceCount} PDF tuần tự. Đích: {destination}");
        if (preferences.UseTsaTimestamp) Log($"TSA được bật: {preferences.TsaUrl}. Mỗi PDF chỉ thành công khi timestamp RFC 3161 được xác minh.");
        try
        {
            CertificateListItem currentCertificate;
            try { currentCertificate = _certificateStore.Revalidate(item); Log($"Đã kiểm tra lại chứng thư trước khi ký: {FormatTokenStatus(currentCertificate.KeyStorage.VerificationStatus)}."); }
            catch (Exception exception)
            {
                LogExceptionDetails("Không thể dùng chứng thư đã chọn", exception); MessageBox.Show(this, exception.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); return;
            }
            PdfSigningService.SigningSession signingSession;
            try { signingSession = _pdfSigning.CreateSession(currentCertificate, preferences.UseTsaTimestamp, preferences.TsaUrl); }
            catch (Exception exception)
            {
                LogExceptionDetails("Khởi tạo luồng ký", exception); MessageBox.Show(this, "Không thể khởi tạo CSP để ký. Xem nhật ký chẩn đoán.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); return;
            }
            using (signingSession)
            {
                foreach (var source in sources)
                {
                    if (_stopRequested) { Log("Đã dừng theo yêu cầu người dùng trước file kế tiếp."); break; }
                    var fileName = Path.GetFileName(source); _progressStatus.Text = $"Đang ký: {fileName}"; Log($"Bắt đầu: {fileName}");
                    if (preferences.UseTsaTimestamp) Log($"TSA: gửi yêu cầu RFC 3161 tới {preferences.TsaUrl}.");
                    try
                    {
                        var result = await _pdfSigning.SignAsync(source, destination, signingSession, displayName, _uppercaseSignatureText.Checked, _addSignedSuffix.Checked, CancellationToken.None);
                        _successCount++;
                        var timestampLog = result.Timestamp is null
                            ? string.Empty
                            : $" · TSA token: có; kiểm tra kỹ thuật đạt; genTime={result.Timestamp.GeneratedAt:O}; {FormatTsaTrust(result.Timestamp)}";
                        var appearance = result.Appearance;
                        Log($"Hoàn tất: {Path.GetFileName(result.OutputPath)} · {result.Elapsed.TotalSeconds:F1}s · CMS/ByteRange đã kiểm tra toàn vẹn · Widget trang 1: Rect=({appearance.Left:F1},{appearance.Bottom:F1},{appearance.Width:F1},{appearance.Height:F1}), /AP/N={appearance.AppearanceStreamLength} byte{timestampLog}.");
                    }
                    catch (Exception exception)
                    {
                        _failureCount++;
                        if (FindPdfSignatureProtectionException(exception) is { } protectionException)
                        {
                            Log($"Không xử lý: {fileName}; {protectionException.Message}");
                            foreach (var evidence in protectionException.Evidence)
                            {
                                Log($"Kiểm tra chữ ký nguồn: {evidence}");
                            }
                        }
                        if (FindTsaTimestampException(exception) is { } tsaException)
                        {
                            Log($"TSA token: không được chấp nhận; lỗi: {tsaException.Message}");
                        }
                        LogExceptionDetails($"Ký thất bại: {fileName}", exception);
                        if (IsProviderUnavailable(exception)) { Log("Dừng vì CSP/Token không còn sẵn sàng; các file còn lại chưa được xử lý."); break; }
                    }
                    finally { UpdateProgress(); }
                }
            }
        }
        finally
        {
            _signing = false;
            var processedCount = _successCount + _failureCount;
            _progressStatus.Text = _stopRequested
                ? $"Đã dừng. Thành công {_successCount}/{_sourceCount}; thất bại {_failureCount}."
                : processedCount < _sourceCount
                    ? $"Đã dừng do Token/CSP không sẵn sàng. Đã xử lý {processedCount}/{_sourceCount}; thành công {_successCount}; thất bại {_failureCount}."
                    : $"Hoàn tất. Thành công {_successCount}/{_sourceCount}; thất bại {_failureCount}.";
            UpdateProgress(); UpdateControls();
            MessageBox.Show(this, _progressStatus.Text, Text, MessageBoxButtons.OK, _failureCount == 0 ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }
    }

    private void RequestStop()
    {
        if (!_signing) return;
        _stopRequested = true; _stopButton.Enabled = false; _progressStatus.Text = "Sẽ dừng sau khi hoàn tất file đang ký.";
        Log("Đã nhận yêu cầu dừng; không ngắt cưỡng bức thao tác ký hoặc hộp thoại PIN.");
    }

    private void OpenOutputFolder()
    {
        if (_folder is null) return;
        var destination = Path.Combine(_folder, "signed");
        if (!Directory.Exists(destination)) { MessageBox.Show(this, "Thư mục signed chưa được tạo. Hãy ký ít nhất một PDF trước.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        try { Process.Start(new ProcessStartInfo { FileName = destination, UseShellExecute = true }); }
        catch (Exception exception) { LogExceptionDetails("Mở thư mục kết quả", exception); MessageBox.Show(this, "Không thể mở thư mục kết quả. Xem nhật ký để biết chi tiết.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    private void ShowCertificateDetails()
    {
        if (_certificateList.SelectedItem is not CertificateListItem item) { MessageBox.Show(this, "Chưa chọn chứng thư số.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        using var dialog = CreateReadOnlyDialog("Thông tin chứng thư số", BuildCertificateDetails(item), new Size(700, 440)); dialog.ShowDialog(this);
    }

    private void ShowLogDialog()
    {
        using var dialog = CreateReadOnlyDialog("Nhật ký", _logBuffer.ToString(), new Size(820, 560)); dialog.ShowDialog(this);
    }

    private void ShowAdvancedDialog()
    {
        var preferences = _preferencesStore.Load();
        using var dialog = new Form { Text = "Setting", StartPosition = FormStartPosition.CenterParent, FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false, MinimizeBox = false, ShowInTaskbar = false, ClientSize = new Size(610, 245) };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(16), ColumnCount = 2, RowCount = 5 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 185)); layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (var row = 0; row < 5; row++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var tsaUrl = new TextBox { Text = preferences.TsaUrl, MaxLength = 2_000, Dock = DockStyle.Fill };
        var useTsaTimestamp = new CheckBox { Text = "Sử dụng dấu thời gian TSA", Checked = preferences.UseTsaTimestamp, AutoSize = true };
        var showAllWindowsCertificates = new CheckBox { Text = "Hiển thị tất cả chứng thư Windows", Checked = _showAllWindowsCertificates, AutoSize = true };
        var tsaNotice = new Label { Text = "Khi bật, mỗi PDF phải có token RFC 3161 đúng nonce, message imprint và chữ ký TSA. TSA nội bộ không cần Windows/Adobe tin cậy để ký thành công.", AutoSize = true, MaximumSize = new Size(380, 0) };
        var tokenCheck = new Button { Text = "Kiểm tra ký Token", AutoSize = true, Enabled = CanCheckToken() }; tokenCheck.Click += (_, _) => CheckTokenSigning();
        var save = new Button { Text = "Lưu", AutoSize = true, DialogResult = DialogResult.OK }; var cancel = new Button { Text = "Hủy", AutoSize = true, DialogResult = DialogResult.Cancel };
        var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill }; buttons.Controls.Add(cancel); buttons.Controls.Add(save); buttons.Controls.Add(tokenCheck);
        layout.Controls.Add(new Label { Text = "Máy chủ dấu thời gian (TSA)", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0); layout.Controls.Add(tsaUrl, 1, 0);
        layout.Controls.Add(new Label { Text = "", AutoSize = true }, 0, 1); layout.Controls.Add(tsaNotice, 1, 1);
        layout.Controls.Add(new Label { Text = "Dấu thời gian", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 2); layout.Controls.Add(useTsaTimestamp, 1, 2);
        layout.Controls.Add(new Label { Text = "Danh sách chứng thư", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 3); layout.Controls.Add(showAllWindowsCertificates, 1, 3);
        layout.Controls.Add(buttons, 0, 4); layout.SetColumnSpan(buttons, 2); dialog.Controls.Add(layout); dialog.AcceptButton = save; dialog.CancelButton = cancel;
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        if (useTsaTimestamp.Checked && !TryValidateTsaUrl(tsaUrl.Text.Trim(), out var validationError)) { MessageBox.Show(this, validationError, Text, MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        _preferencesStore.Save(new SigningPreferences(_uppercaseSignatureText.Checked, tsaUrl.Text.Trim(), useTsaTimestamp.Checked));
        var reloadCertificates = _showAllWindowsCertificates != showAllWindowsCertificates.Checked;
        _showAllWindowsCertificates = showAllWindowsCertificates.Checked;
        if (reloadCertificates) ReloadCertificates();
        Log("Đã lưu cấu hình Setting cục bộ.");
    }

    private void CheckTokenSigning()
    {
        if (_signing || _checkingToken || _certificateList.SelectedItem is not CertificateListItem item) return;
        _checkingToken = true; UpdateControls();
        try
        {
            CertificateListItem currentCertificate;
            try { currentCertificate = _certificateStore.Revalidate(item); }
            catch (Exception exception) { LogExceptionDetails("Kiểm tra Token: chứng thư không sẵn sàng", exception); MessageBox.Show(this, "Chứng thư không sẵn sàng. Xem nhật ký chẩn đoán.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            Log("Bắt đầu kiểm tra CSP Token theo yêu cầu người dùng."); _cspDiagnostic.CheckSigning(currentCertificate, Log);
            Log("Kiểm tra ký Token thành công: CSP ký SHA-256 và public key chứng thư xác minh được.");
            MessageBox.Show(this, "CSP Token ký và xác minh SHA-256 thành công. Luồng ký PDF sẽ dùng CSP tường minh cho chứng thư này.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception exception) { LogExceptionDetails("Kiểm tra ký Token thất bại", exception); MessageBox.Show(this, "Kiểm tra CSP Token thất bại. Xem nhật ký chẩn đoán để biết giai đoạn và HRESULT.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        finally { _checkingToken = false; UpdateControls(); }
    }

    private void UpdateControls()
    {
        var canSign = !_signing && !_checkingToken && _sourceCount > 0 && _certificateList.SelectedItem is CertificateListItem item && item.InitialReadiness == CertificateReadiness.Ready;
        _signButton.Enabled = canSign; _stopButton.Enabled = _signing && !_stopRequested; _browseButton.Enabled = !_signing && !_checkingToken; _reloadCertificatesButton.Enabled = !_signing && !_checkingToken;
        _certificateList.Enabled = !_signing && !_checkingToken; _certificateInfoButton.Enabled = !_signing && _certificateList.SelectedItem is not null; _addSignedSuffix.Enabled = !_signing; _uppercaseSignatureText.Enabled = !_signing;
        _advancedButton.Enabled = !_signing && !_checkingToken; _openOutputButton.Enabled = !_signing && _folder is not null && Directory.Exists(Path.Combine(_folder, "signed"));
    }

    // The existing diagnostic explicitly opens CspParameters, so do not offer it for a KSP/CNG
    // certificate. The normal signing action is the user-initiated compatibility test for CNG.
    private bool CanCheckToken() => !_signing && !_checkingToken
        && _certificateList.SelectedItem is CertificateListItem { IsUsableForSigning: true, HasPrivateKey: true } item
        && item.InitialReadiness == CertificateReadiness.Ready
        && item.UsesLegacyCspKeyStorage;
    private static IReadOnlyList<string> GetSourcePdfs(string folder) => Directory.EnumerateFiles(folder, "*", SearchOption.TopDirectoryOnly).Where(path => string.Equals(Path.GetExtension(path), ".pdf", StringComparison.OrdinalIgnoreCase)).OrderBy(path => Path.GetFileName(path), StringComparer.CurrentCultureIgnoreCase).ToArray();
    private void UpdateProgress() { _totalValue.Text = _sourceCount.ToString(); _successValue.Text = _successCount.ToString(); _failureValue.Text = _failureCount.ToString(); }
    private static string? ResolveDisplayName(CertificateListItem item) => GetCommonName(item.Certificate);
    private static string? GetCommonName(X509Certificate2 certificate)
    {
        var match = Regex.Match(certificate.Subject, "(?:^|,\\s*)CN\\s*=\\s*(?<value>\"[^\"]*\"|(?:\\\\.|[^,])*)", RegexOptions.IgnoreCase);
        if (!match.Success) return null;
        var value = match.Groups["value"].Value.Trim().Trim('"');
        return value.Replace("\\,", ",", StringComparison.Ordinal).Replace("\\\"", "\"", StringComparison.Ordinal).Replace("\\\\", "\\", StringComparison.Ordinal).Trim();
    }

    private static string BuildCertificateDetails(CertificateListItem item)
    {
        var timeStatus = item.NotBefore <= DateTime.Now && item.NotAfter >= DateTime.Now ? "Trong thời hạn" : "Ngoài thời hạn";
        var keyStatus = item.HasPrivateKey ? "Có" : "Không";
        var lines = new List<string>
        {
            $"Đánh giá ban đầu: {item.ReadinessText}",
            $"Subject: {item.Certificate.Subject}",
            $"Issuer: {item.IssuerName}",
            $"Bắt đầu hiệu lực: {item.NotBefore:yyyy-MM-dd HH:mm:ss}",
            $"Hết hạn: {item.NotAfter:yyyy-MM-dd HH:mm:ss} ({timeStatus})",
            $"Khóa riêng: {keyStatus}; Key Usage phù hợp: {(item.AllowsDigitalSignature ? "Có" : "Không")}",
            $"Provider: {item.KeyStorage.ProviderName}",
            $"Container: {item.KeyStorage.ContainerName}",
            $"Provider type: {FormatNativeValue(item.KeyStorage.ProviderType)}; Key spec: {FormatNativeValue(item.KeyStorage.KeySpec)}",
            $"Liên kết provider: {FormatProviderLink(item.KeyStorage.ProviderLinkStatus)}",
            $"Loại khóa: {item.KeyStorage.KeyType}",
            $"Trạng thái Token: {FormatTokenStatus(item.KeyStorage.VerificationStatus)}",
            $"Thiết bị tháo rời: {FormatOptional(item.KeyStorage.IsRemovable)}; truy cập khóa: {FormatOptional(item.KeyStorage.IsAccessible)}",
            $"Chi tiết kiểm tra metadata: {item.KeyStorage.Detail}",
            $"Dấu vân tay: {item.Certificate.Thumbprint}"
        };
        if (item.EvaluationReasons.Count > 0)
        {
            lines.Add("Nguyên nhân cảnh báo:");
            lines.AddRange(item.EvaluationReasons.Select(reason => $"• {reason}"));
        }
        else if (item.InitialReadiness == CertificateReadiness.Unknown)
        {
            lines.Add(item.UsesCngKeyStorage
                ? "Nguyên nhân trạng thái chưa xác định: metadata cho thấy KSP/CNG nhưng không thỏa điều kiện RSA/provider Smart Card cho nhánh CNG hiện có."
                : "Nguyên nhân trạng thái chưa xác định: metadata provider chưa đủ để xác nhận đường truy cập khóa; không mở private key khi xem chi tiết.");
        }
        else
        {
            lines.Add("Chứng thư đáp ứng các điều kiện metadata ban đầu. Điều này không xác nhận USB Token đang cắm hoặc khóa riêng sử dụng được.");
        }
        return string.Join(Environment.NewLine, lines);
    }

    private static Form CreateReadOnlyDialog(string title, string content, Size size)
    {
        var dialog = new Form { Text = title, StartPosition = FormStartPosition.CenterParent, Size = size, MinimumSize = new Size(480, 320) };
        var text = new TextBox { ReadOnly = true, Multiline = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, BackColor = SystemColors.Window, Text = content };
        var close = new Button { Text = "Đóng", AutoSize = true, DialogResult = DialogResult.OK };
        var footer = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 42, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8) }; footer.Controls.Add(close);
        dialog.Controls.Add(text); dialog.Controls.Add(footer); dialog.AcceptButton = close; return dialog;
    }

    private static bool IsProviderUnavailable(Exception exception)
    {
        const int nteProviderDllFail = unchecked((int)0x8009001D);
        for (var current = exception; current is not null; current = current.InnerException) if (current is CryptographicException && current.HResult == nteProviderDllFail) return true;
        return false;
    }
    private static string FormatOptional(bool? value) => value switch { true => "Có", false => "Không", null => "Chưa xác minh" };
    private static string FormatTokenStatus(TokenVerificationStatus status) => status switch { TokenVerificationStatus.HardwareVerified => "Đã xác minh phần cứng", TokenVerificationStatus.SoftwareVerified => "Windows xác định khóa phần mềm", TokenVerificationStatus.PrivateKeyUnavailable => "Không truy cập được khóa riêng", _ => "Chưa xác minh" };
    private static string FormatProviderLink(ProviderLinkStatus status) => status switch { ProviderLinkStatus.SmartCardProviderLinked => "Liên kết Smart Card - chưa xác minh kết nối", ProviderLinkStatus.SoftwareProviderLinked => "Liên kết provider phần mềm", ProviderLinkStatus.ProviderLinkedUnclassified => "Provider chưa phân loại", _ => "Không có metadata provider" };
    private static string FormatNativeValue(uint? value) => value is null ? "Không có" : $"{value.Value} (0x{value.Value:X8})";
    private static TsaTimestampException? FindTsaTimestampException(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is TsaTimestampException tsaException) return tsaException;
        }

        return null;
    }

    private static PdfSignatureProtectionException? FindPdfSignatureProtectionException(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is PdfSignatureProtectionException protectionException) return protectionException;
        }

        return null;
    }

    private static string FormatTsaTrust(TimestampResult timestamp) => timestamp.TrustStatus switch
    {
        TsaTrustStatus.TrustedByWindows => "TSA được Windows tin cậy",
        TsaTrustStatus.NotTrustedByWindows => $"TSA chưa được Windows tin cậy ({timestamp.TrustDetails})",
        _ => $"Chưa đánh giá được trust TSA ({timestamp.TrustDetails})"
    };
    private void LogExceptionDetails(string context, Exception exception)
    {
        var depth = 0;
        for (var current = exception; current is not null; current = current.InnerException)
        {
            var stage = current switch { SigningStageException staged => $"; giai đoạn={staged.Stage}", CspDiagnosticException diagnostic => $"; giai đoạn={diagnostic.Stage}", _ => string.Empty };
            Log($"{context}{stage}; lớp={current.GetType().FullName}; HRESULT=0x{current.HResult:X8}; lỗi={current.Message}");
            if (!string.IsNullOrWhiteSpace(current.StackTrace)) Log($"Stack[{depth}]: {current.StackTrace}");
            depth++;
        }
    }
    private static bool TryValidateTsaUrl(string value, out string error)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) || string.IsNullOrWhiteSpace(uri.Host))
        { error = "Máy chủ TSA phải là URL HTTP hoặc HTTPS hợp lệ, ví dụ http://tsa.ca.gov.vn."; return false; }
        error = string.Empty; return true;
    }
    private void Log(string message) => _logBuffer.Append($"{DateTimeOffset.Now:HH:mm:ss}  {message}{Environment.NewLine}");
}
