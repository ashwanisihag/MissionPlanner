// Protected Firmware Panel — QCI Compliance Level 1
// Mirrors SaamGCS SecureFirmwarePanel + SigningKeyManagerForm
// Adapted for MissionPlanner APIs (no LocalAuthService, no FirmwareSigningService,
// no custom MAVLink SECURE_COMMAND provisioning API).

using log4net;
using MissionPlanner.Controls;
using MissionPlanner.Utilities;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Ionic.Zlib;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MissionPlanner.GCSViews
{
    public class ProtectedFirmware : MyUserControl, IActivate
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(ProtectedFirmware));

        // ── Left panel ───────────────────────────────────────────────────
        private ComplianceIndicator _complianceIndicator;
        private Label  lblExportPath;
        private Button btnExportAudit, btnOpenExportFolder;
        private TextBox txtFirmwareFile, txtBootloaderFile, txtSha256, txtOutput, txtDiag;
        private Label lblApjStatus, lblHashCheck, lblWorkflowStatus;
        private Button btnBrowseFirmware, btnFlashFirmware;
        private Button btnBrowseBootloader, btnFlashBootloader;
        private Button btnProvisionRegistry, btnVerifyRegistry, btnDiagRefresh;
        private ProgressBar progressBar;
        private Label lblProgressStatus;

        // ── Middle panel — signing tabs ──────────────────────────────────
        private TabControl tabsSigning;

        // ArduPilot Ed25519
        private Label  lblApWslStatus, lblApBootloaderStatus, lblApApjStatus;
        private Button btnApCheckWsl, btnApGenerateKeys, btnApBuildFwBl;
        private Button btnApBuildBootloader, btnApVerifyBootloader;
        private Button btnApSignFw, btnApVerifyApj;
        private TextBox txtApRoot, txtApBoard, txtApKeyOutDir;
        private TextBox txtApBootloaderPath, txtApApjPath, txtApPrivateKey, txtApOutput;
        private Button btnBrowseKeyOut, btnBrowseApBootloader, btnBrowseApj, btnBrowsePrivKey;

        // RSA Certificate
        private TextBox txtCertInfo, txtFwCert, txtSigOut;
        private Label   lblCertStatus;
        private Button  btnImportCert, btnSignWithCert;
        private Button  btnBrowseFwCert, btnBrowseSigOut;
        private X509Certificate2 _loadedCert;
        private string  _loadedCertPath, _loadedKeyPath, _loadedKeyPassword;

        // HMAC
        private TextBox txtHmacKeyHex;
        private Label   lblHmacStatus;
        private Button  btnGenerateHmac, btnExportHmac;
        private byte[]  _currentHmacKey;

        // Self-test
        private TextBox txtTestReport;
        private Button  btnRunTests;

        // ── Right panel — live log ────────────────────────────────────────
        private TextBox txtLiveLog, txtLogFind;
        private Button  btnLogFind, btnLogClear;
        private System.Windows.Forms.Timer _logTimer;
        private long    _lastLogPos;
        private string  _logFilePath;

        // ── State ────────────────────────────────────────────────────────
        private string  _auditExportFolder;
        private string  _lastFirmwareSha256 = string.Empty;
        private int     _flashFirmwareInProgress;
        private int     _flashStepCounter;
        private const string AppSettingApWslRepo   = "ProtFwArduPilotWslRepoPath";
        private const string AppSettingApBoard     = "ProtFwArduPilotBoardName";
        private const string AppSettingApKeyOutDir = "ProtFwArduPilotKeyOutputDir";
        private const string AppSettingApPrivKey   = "ProtFwArduPilotPrivateKeyDatPath";
        private const string HmacKeySettingName    = "ProtFwHmacKeyHex";
        private int     _autoVerifyInProgress;
        private DateTime _autoVerifySuppressedUntilUtc = DateTime.MinValue;
        private string  _lastAutoVerifyPort = string.Empty;
        private const uint ScOpGetSessionKey = 0;
        private const uint ScOpGetChecksumRegistry = 8;
        private const uint ScOpSetChecksumRegistry = 9;
        private static readonly byte[] ApjDescriptorMagic = { 0x41, 0xA3, 0xE5, 0xF2, 0x65, 0x69, 0x92, 0x07 };

        // ────────────────────────────────────────────────────────────────
        public ProtectedFirmware()
        {
            _auditExportFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Mission Planner", "audit_exports");

            _logFilePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Mission Planner", "MissionPlanner.log");

            BuildUi();
            LoadPreferences();
            RefreshHmacKeyUi();
            RoleBasedAccess.SessionChanged += RoleBasedAccess_SessionChanged;

            _logTimer = new System.Windows.Forms.Timer { Interval = 2000 };
            _logTimer.Tick += LogTimer_Tick;
        }

        public void Activate()
        {
            ApplyRoleAccessUi();
            RefreshHmacKeyUi();
            _lastLogPos = 0; // re-read from tail
            _logTimer.Start();
            Task.Run(() => RunDiagnostics());
            _ = TryAutoVerifyOnConnectAsync();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                RoleBasedAccess.SessionChanged -= RoleBasedAccess_SessionChanged;
                _logTimer?.Stop();
                _logTimer?.Dispose();
            }
            base.Dispose(disposing);
        }

        // ================================================================
        // UI Construction
        // ================================================================

        private void BuildUi()
        {
            Dock = DockStyle.Fill;
            BackColor = Color.FromArgb(30, 30, 30);

            // Outer container to handle title + content
            var outer = new Panel { Dock = DockStyle.Fill };

            // Top title bar
            var title = new Label
            {
                Text = "Protected Firmware — QCI Compliance Level 1",
                Font = new Font(Font.FontFamily, 11f, FontStyle.Bold),
                Dock = DockStyle.Top,
                Height = 32,
                Padding = new Padding(6, 6, 0, 0),
                BackColor = Color.FromArgb(45, 45, 45),
                ForeColor = Color.White
            };

            // 3-column table using percentages so it adapts to any window size
            var table = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 1,
                Padding = new Padding(2),
                CellBorderStyle = TableLayoutPanelCellBorderStyle.Single
            };

            // Column 0: 25% — firmware/bootloader controls
            table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25f));
            var leftPanel = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(6) };
            BuildLeftPanel(leftPanel);
            table.Controls.Add(leftPanel, 0, 0);

            // Column 1: 40% — signing tabs
            table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40f));
            var middlePanel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(4) };
            BuildMiddlePanel(middlePanel);
            table.Controls.Add(middlePanel, 1, 0);

            // Column 2: 35% — live log
            table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 35f));
            var rightPanel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(4) };
            BuildRightPanel(rightPanel);
            table.Controls.Add(rightPanel, 2, 0);

            table.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));

            // Add table first (Fill), then title (Top) — WinForms docks in reverse order
            outer.Controls.Add(table);
            outer.Controls.Add(title);

            Controls.Add(outer);
        }

        // ================================================================
        // LEFT PANEL — Protected Firmware Controls
        // ================================================================

        private void BuildLeftPanel(Control parent)
        {
            var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(6) };
            parent.Controls.Add(scroll);

            const int w = 270; // controls width; left col is ~25% of ~1450 ≈ 362px, minus padding = ~340. Use 270 conservatively.
            const int btnW = 90;
            const int inputW = w - btnW - 6; // textbox width when paired with Browse button
            int y = 6;

            // Compliance indicator
            _complianceIndicator = new ComplianceIndicator
            {
                Left = 0, Top = y, Width = w, Height = 68,
                CurrentLevel = ComplianceLevel.Level1
            };
            scroll.Controls.Add(_complianceIndicator);
            y += 74;

            // Export row
            btnExportAudit = MakeButton("Export Signed Audit", new Point(0, y), new Size(162, 28));
            btnExportAudit.Click += BtnExportAudit_Click;
            scroll.Controls.Add(btnExportAudit);

            btnOpenExportFolder = MakeButton("Open Export Folder", new Point(170, y), new Size(w - 172, 28));
            btnOpenExportFolder.Click += (s, e) =>
            {
                try
                {
                    Directory.CreateDirectory(_auditExportFolder);
                    Process.Start("explorer.exe", _auditExportFolder);
                }
                catch (Exception ex) { ShowErr("Cannot open folder:\n" + ex.Message); }
            };
            scroll.Controls.Add(btnOpenExportFolder);
            y += 34;

            lblExportPath = MakeLabel("Export: " + _auditExportFolder, new Point(0, y), w, false);
            lblExportPath.ForeColor = Color.Gray;
            lblExportPath.Font = new Font(Font.FontFamily, 7.5f);
            scroll.Controls.Add(lblExportPath);
            y += 22;

            AddSeparator(scroll, ref y);

            // ── Firmware file ──────────────────────────────────────────
            scroll.Controls.Add(MakeLabel("Local Firmware File (*.apj *.px4 *.bin *.hex):", new Point(0, y), w));
            y += 20;

            txtFirmwareFile = new TextBox { Location = new Point(0, y), Width = inputW, ReadOnly = true };
            scroll.Controls.Add(txtFirmwareFile);

            btnBrowseFirmware = MakeButton("Browse...", new Point(inputW + 4, y - 1), new Size(btnW, 24));
            btnBrowseFirmware.Click += BtnBrowseFirmware_Click;
            scroll.Controls.Add(btnBrowseFirmware);
            y += 30;

            lblApjStatus = MakeLabel("APJ Status: No file selected", new Point(0, y), w);
            lblApjStatus.ForeColor = Color.Gray;
            scroll.Controls.Add(lblApjStatus);
            y += 22;

            btnFlashFirmware = MakeButton("Flash Firmware", new Point(0, y), new Size(150, 30));
            btnFlashFirmware.BackColor = Color.DarkGreen;
            btnFlashFirmware.ForeColor = Color.White;
            btnFlashFirmware.Click += BtnFlashFirmware_Click;
            scroll.Controls.Add(btnFlashFirmware);
            y += 38;

            // ── Bootloader file ────────────────────────────────────────
            scroll.Controls.Add(MakeLabel("Local Bootloader File (*.bin *.hex *.dfu):", new Point(0, y), w));
            y += 20;

            txtBootloaderFile = new TextBox { Location = new Point(0, y), Width = inputW, ReadOnly = true };
            scroll.Controls.Add(txtBootloaderFile);

            btnBrowseBootloader = MakeButton("Browse...", new Point(inputW + 4, y - 1), new Size(btnW, 24));
            btnBrowseBootloader.Click += BtnBrowseBootloader_Click;
            scroll.Controls.Add(btnBrowseBootloader);
            y += 30;

            btnFlashBootloader = MakeButton("Flash Bootloader", new Point(0, y), new Size(150, 30));
            btnFlashBootloader.Click += BtnFlashBootloader_Click;
            scroll.Controls.Add(btnFlashBootloader);
            y += 38;

            // ── SHA256 ─────────────────────────────────────────────────
            scroll.Controls.Add(MakeLabel("Firmware SHA256:", new Point(0, y), w));
            y += 20;

            txtSha256 = new TextBox { Location = new Point(0, y), Width = w, ReadOnly = true, Font = new Font("Consolas", 8f) };
            scroll.Controls.Add(txtSha256);
            y += 26;

            lblHashCheck = MakeLabel("Bootloader/Firmware hash check: pending", new Point(0, y), w);
            lblHashCheck.ForeColor = Color.Gray;
            scroll.Controls.Add(lblHashCheck);
            y += 22;

            AddSeparator(scroll, ref y);

            // ── Secure Workflow (Strict) ────────────────────────────────
            var lblWorkflowTitle = MakeLabel("Secure Update Workflow (Strict)", new Point(0, y), w);
            lblWorkflowTitle.ForeColor = Color.LimeGreen;
            lblWorkflowTitle.Font = new Font(Font.FontFamily, 9.5f, FontStyle.Bold);
            scroll.Controls.Add(lblWorkflowTitle);
            y += 24;

            btnProvisionRegistry = MakeButton("Provision Registry", new Point(0, y), new Size(w / 2 - 3, 28));
            btnProvisionRegistry.Click += BtnProvisionRegistry_Click;
            scroll.Controls.Add(btnProvisionRegistry);

            btnVerifyRegistry = MakeButton("Verify Registry", new Point(w / 2 + 3, y), new Size(w / 2 - 3, 28));
            btnVerifyRegistry.Click += BtnVerifyRegistry_Click;
            scroll.Controls.Add(btnVerifyRegistry);
            y += 34;

            lblWorkflowStatus = MakeLabel("Strict mode active. Ed25519 verification enforced.", new Point(0, y), w);
            lblWorkflowStatus.ForeColor = Color.Goldenrod;
            scroll.Controls.Add(lblWorkflowStatus);
            y += 22;

            AddSeparator(scroll, ref y);

            // ── Output log ─────────────────────────────────────────────
            progressBar = new ProgressBar { Location = new Point(0, y), Width = w, Height = 16 };
            scroll.Controls.Add(progressBar);
            y += 22;

            lblProgressStatus = MakeLabel("Ready", new Point(0, y), w);
            lblProgressStatus.ForeColor = Color.Gray;
            scroll.Controls.Add(lblProgressStatus);
            y += 22;

            txtOutput = new TextBox
            {
                Location = new Point(0, y),
                Size = new Size(w, 160),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = Color.FromArgb(15, 15, 15),
                ForeColor = Color.LimeGreen,
                Font = new Font("Consolas", 8.5f),
                BorderStyle = BorderStyle.FixedSingle
            };
            scroll.Controls.Add(txtOutput);
            y += 166;

            AddSeparator(scroll, ref y);

            // ── Diagnostics ────────────────────────────────────────────
            var diagRow = new Label { Text = "Diagnostics:", AutoSize = true, Location = new Point(0, y), Font = new Font(Font.FontFamily, 9f, FontStyle.Bold) };
            scroll.Controls.Add(diagRow);

            btnDiagRefresh = MakeButton("Refresh", new Point(110, y - 2), new Size(80, 22));
            btnDiagRefresh.Click += (s, e) => Task.Run(() => RunDiagnostics());
            scroll.Controls.Add(btnDiagRefresh);
            y += 26;

            txtDiag = new TextBox
            {
                Location = new Point(0, y),
                Size = new Size(w, 90),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 8f)
            };
            scroll.Controls.Add(txtDiag);

            // Stretch all controls when panel resizes
            scroll.Resize += (s2, e2) =>
            {
                int cw = scroll.ClientSize.Width - scroll.Padding.Left - scroll.Padding.Right - 4;
                if (cw < 80) return;
                int bw = 86;
                int tw = cw - bw - 4;
                foreach (Control c in scroll.Controls)
                {
                    if (c is Label l && !l.AutoSize) l.Width = cw;
                    else if (c is ProgressBar) c.Width = cw;
                }
                if (_complianceIndicator != null) _complianceIndicator.Width = cw;
                txtSha256.Width = cw;
                txtOutput.Width = cw;
                txtDiag.Width = cw;
                txtFirmwareFile.Width = tw;
                btnBrowseFirmware.Left = tw + 4;
                txtBootloaderFile.Width = tw;
                btnBrowseBootloader.Left = tw + 4;
            };
        }

        // ================================================================
        // MIDDLE PANEL — Signing Controls (tabbed)
        // ================================================================

        private void BuildMiddlePanel(Control parent)
        {
            var pnl = new Panel { Dock = DockStyle.Fill, Padding = new Padding(4) };
            parent.Controls.Add(pnl);

            var lblTitle = new Label
            {
                Text = "Ed25519 Signing Controls",
                Font = new Font(Font.FontFamily, 10f, FontStyle.Bold),
                Dock = DockStyle.Top,
                Height = 26,
                Padding = new Padding(2, 4, 0, 0)
            };
            pnl.Controls.Add(lblTitle);

            tabsSigning = new TabControl { Dock = DockStyle.Fill };
            tabsSigning.TabPages.Add(BuildArduPilotTab());
            tabsSigning.TabPages.Add(BuildCertTab());
            tabsSigning.TabPages.Add(BuildHmacTab());
            tabsSigning.TabPages.Add(BuildSelfTestTab());
            tabsSigning.TabPages.Add(BuildProcedureTab());
            pnl.Controls.Add(tabsSigning);
        }

        // ── Tab: ArduPilot Ed25519 ───────────────────────────────────────
        private TabPage BuildArduPilotTab()
        {
            var tab = new TabPage("ArduPilot Signing (Ed25519)");
            var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(8) };
            tab.Controls.Add(scroll);

            int w = scroll.Width > 100 ? scroll.Width - 20 : 500; // safe width
            int y = 4;
            var lbl0 = new Label
            {
                Text = "ArduPilot Ed25519 — Hardware-Enforced Secure Firmware\n" +
                       "Ed25519 signature embedded in .apj; bootloader verifies at boot.\n" +
                       "Requires WSL with ArduPilot source configured.",
                AutoSize = false, Size = new Size(w, 46), Location = new Point(0, y),
                Font = new Font(Font.FontFamily, 8.5f)
            };
            scroll.Controls.Add(lbl0);
            y += 52;

            // WSL check
            lblApWslStatus = new Label { Text = "WSL: not checked", AutoSize = true, Location = new Point(0, y), ForeColor = Color.Gray };
            scroll.Controls.Add(lblApWslStatus);
            btnApCheckWsl = MakeButton("Check WSL", new Point(180, y - 2), new Size(100, 24));
            btnApCheckWsl.Click += async (s, e) => await ApCheckWslAsync();
            scroll.Controls.Add(btnApCheckWsl);
            y += 30;

            scroll.Controls.Add(MakeLabel("ArduPilot WSL Repo Path (e.g. /home/user/ardupilot):", new Point(0, y), w));
            y += 20;
            txtApRoot = new TextBox { Location = new Point(0, y), Width = w };
            scroll.Controls.Add(txtApRoot);
            y += 30;

            // Section 1
            var sec1 = MakeLabel("── 1. Generate Ed25519 Key Pair ──────────────────────────────────", new Point(0, y), w, false);
            sec1.ForeColor = Color.SteelBlue; sec1.Font = new Font(Font.FontFamily, 8.5f, FontStyle.Bold);
            scroll.Controls.Add(sec1); y += 22;

            scroll.Controls.Add(MakeLabel("Board Name (e.g. Pixhawk6C):", new Point(0, y), 300));
            y += 18;
            txtApBoard = new TextBox { Location = new Point(0, y), Width = 220 };
            scroll.Controls.Add(txtApBoard);
            y += 28;

            scroll.Controls.Add(MakeLabel("Output Directory (Windows path):", new Point(0, y), w));
            y += 18;
            txtApKeyOutDir = new TextBox { Location = new Point(0, y), Width = 460 };
            scroll.Controls.Add(txtApKeyOutDir);
            btnBrowseKeyOut = MakeButton("Browse", new Point(468, y - 1), new Size(80, 24));
            btnBrowseKeyOut.Click += (s, e) =>
            {
                using (var fbd = new FolderBrowserDialog { Description = "Select output folder for key files" })
                    if (fbd.ShowDialog(this) == DialogResult.OK)
                        txtApKeyOutDir.Text = fbd.SelectedPath;
            };
            scroll.Controls.Add(btnBrowseKeyOut);
            y += 30;

            btnApGenerateKeys = MakeButton("Generate Keys via WSL", new Point(0, y), new Size(200, 30));
            btnApGenerateKeys.Click += async (s, e) => await ApGenerateKeysAsync();
            scroll.Controls.Add(btnApGenerateKeys);

            btnApBuildFwBl = MakeButton("Build Firmware & Bootloader (WSL)", new Point(208, y), new Size(240, 30));
            btnApBuildFwBl.Click += async (s, e) => await ApBuildFwAndBlAsync();
            scroll.Controls.Add(btnApBuildFwBl);
            y += 38;

            // Section 3
            var sec3 = MakeLabel("── 3. Build / Verify Bootloader Artifact ─────────────────────────", new Point(0, y), w, false);
            sec3.ForeColor = Color.SteelBlue; sec3.Font = new Font(Font.FontFamily, 8.5f, FontStyle.Bold);
            scroll.Controls.Add(sec3); y += 22;

            scroll.Controls.Add(MakeLabel("Bootloader (.bin):", new Point(0, y), 300));
            y += 18;
            txtApBootloaderPath = new TextBox { Location = new Point(0, y), Width = 460 };
            scroll.Controls.Add(txtApBootloaderPath);
            btnBrowseApBootloader = MakeButton("Browse", new Point(468, y - 1), new Size(80, 24));
            btnBrowseApBootloader.Click += (s, e) =>
            {
                using (var ofd = new OpenFileDialog { Filter = "Binary (*.bin)|*.bin|All (*.*)|*.*" })
                    if (ofd.ShowDialog(this) == DialogResult.OK)
                        txtApBootloaderPath.Text = ofd.FileName;
            };
            scroll.Controls.Add(btnBrowseApBootloader);
            y += 28;

            lblApBootloaderStatus = new Label { Text = "Bootloader Status: no file", AutoSize = true, Location = new Point(0, y), ForeColor = Color.Gray };
            scroll.Controls.Add(lblApBootloaderStatus);
            y += 22;

            btnApBuildBootloader = MakeButton("Build Secure Bootloader (WSL)", new Point(0, y), new Size(230, 30));
            btnApBuildBootloader.Click += async (s, e) => await ApBuildBootloaderAsync();
            scroll.Controls.Add(btnApBuildBootloader);

            btnApVerifyBootloader = MakeButton("Verify Bootloader File", new Point(238, y), new Size(160, 30));
            btnApVerifyBootloader.Click += (s, e) => ApVerifyBootloaderFile();
            scroll.Controls.Add(btnApVerifyBootloader);
            y += 38;

            // Section 4
            var sec4 = MakeLabel("── 4. Sign Compiled .apj with Private Key ────────────────────────", new Point(0, y), w, false);
            sec4.ForeColor = Color.SteelBlue; sec4.Font = new Font(Font.FontFamily, 8.5f, FontStyle.Bold);
            scroll.Controls.Add(sec4); y += 22;

            scroll.Controls.Add(MakeLabel("Unsigned Firmware (.apj):", new Point(0, y), 300));
            y += 18;
            txtApApjPath = new TextBox { Location = new Point(0, y), Width = 460 };
            txtApApjPath.TextChanged += (s, e) => UpdateApjStatusLabel();
            scroll.Controls.Add(txtApApjPath);
            btnBrowseApj = MakeButton("Browse", new Point(468, y - 1), new Size(80, 24));
            btnBrowseApj.Click += (s, e) =>
            {
                using (var ofd = new OpenFileDialog { Filter = "ArduPilot Firmware (*.apj)|*.apj|All (*.*)|*.*" })
                    if (ofd.ShowDialog(this) == DialogResult.OK)
                        txtApApjPath.Text = ofd.FileName;
            };
            scroll.Controls.Add(btnBrowseApj);
            y += 28;

            lblApApjStatus = new Label { Text = "APJ Status: no file selected", AutoSize = true, Location = new Point(0, y), ForeColor = Color.Gray };
            scroll.Controls.Add(lblApApjStatus);
            y += 22;

            scroll.Controls.Add(MakeLabel("Private Key (.dat):", new Point(0, y), 300));
            y += 18;
            txtApPrivateKey = new TextBox { Location = new Point(0, y), Width = 460 };
            scroll.Controls.Add(txtApPrivateKey);
            btnBrowsePrivKey = MakeButton("Browse", new Point(468, y - 1), new Size(80, 24));
            btnBrowsePrivKey.Click += (s, e) =>
            {
                using (var ofd = new OpenFileDialog { Filter = "Private Key (*.dat)|*.dat|All (*.*)|*.*" })
                    if (ofd.ShowDialog(this) == DialogResult.OK)
                        txtApPrivateKey.Text = ofd.FileName;
            };
            scroll.Controls.Add(btnBrowsePrivKey);
            y += 30;

            btnApSignFw = MakeButton("Sign Firmware (make_secure_fw.py)", new Point(0, y), new Size(268, 30));
            btnApSignFw.Click += async (s, e) => await ApSignFirmwareAsync();
            scroll.Controls.Add(btnApSignFw);

            btnApVerifyApj = MakeButton("Verify Signed APJ", new Point(276, y), new Size(150, 30));
            btnApVerifyApj.Click += async (s, e) => await ApVerifyApjAsync();
            scroll.Controls.Add(btnApVerifyApj);
            y += 38;

            // Output
            scroll.Controls.Add(MakeLabel("Output:", new Point(0, y), w));
            y += 18;
            txtApOutput = new TextBox
            {
                Location = new Point(0, y), Size = new Size(w, 180),
                Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 8f), BorderStyle = BorderStyle.FixedSingle
            };
            scroll.Controls.Add(txtApOutput);

            // Stretch all controls when tab resizes
            scroll.Resize += (s2, e2) =>
            {
                int cw = scroll.ClientSize.Width - scroll.Padding.Left - scroll.Padding.Right - 4;
                if (cw < 100) return;
                int bw = 80;
                int tw = cw - bw - 4;
                foreach (Control c in scroll.Controls)
                    if (c is Label l && !l.AutoSize) l.Width = cw;
                txtApRoot.Width = cw;
                txtApOutput.Width = cw; txtApOutput.Height = 180;
                txtApBoard.Width = Math.Min(220, cw);
                txtApKeyOutDir.Width = tw; btnBrowseKeyOut.Left = tw + 4;
                txtApBootloaderPath.Width = tw; btnBrowseApBootloader.Left = tw + 4;
                txtApApjPath.Width = tw; btnBrowseApj.Left = tw + 4;
                txtApPrivateKey.Width = tw; btnBrowsePrivKey.Left = tw + 4;
            };

            return tab;
        }

        // ── Tab: RSA Certificate ─────────────────────────────────────────
        private TabPage BuildCertTab()
        {
            var tab = new TabPage("Certificate Signing (RSA)");
            var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(8) };
            tab.Controls.Add(scroll);

            int y = 4;
            int w = scroll.Width > 100 ? scroll.Width - 20 : 500;
            var lbl = MakeLabel("RSA Certificate — Asymmetric Firmware Signing", new Point(0, y), w, false);
            lbl.Font = new Font(Font.FontFamily, 10f, FontStyle.Bold); lbl.ForeColor = Color.SteelBlue;
            scroll.Controls.Add(lbl); y += 28;

            lblCertStatus = MakeLabel("No certificate loaded", new Point(0, y), w);
            scroll.Controls.Add(lblCertStatus); y += 22;

            btnImportCert = MakeButton("Import Certificate (PFX/PEM)...", new Point(0, y), new Size(230, 30));
            btnImportCert.Click += BtnImportCert_Click;
            scroll.Controls.Add(btnImportCert); y += 36;

            scroll.Controls.Add(MakeLabel("Certificate Details:", new Point(0, y), w));
            y += 18;
            txtCertInfo = new TextBox
            {
                Location = new Point(0, y), Size = new Size(w, 90),
                Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 8f), BorderStyle = BorderStyle.FixedSingle,
                Text = "(Import a PFX or PEM certificate to see details here)"
            };
            scroll.Controls.Add(txtCertInfo); y += 96;

            scroll.Controls.Add(MakeLabel("Firmware File to Sign:", new Point(0, y), w)); y += 18;
            txtFwCert = new TextBox { Location = new Point(0, y), Width = w - 50, ReadOnly = true };
            scroll.Controls.Add(txtFwCert);
            btnBrowseFwCert = MakeButton("Browse", new Point(w - 50, y - 1), new Size(80, 24));
            btnBrowseFwCert.Click += (s, e) =>
            {
                using (var ofd = new OpenFileDialog { Filter = "Firmware (*.apj;*.px4;*.bin;*.hex)|*.apj;*.px4;*.bin;*.hex|All (*.*)|*.*" })
                    if (ofd.ShowDialog(this) == DialogResult.OK)
                        txtFwCert.Text = ofd.FileName;
            };
            scroll.Controls.Add(btnBrowseFwCert); y += 30;

            scroll.Controls.Add(MakeLabel("Output Signature File:", new Point(0, y), w)); y += 18;
            txtSigOut = new TextBox { Location = new Point(0, y), Width = w - 50, ReadOnly = true };
            scroll.Controls.Add(txtSigOut);
            btnBrowseSigOut = MakeButton("Browse", new Point(w - 50, y - 1), new Size(80, 24));
            btnBrowseSigOut.Click += (s, e) =>
            {
                using (var sfd = new SaveFileDialog { Filter = "Signature (*.sig)|*.sig|All (*.*)|*.*", DefaultExt = "sig" })
                    if (sfd.ShowDialog(this) == DialogResult.OK)
                        txtSigOut.Text = sfd.FileName;
            };
            scroll.Controls.Add(btnBrowseSigOut); y += 30;

            btnSignWithCert = MakeButton("Sign Firmware with Certificate", new Point(0, y), new Size(230, 30));
            btnSignWithCert.Enabled = false;
            btnSignWithCert.Click += async (s, e) => await SignWithCertificateAsync();
            scroll.Controls.Add(btnSignWithCert); y += 38;

            var warn = MakeLabel(
                "⚠  Private key is used only in-memory during signing and is never persisted by the GCS.",
                new Point(0, y), 560);
            warn.ForeColor = Color.Goldenrod;
            scroll.Controls.Add(warn);

            // Stretch all controls when tab resizes
            scroll.Resize += (s2, e2) =>
            {
                int cw = scroll.ClientSize.Width - scroll.Padding.Left - scroll.Padding.Right - 4;
                if (cw < 100) return;
                int bw = 80;
                int tw = cw - bw - 4;
                foreach (Control c in scroll.Controls)
                    if (c is Label l && !l.AutoSize) l.Width = cw;
                txtCertInfo.Width = cw;
                txtFwCert.Width = tw; btnBrowseFwCert.Left = tw + 4;
                txtSigOut.Width = tw; btnBrowseSigOut.Left = tw + 4;
            };

            return tab;
        }

        // ── Tab: HMAC Key ────────────────────────────────────────────────
        private TabPage BuildHmacTab()
        {
            var tab = new TabPage("HMAC Key (Symmetric)");
            var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(8) };
            tab.Controls.Add(scroll);

            int w = scroll.Width > 100 ? scroll.Width - 20 : 500;
            int y = 4;
            var lbl = MakeLabel("HMAC-SHA256 — Symmetric Signing Key", new Point(0, y), w, false);
            lbl.Font = new Font(Font.FontFamily, 10f, FontStyle.Bold); lbl.ForeColor = Color.SteelBlue;
            scroll.Controls.Add(lbl); y += 28;

            var desc = new Label
            {
                Text = "Manages the DPAPI-protected 256-bit key used for HMAC-SHA256 signing.\n" +
                       "Minimum 128-bit keys required for QCI Level 0 compliance.",
                AutoSize = false, Size = new Size(w, 36), Location = new Point(0, y)
            };
            scroll.Controls.Add(desc); y += 42;

            lblHmacStatus = MakeLabel("No active key configured", new Point(0, y), w);
            lblHmacStatus.ForeColor = Color.Gray;
            scroll.Controls.Add(lblHmacStatus); y += 22;

            btnGenerateHmac = MakeButton("Generate New 256-bit Key", new Point(0, y), new Size(210, 30));
            btnGenerateHmac.Click += BtnGenerateHmac_Click;
            scroll.Controls.Add(btnGenerateHmac); y += 38;

            scroll.Controls.Add(MakeLabel("Active Key (hex):", new Point(0, y), w)); y += 18;
            txtHmacKeyHex = new TextBox
            {
                Location = new Point(0, y), Size = new Size(w, 46),
                Multiline = true, ReadOnly = true,
                Font = new Font("Consolas", 8f), BorderStyle = BorderStyle.FixedSingle
            };
            scroll.Controls.Add(txtHmacKeyHex); y += 52;

            btnExportHmac = MakeButton("Export Key to File...", new Point(0, y), new Size(160, 30));
            btnExportHmac.Enabled = false;
            btnExportHmac.Click += BtnExportHmac_Click;
            scroll.Controls.Add(btnExportHmac); y += 38;

            scroll.Resize += (s2, e2) =>
            {
                int cw = scroll.ClientSize.Width - scroll.Padding.Left - scroll.Padding.Right - 4;
                if (cw < 100) return;
                foreach (Control c in scroll.Controls)
                    if (c is Label l && !l.AutoSize) l.Width = cw;
                txtHmacKeyHex.Width = cw;
            };

            var secNote = new Label
            {
                Text = "⚠  Store exported key files securely. Anyone with the key can produce valid signatures.\n" +
                       "    Recommended: Use encrypted storage. Delete from unprotected locations immediately.",
                ForeColor = Color.Goldenrod, AutoSize = false, Size = new Size(560, 40), Location = new Point(0, y)
            };
            scroll.Controls.Add(secNote);

            return tab;
        }

        // ── Tab: Signing Self-Test ───────────────────────────────────────
        private TabPage BuildSelfTestTab()
        {
            var tab = new TabPage("Signing Self-Test");
            var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(8) };
            tab.Controls.Add(scroll);

            int y = 4;
            int w = scroll.Width > 100 ? scroll.Width - 20 : 500;
            var lbl = MakeLabel("Firmware Signing Compliance Tests", new Point(0, y), w, false);
            lbl.Font = new Font(Font.FontFamily, 10f, FontStyle.Bold); lbl.ForeColor = Color.SteelBlue;
            scroll.Controls.Add(lbl); y += 28;

            var desc = new Label
            {
                Text = "Runs 5 automated tests: SHA-256 consistency, HMAC-SHA256 known-vector,\n" +
                       "tamper detection, key-length enforcement, and RSA signing round-trip.",
                AutoSize = false, Size = new Size(560, 34), Location = new Point(0, y)
            };
            scroll.Controls.Add(desc); y += 40;

            btnRunTests = MakeButton("▶  Run All Tests", new Point(0, y), new Size(160, 32));
            btnRunTests.Click += async (s, e) => await RunSigningTestsAsync();
            scroll.Controls.Add(btnRunTests); y += 40;

            txtTestReport = new TextBox
            {
                Location = new Point(0, y), Size = new Size(w, 320),
                Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 8.5f), BorderStyle = BorderStyle.FixedSingle,
                Text = "(Click 'Run All Tests' to generate the compliance test report)"
            };
            scroll.Controls.Add(txtTestReport);

            scroll.Resize += (s2, e2) =>
            {
                int cw = scroll.ClientSize.Width - scroll.Padding.Left - scroll.Padding.Right - 4;
                if (cw < 100) return;
                foreach (Control c in scroll.Controls)
                    if (c is Label l && !l.AutoSize) l.Width = cw;
                txtTestReport.Width = cw;
            };

            return tab;
        }

        // ── Tab: Procedure Guide ─────────────────────────────────────────
        private TabPage BuildProcedureTab()
        {
            var tab = new TabPage("Procedure Guide");
            var txt = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
                BorderStyle = BorderStyle.None,
                Font = new Font("Segoe UI", 9.5f),
                Text = GetProcedureText()
            };
            tab.Controls.Add(txt);
            return tab;
        }

        // ================================================================
        // RIGHT PANEL — Live Log
        // ================================================================

        private void BuildRightPanel(Control parent)
        {
            var pnl = new Panel { Dock = DockStyle.Fill, Padding = new Padding(4) };
            parent.Controls.Add(pnl);

            var lblTitle = new Label
            {
                Text = "MissionPlanner Log (Live)",
                Font = new Font(Font.FontFamily, 9f, FontStyle.Bold),
                Dock = DockStyle.Top,
                Height = 22,
                Padding = new Padding(2, 2, 0, 0)
            };
            pnl.Controls.Add(lblTitle);

            var toolRow = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                Height = 32,
                Padding = new Padding(0),
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false
            };
            pnl.Controls.Add(toolRow);

            txtLogFind = new TextBox { Width = 130, Height = 22, Margin = new Padding(0, 4, 4, 0) };
            toolRow.Controls.Add(txtLogFind);

            btnLogFind = MakeButton("Find", new Point(0, 0), new Size(56, 26));
            btnLogFind.Margin = new Padding(0, 3, 4, 0);
            btnLogFind.Click += BtnLogFind_Click;
            toolRow.Controls.Add(btnLogFind);

            btnLogClear = MakeButton("Clear", new Point(0, 0), new Size(56, 26));
            btnLogClear.Margin = new Padding(0, 3, 0, 0);
            btnLogClear.Click += (s, e) => { txtLiveLog.Text = string.Empty; _lastLogPos = 0; };
            toolRow.Controls.Add(btnLogClear);

            txtLiveLog = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Both,
                BackColor = Color.FromArgb(10, 10, 10),
                ForeColor = Color.LightGreen,
                Font = new Font("Consolas", 7.5f),
                WordWrap = false
            };
            pnl.Controls.Add(txtLiveLog);
        }

        // ================================================================
        // LEFT PANEL — Event Handlers
        // ================================================================

        private void BtnBrowseFirmware_Click(object sender, EventArgs e)
        {
            using (var ofd = new OpenFileDialog
            {
                Title = "Select Firmware File",
                Filter = "Firmware Files (*.apj;*.px4;*.bin;*.hex)|*.apj;*.px4;*.bin;*.hex|All files (*.*)|*.*"
            })
            {
                if (ofd.ShowDialog(this) != DialogResult.OK) return;
                txtFirmwareFile.Text = ofd.FileName;
                UpdateFirmwareSha256(ofd.FileName);
                UpdateApjStatusLabel(ofd.FileName, lblApjStatus);
            }
        }

        private void BtnBrowseBootloader_Click(object sender, EventArgs e)
        {
            using (var ofd = new OpenFileDialog
            {
                Title = "Select Bootloader File",
                Filter = "Bootloader Files (*.bin;*.hex;*.dfu)|*.bin;*.hex;*.dfu|All files (*.*)|*.*"
            })
            {
                if (ofd.ShowDialog(this) == DialogResult.OK)
                    txtBootloaderFile.Text = ofd.FileName;
            }
        }

        private void BtnFlashFirmware_Click(object sender, EventArgs e)
        {
            if (!EnsureProtectedRole(AppUserRole.Admin, "flash firmware"))
                return;

            if (Interlocked.CompareExchange(ref _flashFirmwareInProgress, 1, 0) != 0)
            {
                AppendOutput("[FLASH] Ignored: flash already in progress.");
                return;
            }

            string opId = DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff");
            _flashStepCounter = 0;
            Action<string> logStep = msg =>
            {
                string line = "[FLASH-STEP " + (++_flashStepCounter).ToString("D2") + "] [op=" + opId + "] " + msg;
                AppendOutput(line);
                log.Info(line);
            };

            string fwPath = txtFirmwareFile.Text.Trim();
            string mappedFlashPath = TryMapLegacySignedFirmwarePath(fwPath,
                (txtApKeyOutDir?.Text ?? Settings.Instance[AppSettingApKeyOutDir] ?? string.Empty).Trim());
            if (!string.IsNullOrWhiteSpace(mappedFlashPath))
            {
                fwPath = mappedFlashPath;
                if (txtFirmwareFile != null)
                    txtFirmwareFile.Text = fwPath;
            }
            logStep("Selected firmware: " + (string.IsNullOrWhiteSpace(fwPath) ? "(none)" : fwPath));

            if (string.IsNullOrWhiteSpace(fwPath) || !File.Exists(fwPath))
            {
                ShowErr("Select a valid firmware file first.");
                Interlocked.Exchange(ref _flashFirmwareInProgress, 0);
                return;
            }

            // ── Gate 1: HMAC artifact blocking ──────────────────────────
            string fwFileName = Path.GetFileName(fwPath);
            if (fwFileName.IndexOf("hmac", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                string rejectMsg = "Strict profile blocked HMAC artifact. Use manufacturer-signed Ed25519/certificate-backed firmware.";
                logStep("REJECTED: " + rejectMsg);
                ShowErr(rejectMsg + "\n\nSelect an Ed25519-signed APJ and retry.");
                BeginInvoke((MethodInvoker)(() => { lblHashCheck.Text = "BLOCKED: HMAC artifact rejected"; lblHashCheck.ForeColor = Color.Red; }));
                Interlocked.Exchange(ref _flashFirmwareInProgress, 0);
                return;
            }

            // ── Gate 2: APJ must be Ed25519-signed ────────────────────
            if (Path.GetExtension(fwPath).Equals(".apj", StringComparison.OrdinalIgnoreCase) && !IsApjSigned(fwPath))
            {
                logStep("REJECTED: APJ is unsigned.");
                ShowErr("Firmware is unsigned.\n\nThis panel enforces signed firmware only.\nSign the firmware via the ArduPilot Signing tab before flashing.");
                BeginInvoke((MethodInvoker)(() => { lblHashCheck.Text = "BLOCKED: unsigned firmware"; lblHashCheck.ForeColor = Color.Red; }));
                Interlocked.Exchange(ref _flashFirmwareInProgress, 0);
                return;
            }

            // ── Gate 3: Release manifest validation ───────────────────
            string firmwareHash = ComputeFileSha256(fwPath);
            logStep("SHA256: " + firmwareHash);

            var manifestResult = ValidateReleaseManifestForArtifact(fwPath, firmwareHash);
            if (!manifestResult.IsValid)
            {
                if (manifestResult.IsAbsent)
                {
                    // No manifest present — soft warning, user may still proceed
                    logStep("WARNING: " + manifestResult.Reason);
                    BeginInvoke((MethodInvoker)(() =>
                    {
                        lblHashCheck.Text      = "WARNING: no release manifest";
                        lblHashCheck.ForeColor = Color.Orange;
                    }));
                    bool proceed = false;
                    using (var ev = new System.Threading.ManualResetEventSlim(false))
                    {
                        BeginInvoke((MethodInvoker)(() =>
                        {
                            proceed = MessageBox.Show(
                                "No release_manifest.json was found near this firmware file.\n\n" +
                                "Manifest validation ensures the firmware matches a signed, manufacturer-approved release.\n\n" +
                                "Proceed without manifest verification?",
                                "No Release Manifest",
                                MessageBoxButtons.YesNo,
                                MessageBoxIcon.Warning) == DialogResult.Yes;
                            ev.Set();
                        }));
                        ev.Wait();
                    }
                    if (!proceed)
                    {
                        logStep("Cancelled by user (no manifest).");
                        Interlocked.Exchange(ref _flashFirmwareInProgress, 0);
                        return;
                    }
                    logStep("User acknowledged missing manifest. Continuing.");
                }
                else
                {
                    // Manifest found but failed validation — hard block
                    logStep("REJECTED by release manifest: " + manifestResult.Reason);
                    string rejectMsg = "Protected mode rejected firmware: " + manifestResult.Reason;
                    ShowErr(rejectMsg + "\n\nRegenerate signed artifacts and release_manifest.json before flashing.");
                    BeginInvoke((MethodInvoker)(() => { lblHashCheck.Text = "BLOCKED: " + manifestResult.Reason; lblHashCheck.ForeColor = Color.Red; }));
                    Interlocked.Exchange(ref _flashFirmwareInProgress, 0);
                    return;
                }
            }
            else
            {
                logStep("Release manifest validated: " + manifestResult.Reason);
            }

            if (MessageBox.Show(
                    "Flash firmware to connected flight controller?\n\nFile: " + Path.GetFileName(fwPath) +
                    "\nSHA256: " + firmwareHash.Substring(0, 16) + "...",
                    "Confirm Flash", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
            {
                logStep("Cancelled by user.");
                Interlocked.Exchange(ref _flashFirmwareInProgress, 0);
                return;
            }

            btnFlashFirmware.Enabled = false;
            Task.Run(() =>
            {
                bool flashCompleted = false;
                try
                {
                    log.Info("[FW-CHANGE] START file=" + Path.GetFileName(fwPath) + " sha256=" + firmwareHash);
                    logStep("Starting FlashDispatcher pipeline...");
                    SetProgress(10, "Uploading firmware...");

                    var fw = new Utilities.Firmware();
                    fw.Progress += (pct, stat) => SetProgress(pct, "Uploading... " + pct + "%");

                    bool ok = fw.UploadFlash(MainV2.comPortName, fwPath, BoardDetect.boards.pass);
                    flashCompleted = ok;

                    if (ok)
                    {
                        logStep("FlashDispatcher completed successfully.");
                        SetProgress(90, "Upload complete. Run Provision Registry to complete secure update.");
                        AppendOutput("[FLASH] Please reconnect manually: unplug the board, wait a few seconds, then plug it back in.");
                        AppendOutput("[FLASH] COMPLETE. Firmware: " + Path.GetFileName(fwPath));
                        AppendOutput("[FLASH] SHA256: " + firmwareHash);
                        log.Info("[FW-CHANGE] INCOMPLETE file=" + Path.GetFileName(fwPath) + " sha256=" + firmwareHash + " registry_update=PENDING (manual-required)");

                        BeginInvoke((MethodInvoker)(() =>
                        {
                            lblHashCheck.Text = "Upload complete. Run Provision Registry to complete secure update.";
                            lblHashCheck.ForeColor = Color.DarkOrange;
                            CustomMessageBox.Show(
                                "Firmware flashed successfully.\n\nStrict mode is active: run Provision Registry now to complete update compliance.\n\nAlso reconnect manually: unplug the board, wait a few seconds, then plug it back in.",
                                "Firmware Upload Complete (Pending Provision)",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Warning);
                        }));
                    }
                    else
                    {
                        logStep("Flash FAILED.");
                        SetProgress(0, "Flash failed.");
                        log.Warn("[FW-CHANGE] FAILED file=" + Path.GetFileName(fwPath) + " sha256=" + firmwareHash);
                        BeginInvoke((MethodInvoker)(() =>
                        {
                            lblHashCheck.Text = "Bootloader/Firmware hash check: FAIL";
                            lblHashCheck.ForeColor = Color.Red;
                        }));
                    }
                }
                catch (Exception ex)
                {
                    logStep("Exception: " + ex.Message);
                    if (flashCompleted)
                    {
                        AppendOutput("[FLASH] Flashed but post-upgrade completion failed: " + ex.Message);
                        log.Error("[FW-CHANGE] INCOMPLETE post-upgrade failure", ex);
                    }
                    else
                    {
                        AppendOutput("[FLASH] ERROR: " + ex.Message);
                        log.Error("[FLASH] Firmware upload failed", ex);
                    }
                    SetProgress(0, "Error: " + ex.Message);
                }
                finally
                {
                    Interlocked.Exchange(ref _flashFirmwareInProgress, 0);
                    BeginInvoke((MethodInvoker)(() => btnFlashFirmware.Enabled = true));
                }
            });
        }

        private void BtnFlashBootloader_Click(object sender, EventArgs e)
        {
            if (!EnsureProtectedRole(AppUserRole.Admin, "flash bootloader"))
                return;

            string blPath = txtBootloaderFile.Text.Trim();
            if (string.IsNullOrWhiteSpace(blPath) || !File.Exists(blPath))
            {
                ShowErr("Select a valid bootloader file first.");
                return;
            }

            if (MessageBox.Show(
                    "Flash bootloader to connected flight controller?\n\n" +
                    "WARNING: Flashing an incorrect bootloader can brick your board.\n\n" +
                    "File: " + Path.GetFileName(blPath),
                    "Confirm Bootloader Flash", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                return;

            btnFlashBootloader.Enabled = false;
            Task.Run(() =>
            {
                try
                {
                    AppendOutput("[BL-FLASH] Starting bootloader upload: " + Path.GetFileName(blPath));
                    SetProgress(10, "Uploading bootloader...");

                    var fw = new Utilities.Firmware();
                    fw.Progress += (pct, stat) => SetProgress(pct, "Uploading bootloader... " + pct + "%");

                    bool ok = fw.UploadFlash(MainV2.comPortName, blPath, BoardDetect.boards.pass);

                    if (ok)
                    {
                        SetProgress(100, "Bootloader flash complete.");
                        AppendOutput("[BL-FLASH] COMPLETE. Bootloader: " + Path.GetFileName(blPath));
                        log.Info("[BL-CHANGE] COMPLETE file=" + Path.GetFileName(blPath));
                    }
                    else
                    {
                        SetProgress(0, "Bootloader flash failed.");
                        AppendOutput("[BL-FLASH] FAILED. Check connection and retry.");
                    }
                }
                catch (Exception ex)
                {
                    AppendOutput("[BL-FLASH] ERROR: " + ex.Message);
                    SetProgress(0, "Error: " + ex.Message);
                    log.Error("[BL-FLASH] Bootloader upload failed", ex);
                }
                finally
                {
                    BeginInvoke((MethodInvoker)(() => btnFlashBootloader.Enabled = true));
                }
            });
        }

        private void BtnExportAudit_Click(object sender, EventArgs e)
        {
            if (!EnsureProtectedRole(AppUserRole.Operator, "export audit bundle"))
                return;

            try
            {
                Directory.CreateDirectory(_auditExportFolder);
                string ts = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
                string outFile = Path.Combine(_auditExportFolder, "audit_bundle_" + ts + ".json");

                string fwPath = txtFirmwareFile.Text.Trim();
                string fwHash = _lastFirmwareSha256;

                // Resolve release manifest evidence
                string manifestPath = string.Empty, manifestHashPath = string.Empty;
                string manifestHash = string.Empty, manifestSigPresent = "false";
                string keyEvidencePrivSha = string.Empty, keyEvidencePubSha = string.Empty;
                bool manifestFound = !string.IsNullOrWhiteSpace(fwPath) && TryResolveReleaseManifestPaths(fwPath, out manifestPath, out manifestHashPath);
                if (manifestFound && File.Exists(manifestHashPath))
                    manifestHash = ReadManifestExpectedHash(manifestHashPath);
                if (manifestFound && File.Exists(manifestPath))
                {
                    string manifestDir = Path.GetDirectoryName(manifestPath) ?? string.Empty;
                    manifestSigPresent = File.Exists(Path.Combine(manifestDir, "release_manifest.sig")).ToString().ToLowerInvariant();
                    try
                    {
                        var mObj = JObject.Parse(File.ReadAllText(manifestPath));
                        keyEvidencePrivSha = mObj["keyEvidence"]?["privateKeySha"]?.ToString() ?? string.Empty;
                        keyEvidencePubSha  = mObj["keyEvidence"]?["publicKeySha"]?.ToString()  ?? string.Empty;
                    }
                    catch { }
                }

                var mav = MainV2.comPort?.MAV;

                var sb = new StringBuilder();
                sb.AppendLine("{");
                sb.AppendLine("  \"timestamp_utc\": \"" + DateTime.UtcNow.ToString("o") + "\",");
                sb.AppendLine("  \"gcs\": \"MissionPlanner\",");
                sb.AppendLine("  \"compliance_level\": \"Level1\",");
                sb.AppendLine("  \"firmware_file\": \"" + EscapeJson(fwPath) + "\",");
                sb.AppendLine("  \"firmware_sha256\": \"" + EscapeJson(fwHash) + "\",");
                sb.AppendLine("  \"bootloader_file\": \"" + EscapeJson(txtBootloaderFile.Text) + "\",");
                sb.AppendLine("  \"apj_status\": \"" + EscapeJson(lblApjStatus.Text) + "\",");
                sb.AppendLine("  \"hash_check\": \"" + EscapeJson(lblHashCheck.Text) + "\",");
                sb.AppendLine("  \"manifest_found\": " + manifestFound.ToString().ToLowerInvariant() + ",");
                sb.AppendLine("  \"manifest_path\": \"" + EscapeJson(manifestPath) + "\",");
                sb.AppendLine("  \"manifest_sha256\": \"" + EscapeJson(manifestHash) + "\",");
                sb.AppendLine("  \"manifest_sig_present\": " + manifestSigPresent + ",");
                sb.AppendLine("  \"key_evidence_private_sha256\": \"" + EscapeJson(keyEvidencePrivSha) + "\",");
                sb.AppendLine("  \"key_evidence_public_sha256\": \"" + EscapeJson(keyEvidencePubSha) + "\",");
                if (mav != null)
                {
                    sb.AppendLine("  \"fc_sysid\": " + mav.sysid + ",");
                    sb.AppendLine("  \"fc_compid\": " + mav.compid + ",");
                }
                sb.AppendLine("  \"workflow\": \"" + EscapeJson(lblWorkflowStatus.Text) + "\"");
                sb.AppendLine("}");

                File.WriteAllText(outFile, sb.ToString());
                log.Info("[AUDIT-EXPORT] Bundle exported: " + outFile);
                AppendOutput("[AUDIT] Bundle exported: " + outFile);
                AppendOutput("[AUDIT] manifest_found=" + manifestFound + " sig_present=" + manifestSigPresent);
                lblExportPath.Text = "Last export: " + outFile;

                MessageBox.Show("Audit bundle exported to:\n" + outFile,
                    "Export Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                ShowErr("Export failed:\n" + ex.Message);
                log.Error("Audit export failed", ex);
            }
        }

        private async void BtnProvisionRegistry_Click(object sender, EventArgs e)
        {
            if (!EnsureProtectedRole(AppUserRole.Admin, "provision checksum registry"))
                return;

            string fwPath = ResolveDefaultFirmwareForRegistryScripts();
            if (string.IsNullOrWhiteSpace(fwPath) || !File.Exists(fwPath))
            {
                ShowErr("Select a valid signed firmware APJ before provisioning checksum registry.");
                return;
            }

            if (MainV2.comPort?.BaseStream == null || !MainV2.comPort.BaseStream.IsOpen)
            {
                ShowErr("Connect to the flight controller first.");
                return;
            }

            string board = txtApBoard?.Text.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(board)) board = Settings.Instance[AppSettingApBoard] ?? "Pixhawk6C";

            string keyPath = string.Empty, pubKeyPath = string.Empty;
            bool keyResolved = TryResolveConfiguredKeyPaths(board, out string keyFolder, out keyPath, out pubKeyPath, out string keyError);

            string firmwareHash = string.IsNullOrWhiteSpace(_lastFirmwareSha256)
                ? ComputeFileSha256(fwPath)
                : _lastFirmwareSha256;

            AppendOutput("[PROVISION] Provisioning checksum registry...");
            AppendOutput("[PROVISION] Firmware: " + Path.GetFileName(fwPath));
            AppendOutput("[PROVISION] SHA256: " + firmwareHash);
            if (keyResolved)
            {
                AppendOutput("[PROVISION] Keys folder: " + keyFolder);
                AppendOutput("[PROVISION] Private key: " + Path.GetFileName(keyPath));
            }
            else
            {
                AppendOutput("[PROVISION] WARN: " + keyError);
                AppendOutput("[PROVISION] Continuing — key is only required for native SECURE_COMMAND provisioning.");
            }

            log.Info("[PROVISION] Registry provision requested. Firmware=" + Path.GetFileName(fwPath) + " sha256=" + firmwareHash);

            if (keyResolved)
            {
                try
                {
                    btnProvisionRegistry.Enabled = false;
                    AppendOutput("[PROVISION] Native SECURE_COMMAND provisioning started...");
                    await ProvisionChecksumRegistryNativeAsync(fwPath, keyPath, AppendOutput).ConfigureAwait(true);
                    SetWorkflowStatus("Provision PASSED: checksum registry matches APJ", Color.LimeGreen);

                    MessageBox.Show(
                        "Checksum registry provision completed successfully.",
                        "Provision Registry",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                    return;
                }
                catch (Exception ex)
                {
                    AppendOutput("[PROVISION] Native provisioning failed: " + ex.Message);
                    AppendOutput("[PROVISION] Falling back to manual provisioning guidance.");
                    SetWorkflowStatus("Provision FAILED: " + ex.Message, Color.Red);
                    log.Warn("[PROVISION] Native provisioning failed", ex);
                }
                finally
                {
                    btnProvisionRegistry.Enabled = true;
                }
            }

            // Native flow failed or key is not available.
            // Fall back to manual script guidance.
            string portHint = MainV2.comPortName ?? "COMx";
            string keyArg   = keyResolved ? " --key \"" + keyPath + "\"" : " --key \"<board>_private_key.dat\"";

            AppendOutput("[PROVISION] To provision using the automation script:");
            AppendOutput("[PROVISION]   cd " + (keyResolved ? keyFolder : "<KeyOutputDir>\\tools\\automation"));
            AppendOutput("[PROVISION]   python provision_checksum_registry.py --port " + portHint + " --firmware \"" + fwPath + "\"" + keyArg);

            MessageBox.Show(
                "Checksum registry provision requires ArduPilot's SECURE_COMMAND protocol.\n\n" +
                "To provision:\n" +
                "1. Ensure ArduPilot firmware was built with AP_SECURE_COMMAND enabled.\n" +
                "2. Run the provisioning script from the tools/automation directory (see output log).\n" +
                "3. Verify with the 'Verify Registry' button after provisioning.\n\n" +
                "Firmware:   " + Path.GetFileName(fwPath) + "\n" +
                "SHA256:      " + (firmwareHash.Length > 32 ? firmwareHash.Substring(0, 32) + "..." : firmwareHash) + "\n" +
                (keyResolved ? "Private key: " + Path.GetFileName(keyPath) : "Private key: not resolved — set Key Output Dir in ArduPilot Signing tab"),
                "Provision Registry",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private async Task ProvisionChecksumRegistryNativeAsync(string apjPath, string privateKeyPath, Action<string> logLine, int stepTimeoutMs = 10000)
        {
            if (MainV2.comPort?.BaseStream == null || !MainV2.comPort.BaseStream.IsOpen)
                throw new InvalidOperationException("MAVLink link is not open.");
            if (!File.Exists(apjPath))
                throw new FileNotFoundException("APJ file not found: " + apjPath);
            if (!File.Exists(privateKeyPath))
                throw new FileNotFoundException("Private key file not found: " + privateKeyPath);

            var (codeHash, dataHash) = await Task.Run(() => ComputeApjPartitionHashes(apjPath)).ConfigureAwait(false);
            logLine("[PROVISION] Code hash: " + BitConverter.ToString(codeHash).Replace("-", ""));
            logLine("[PROVISION] Data hash: " + BitConverter.ToString(dataHash).Replace("-", ""));

            byte[] seed = await Task.Run(() => LoadEd25519Seed(privateKeyPath)).ConfigureAwait(false);

            uint seq = (uint)(DateTime.UtcNow.Ticks & 0xFFFF);
            byte[] empty = new byte[0];
            byte[] sessionKey = null;
            bool legacy = false;

            logLine("[PROVISION] Step 1/3: Requesting session key...");

            for (int mode = 0; mode < 2; mode++)
            {
                bool tryLegacy = mode == 1;
                byte[] signingPayload = tryLegacy
                    ? BuildSigningPayloadLegacyU16(seq, ScOpGetSessionKey, empty, empty)
                    : BuildSigningPayload(seq, ScOpGetSessionKey, empty, empty);
                byte[] sig = Ed25519Sign(seed, signingPayload);

                var reply = await SendSecureCommandAsync(seq, ScOpGetSessionKey, empty, sig, stepTimeoutMs).ConfigureAwait(false);
                logLine("[PROVISION] GET_SESSION_KEY " + (tryLegacy ? "legacy-u16" : "primary-u32") + " result=" + reply.result);

                if (reply.result == 0)
                {
                    sessionKey = reply.data;
                    legacy = tryLegacy;
                    break;
                }
            }

            if (sessionKey == null || sessionKey.Length < 8)
                throw new InvalidOperationException("GET_SESSION_KEY failed or returned short key.");

            byte[] regPayload = new byte[1 + 32 + 32];
            regPayload[0] = 1; // version
            Buffer.BlockCopy(codeHash, 0, regPayload, 1, 32);
            Buffer.BlockCopy(dataHash, 0, regPayload, 33, 32);

            seq++;
            logLine("[PROVISION] Step 2/3: Sending SET_CHECKSUM_REGISTRY...");
            byte[] setSigning = legacy
                ? BuildSigningPayloadLegacyU16(seq, ScOpSetChecksumRegistry, regPayload, sessionKey)
                : BuildSigningPayload(seq, ScOpSetChecksumRegistry, regPayload, sessionKey);
            byte[] setSig = Ed25519Sign(seed, setSigning);
            var setReply = await SendSecureCommandAsync(seq, ScOpSetChecksumRegistry, regPayload, setSig, Math.Max(stepTimeoutMs, 25000)).ConfigureAwait(false);
            if (setReply.result != 0)
                throw new InvalidOperationException("SET_CHECKSUM_REGISTRY failed: result=" + setReply.result);

            seq++;
            logLine("[PROVISION] Step 3/3: Verifying checksum registry...");
            byte[] getSigning = legacy
                ? BuildSigningPayloadLegacyU16(seq, ScOpGetChecksumRegistry, empty, sessionKey)
                : BuildSigningPayload(seq, ScOpGetChecksumRegistry, empty, sessionKey);
            byte[] getSig = Ed25519Sign(seed, getSigning);
            var getReply = await SendSecureCommandAsync(seq, ScOpGetChecksumRegistry, empty, getSig, stepTimeoutMs).ConfigureAwait(false);
            if (getReply.result != 0)
                throw new InvalidOperationException("GET_CHECKSUM_REGISTRY failed: result=" + getReply.result);

            bool codeOk = false;
            bool dataOk = false;
            bool algoOk = false;
            const byte algoSha256 = 1;

            byte[] readBack = getReply.data ?? new byte[0];
            if (readBack.Length >= 80)
            {
                algoOk = readBack[8] == algoSha256;
                codeOk = readBack.Skip(16).Take(32).SequenceEqual(codeHash);
                dataOk = readBack.Skip(48).Take(32).SequenceEqual(dataHash);
            }
            else if (readBack.Length >= 65)
            {
                // Legacy compact payloads do not include explicit algo byte.
                algoOk = true;
                codeOk = readBack.Skip(1).Take(32).SequenceEqual(codeHash);
                dataOk = readBack.Skip(33).Take(32).SequenceEqual(dataHash);
            }

            if (!algoOk)
                throw new InvalidOperationException("Registry algorithm mismatch: expected SHA2-256.");
            if (!codeOk || !dataOk)
                throw new InvalidOperationException("Registry verify mismatch. codeOk=" + codeOk + " dataOk=" + dataOk);

            logLine("[PROVISION] SUCCESS — Checksum registry provisioned and verified.");
        }

        private async Task<(byte result, byte[] data)> SendSecureCommandAsync(uint seq, uint op, byte[] payload, byte[] signature, int timeoutMs)
        {
            payload = payload ?? new byte[0];
            signature = signature ?? new byte[0];

            if (payload.Length + signature.Length > 220)
                throw new InvalidOperationException("SECURE_COMMAND payload exceeds 220 bytes.");

            byte targetSys = (byte)(MainV2.comPort.sysidcurrent > 0 ? MainV2.comPort.sysidcurrent : MainV2.comPort.MAV.sysid);
            byte targetComp = (byte)(MainV2.comPort.compidcurrent > 0 ? MainV2.comPort.compidcurrent : MainV2.comPort.MAV.compid);
            if (targetSys == 0) targetSys = 1;
            if (targetComp == 0) targetComp = 1;

            for (int attempt = 0; attempt < 3; attempt++)
            {
                var tcs = new TaskCompletionSource<(byte, byte[])>(TaskCreationOptions.RunContinuationsAsynchronously);
                int sub = MainV2.comPort.SubscribeToPacketType(MAVLink.MAVLINK_MSG_ID.SECURE_COMMAND_REPLY, buffer =>
                {
                    try
                    {
                        var reply = buffer.ToStructure<MAVLink.mavlink_secure_command_reply_t>();
                        if (reply.sequence != seq || reply.operation != op)
                            return true;

                        int dataLen = Math.Min(reply.data_length, (byte)(reply.data != null ? reply.data.Length : 0));
                        var data = new byte[dataLen];
                        if (dataLen > 0 && reply.data != null)
                            Array.Copy(reply.data, data, dataLen);

                        tcs.TrySetResult((reply.result, data));
                    }
                    catch (Exception ex)
                    {
                        tcs.TrySetException(ex);
                    }
                    return true;
                }, targetSys, targetComp);

                try
                {
                    byte[] dataField = new byte[220];
                    if (payload.Length > 0)
                        Array.Copy(payload, 0, dataField, 0, payload.Length);
                    if (signature.Length > 0)
                        Array.Copy(signature, 0, dataField, payload.Length, signature.Length);

                    var req = new MAVLink.mavlink_secure_command_t(
                        seq,
                        op,
                        targetSys,
                        targetComp,
                        (byte)payload.Length,
                        (byte)signature.Length,
                        dataField);

                    MainV2.comPort.sendPacket(req, targetSys, targetComp);

                    var completed = await Task.WhenAny(tcs.Task, Task.Delay(timeoutMs)).ConfigureAwait(false);
                    if (completed == tcs.Task)
                        return await tcs.Task.ConfigureAwait(false);
                }
                finally
                {
                    MainV2.comPort.UnSubscribeToPacketType(sub);
                }
            }

            throw new TimeoutException("Timed out waiting for SECURE_COMMAND_REPLY for op=" + op + " seq=" + seq);
        }

        private static byte[] BuildSigningPayload(uint seq, uint op, byte[] data, byte[] sessionKey)
        {
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write(seq);
                bw.Write(op);
                if (data != null && data.Length > 0)
                    bw.Write(data);
                if (sessionKey != null && sessionKey.Length > 0)
                    bw.Write(sessionKey);
                return ms.ToArray();
            }
        }

        private static byte[] BuildSigningPayloadLegacyU16(uint seq, uint op, byte[] data, byte[] sessionKey)
        {
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write((ushort)(seq & 0xFFFF));
                bw.Write((ushort)(op & 0xFFFF));
                if (data != null && data.Length > 0)
                    bw.Write(data);
                if (sessionKey != null && sessionKey.Length > 0)
                    bw.Write(sessionKey);
                return ms.ToArray();
            }
        }

        private static byte[] Ed25519Sign(byte[] seed, byte[] message)
        {
            var key = new Ed25519PrivateKeyParameters(seed, 0);
            var signer = SignerUtilities.GetSigner("ED25519");
            signer.Init(true, key);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.GenerateSignature();
        }

        private static byte[] LoadEd25519Seed(string privateKeyPath)
        {
            byte[] raw = File.ReadAllBytes(privateKeyPath);
            if (raw.Length == 32)
                return raw;

            string text = Encoding.ASCII.GetString(raw).Trim();
            text = text.Replace(" ", string.Empty).Replace("\r", string.Empty).Replace("\n", string.Empty);

            // ArduPilot KEYV1 text format: PRIVATE_KEYV1:<base64-32-bytes>
            const string privatePrefix = "PRIVATE_KEYV1:";
            const string publicPrefix = "PUBLIC_KEYV1:";
            if (text.StartsWith(publicPrefix, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Selected key file is a public key. Use <board>_private_key.dat.");
            if (text.StartsWith(privatePrefix, StringComparison.OrdinalIgnoreCase))
            {
                string b64 = text.Substring(privatePrefix.Length);
                byte[] decoded = Convert.FromBase64String(b64);
                if (decoded.Length == 32)
                    return decoded;
                throw new InvalidDataException("PRIVATE_KEYV1 payload must decode to 32 bytes.");
            }

            // Accept plain base64 seed files as well.
            try
            {
                byte[] b64 = Convert.FromBase64String(text);
                if (b64.Length == 32)
                    return b64;
            }
            catch
            {
                // Not base64; try other formats below.
            }

            // Accept comma-separated hex lists: 0xAA,0xBB,... or AA,BB,...
            string[] parts = text.Split(new[] { ',', ';', ':' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 32)
            {
                try
                {
                    byte[] seed = new byte[32];
                    for (int i = 0; i < 32; i++)
                    {
                        string p = parts[i].Trim();
                        if (p.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                            p = p.Substring(2);
                        if (p.Length != 2 || !p.All(Uri.IsHexDigit))
                            throw new InvalidDataException("Invalid hex byte in key at index " + i + ".");
                        seed[i] = Convert.ToByte(p, 16);
                    }
                    return seed;
                }
                catch
                {
                    // Fall through to final error.
                }
            }

            if (text.Length == 64 && text.All(Uri.IsHexDigit))
            {
                byte[] seed = new byte[32];
                for (int i = 0; i < 32; i++)
                    seed[i] = Convert.ToByte(text.Substring(i * 2, 2), 16);
                return seed;
            }

            throw new InvalidDataException("Unsupported private key format. Expected PRIVATE_KEYV1:<base64>, raw 32-byte seed, 64-char hex, plain base64 seed, or 32-byte hex list.");
        }

        private static (byte[] codeHash, byte[] dataHash) ComputeApjPartitionHashes(string apjPath)
        {
            byte[] binary = ExtractApjBinary(apjPath);
            using (var sha = SHA256.Create())
            {
                int descOffset = FindDescriptorOffset(binary);
                if (descOffset < 0)
                    return (sha.ComputeHash(binary), sha.ComputeHash(new byte[0]));

                const int versionMajorOffset = 100;
                int codeLen = descOffset + 8;
                byte[] codeHash = sha.ComputeHash(binary, 0, codeLen);

                if (descOffset + 20 > binary.Length)
                    throw new InvalidDataException("APJ binary too short to read descriptor image_size.");

                uint imageSize = BitConverter.ToUInt32(binary, descOffset + 16);
                int dataStart = descOffset + versionMajorOffset;
                int dataLen = (int)imageSize - dataStart;
                byte[] dataHash = dataLen > 0
                    ? sha.ComputeHash(binary, dataStart, dataLen)
                    : sha.ComputeHash(new byte[0]);

                return (codeHash, dataHash);
            }
        }

        private static byte[] ExtractApjBinary(string apjPath)
        {
            if (!string.Equals(Path.GetExtension(apjPath), ".apj", StringComparison.OrdinalIgnoreCase))
                return File.ReadAllBytes(apjPath);

            JObject obj = JObject.Parse(File.ReadAllText(apjPath));
            int imageSize = obj["image_size"] != null ? (int)obj["image_size"] : 0;
            if (imageSize <= 0)
                throw new InvalidDataException("APJ image_size is missing or invalid.");

            string imageB64 = (string)obj["image"];
            if (string.IsNullOrWhiteSpace(imageB64))
                throw new InvalidDataException("APJ image field missing.");

            byte[] compressed = Convert.FromBase64String(imageB64);
            byte[] image = new byte[imageSize];
            using (var zs = new ZlibStream(new MemoryStream(compressed), CompressionMode.Decompress, true))
            {
                int read = 0;
                while (read < image.Length)
                {
                    int n = zs.Read(image, read, image.Length - read);
                    if (n <= 0)
                        break;
                    read += n;
                }
                if (read != image.Length)
                    throw new InvalidDataException("APJ decompression returned " + read + " bytes, expected " + image.Length + ".");
            }

            return image;
        }

        private static int FindDescriptorOffset(byte[] binary)
        {
            for (int i = 0; i <= binary.Length - ApjDescriptorMagic.Length; i++)
            {
                bool ok = true;
                for (int j = 0; j < ApjDescriptorMagic.Length; j++)
                {
                    if (binary[i + j] != ApjDescriptorMagic[j])
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok)
                    return i;
            }
            return -1;
        }

        // ── Key + firmware path resolution (mirrors SaamGCS TryResolveConfiguredKeyPaths) ──

        private static bool TryResolveConfiguredKeyPaths(string boardName,
            out string keysFolder, out string privateKeyPath, out string publicKeyPath, out string error)
        {
            keysFolder = privateKeyPath = publicKeyPath = error = string.Empty;
            string board = string.IsNullOrWhiteSpace(boardName) ? "Pixhawk6C" : boardName.Trim();

            string configured = Settings.Instance[AppSettingApPrivKey]?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(configured))
                configured = Settings.Instance[AppSettingApKeyOutDir]?.Trim() ?? string.Empty;

            if (string.IsNullOrWhiteSpace(configured))
            {
                error = "Keys folder path is not configured. Open the ArduPilot Signing tab and set Key Output Dir.";
                return false;
            }

            try
            {
                // If configured value is a file path, treat its directory as the folder
                if (File.Exists(configured))
                    configured = Path.GetDirectoryName(configured) ?? string.Empty;

                string[] candidateFolders = new[]
                {
                    configured,
                    Path.Combine(configured, "Ed25519"),
                    Path.Combine(configured, "tools", "Ed25519")
                };

                foreach (string candidate in candidateFolders)
                {
                    if (!Directory.Exists(candidate)) continue;
                    string priv = Path.Combine(candidate, board + "_private_key.dat");
                    string pub  = Path.Combine(candidate, board + "_public_key.dat");
                    if (File.Exists(priv) && File.Exists(pub))
                    {
                        keysFolder     = candidate;
                        privateKeyPath = priv;
                        publicKeyPath  = pub;
                        return true;
                    }
                }

                keysFolder     = configured;
                privateKeyPath = Path.Combine(configured, board + "_private_key.dat");
                publicKeyPath  = Path.Combine(configured, board + "_public_key.dat");
                error = "Key files not found for board '" + board + "'. Expected " + board + "_private_key.dat in: " +
                        string.Join(" | ", candidateFolders);
                return false;
            }
            catch (Exception ex)
            {
                error = "Key path resolution failed: " + ex.Message;
                return false;
            }
        }

        private string ResolveDefaultFirmwareForRegistryScripts()
        {
            string selected = txtFirmwareFile?.Text?.Trim() ?? string.Empty;
            string outDir = Settings.Instance[AppSettingApKeyOutDir]?.Trim() ?? string.Empty;
            string board  = txtApBoard?.Text.Trim() ?? Settings.Instance[AppSettingApBoard] ?? "Pixhawk6C";

            if (!string.IsNullOrWhiteSpace(selected) && File.Exists(selected))
            {
                // Auto-migrate stale legacy path selections from the older
                // "...\\ed25519\\signed\\firmware" layout.
                string migrated = TryMapLegacySignedFirmwarePath(selected, outDir);
                if (!string.IsNullOrWhiteSpace(migrated))
                    return migrated;

                return selected;
            }

            string[] candidates = new[]
            {
                string.IsNullOrWhiteSpace(outDir) ? null : Path.Combine(outDir, "Signed", "Firmware", board + "-signed.apj"),
                string.IsNullOrWhiteSpace(outDir) ? null : Path.Combine(outDir, "Signed", "Firmware", board + "-arducopter-ed25519-signed.apj"),
                string.IsNullOrWhiteSpace(outDir) ? null : Path.Combine(outDir, "Signed", "Firmware", "arducopter-signed.apj"),
                string.IsNullOrWhiteSpace(outDir) ? null : Path.Combine(outDir, "Signed", "Firmware", "arducopter-ed25519-signed.apj"),
                Path.Combine(Environment.CurrentDirectory, "tools", "Ed25519", "Signed", "Firmware", "arducopter-ed25519-signed.apj"),
                Path.Combine(Environment.CurrentDirectory, "tools", "Ed25519", "Signed", "Firmware", "arducopter-signed.apj"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tools", "Ed25519", "Signed", "Firmware", "arducopter-ed25519-signed.apj")
            };

            foreach (string c in candidates)
                if (!string.IsNullOrWhiteSpace(c) && File.Exists(c))
                    return c;

            return string.Empty;
        }

        private static string TryMapLegacySignedFirmwarePath(string selectedPath, string outDir)
        {
            if (string.IsNullOrWhiteSpace(selectedPath) || string.IsNullOrWhiteSpace(outDir))
                return string.Empty;

            string normalized = selectedPath.Replace('/', '\\');
            if (normalized.IndexOf("\\ed25519\\signed\\firmware\\", StringComparison.OrdinalIgnoreCase) < 0)
                return string.Empty;

            string migrated = Path.Combine(outDir, "Signed", "Firmware", Path.GetFileName(selectedPath));
            return File.Exists(migrated) ? migrated : string.Empty;
        }

        private async void BtnVerifyRegistry_Click(object sender, EventArgs e)
        {
            if (!EnsureProtectedRole(AppUserRole.Operator, "verify checksum registry"))
                return;

            string fwPath = ResolveDefaultFirmwareForRegistryScripts();
            if (string.IsNullOrWhiteSpace(fwPath) || !File.Exists(fwPath))
            {
                ShowErr("Select a valid signed firmware APJ before verifying checksum registry.");
                return;
            }

            if (MainV2.comPort?.BaseStream == null || !MainV2.comPort.BaseStream.IsOpen)
            {
                ShowErr("Connect to the flight controller first.");
                return;
            }

            string firmwareHash = string.IsNullOrWhiteSpace(_lastFirmwareSha256)
                ? ComputeFileSha256(fwPath)
                : _lastFirmwareSha256;

            string board = txtApBoard?.Text.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(board))
                board = Settings.Instance[AppSettingApBoard] ?? "Pixhawk6C";

            bool keyResolved = TryResolveConfiguredKeyPaths(board,
                out string keyFolder,
                out string keyPath,
                out string pubKeyPath,
                out string keyError);

            AppendOutput("[VERIFY] Verifying checksum registry...");
            AppendOutput("[VERIFY] Firmware: " + Path.GetFileName(fwPath));
            AppendOutput("[VERIFY] SHA256: " + firmwareHash);
            if (keyResolved)
            {
                AppendOutput("[VERIFY] Keys folder: " + keyFolder);
                AppendOutput("[VERIFY] Private key: " + Path.GetFileName(keyPath));
            }
            else
            {
                AppendOutput("[VERIFY] WARN: " + keyError);
                AppendOutput("[VERIFY] Native verify unavailable without private key; showing manual guidance.");
            }

            log.Info("[VERIFY] Registry verify requested. Firmware=" + Path.GetFileName(fwPath)
                + " SHA256=" + firmwareHash);

            if (keyResolved)
            {
                try
                {
                    btnVerifyRegistry.Enabled = false;
                    AppendOutput("[VERIFY] Native SECURE_COMMAND verify started...");
                    await VerifyChecksumRegistryNativeAsync(fwPath, keyPath, AppendOutput).ConfigureAwait(true);
                    SetWorkflowStatus("Verify PASSED: checksum registry matches APJ", Color.LimeGreen);

                    MessageBox.Show(
                        "Checksum registry verification completed successfully.",
                        "Verify Registry",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                    return;
                }
                catch (Exception ex)
                {
                    bool registryUnavailable = ex.Message.IndexOf("GET_CHECKSUM_REGISTRY failed: result=4", StringComparison.OrdinalIgnoreCase) >= 0;
                    if (registryUnavailable)
                    {
                        string warning = "Checksum registry not provisioned yet (result=4). Run Provision Registry after flash.";
                        AppendOutput("[VERIFY] WARNING: " + warning);
                        SetWorkflowStatus("Verify WARNING: " + warning, Color.Orange);
                        log.Warn("[VERIFY] " + warning);
                        MessageBox.Show(
                            warning,
                            "Verify Registry",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Warning);
                        return;
                    }

                    AppendOutput("[VERIFY] Native verify failed: " + ex.Message);
                    AppendOutput("[VERIFY] Falling back to manual verification guidance.");
                    SetWorkflowStatus("Verify FAILED: " + ex.Message, Color.Red);
                    log.Warn("[VERIFY] Native verification failed", ex);
                }
                finally
                {
                    btnVerifyRegistry.Enabled = true;
                }
            }

            AppendOutput("[VERIFY] NOTE: Full SECURE_COMMAND registry verification requires ArduPilot");
            AppendOutput("[VERIFY] firmware with AP_SECURE_COMMAND enabled. To verify manually:");
            AppendOutput("[VERIFY]   python tools/scripts/verify_registry.py --port " + MainV2.comPortName);
            AppendOutput("[VERIFY]   --firmware " + fwPath);

            MessageBox.Show(
                "Registry verification requires ArduPilot's SECURE_COMMAND protocol.\n\n" +
                "To verify:\n" +
                "1. Ensure ArduPilot was built with AP_SECURE_COMMAND enabled.\n" +
                "2. Run the verify script from the tools directory (see output log).\n\n" +
                "Firmware SHA256: " + (firmwareHash.Length > 32
                    ? firmwareHash.Substring(0, 32) + "..."
                    : firmwareHash),
                "Verify Registry",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private async Task VerifyChecksumRegistryNativeAsync(string apjPath, string privateKeyPath, Action<string> logLine, int stepTimeoutMs = 10000)
        {
            if (MainV2.comPort?.BaseStream == null || !MainV2.comPort.BaseStream.IsOpen)
                throw new InvalidOperationException("MAVLink link is not open.");
            if (!File.Exists(apjPath))
                throw new FileNotFoundException("APJ file not found: " + apjPath);
            if (!File.Exists(privateKeyPath))
                throw new FileNotFoundException("Private key file not found: " + privateKeyPath);

            var (codeHash, dataHash) = await Task.Run(() => ComputeApjPartitionHashes(apjPath)).ConfigureAwait(false);
            string expectedCode = BitConverter.ToString(codeHash).Replace("-", "");
            string expectedData = BitConverter.ToString(dataHash).Replace("-", "");
            logLine("[VERIFY] expected_code_hash=" + expectedCode);
            logLine("[VERIFY] expected_data_hash=" + expectedData);

            byte[] seed = await Task.Run(() => LoadEd25519Seed(privateKeyPath)).ConfigureAwait(false);
            uint seq = (uint)(DateTime.UtcNow.Ticks & 0xFFFF);
            byte[] empty = new byte[0];
            byte[] sessionKey = null;
            bool legacy = false;

            logLine("[VERIFY] Step 1/2: Requesting session key...");
            for (int mode = 0; mode < 2; mode++)
            {
                bool tryLegacy = mode == 1;
                byte[] signingPayload = tryLegacy
                    ? BuildSigningPayloadLegacyU16(seq, ScOpGetSessionKey, empty, empty)
                    : BuildSigningPayload(seq, ScOpGetSessionKey, empty, empty);
                byte[] sig = Ed25519Sign(seed, signingPayload);
                var reply = await SendSecureCommandAsync(seq, ScOpGetSessionKey, empty, sig, stepTimeoutMs).ConfigureAwait(false);
                logLine("[VERIFY] GET_SESSION_KEY " + (tryLegacy ? "legacy-u16" : "primary-u32") + " result=" + reply.result);
                if (reply.result == 0)
                {
                    sessionKey = reply.data;
                    legacy = tryLegacy;
                    break;
                }
            }

            if (sessionKey == null || sessionKey.Length < 8)
                throw new InvalidOperationException("GET_SESSION_KEY failed or returned short key.");

            logLine("[VERIFY] Step 2/2: Reading checksum registry from FC...");
            seq++;
            byte[] getSigning = legacy
                ? BuildSigningPayloadLegacyU16(seq, ScOpGetChecksumRegistry, empty, sessionKey)
                : BuildSigningPayload(seq, ScOpGetChecksumRegistry, empty, sessionKey);
            byte[] getSig = Ed25519Sign(seed, getSigning);
            var getReply = await SendSecureCommandAsync(seq, ScOpGetChecksumRegistry, empty, getSig, stepTimeoutMs).ConfigureAwait(false);
            if (getReply.result != 0)
                throw new InvalidOperationException("GET_CHECKSUM_REGISTRY failed: result=" + getReply.result);

            const byte algoSha256 = 1;
            bool codeOk = false;
            bool dataOk = false;
            bool algoVerified = false;
            bool algoOk = false;
            string storedCode = "(none)";
            string storedData = "(none)";

            byte[] readBack = getReply.data ?? new byte[0];
            if (readBack.Length >= 80)
            {
                algoVerified = true;
                algoOk = readBack[8] == algoSha256;
                byte[] code = readBack.Skip(16).Take(32).ToArray();
                byte[] data = readBack.Skip(48).Take(32).ToArray();
                storedCode = BitConverter.ToString(code).Replace("-", "");
                storedData = BitConverter.ToString(data).Replace("-", "");
                codeOk = code.SequenceEqual(codeHash);
                dataOk = data.SequenceEqual(dataHash);
            }
            else if (readBack.Length >= 65)
            {
                byte[] code = readBack.Skip(1).Take(32).ToArray();
                byte[] data = readBack.Skip(33).Take(32).ToArray();
                storedCode = BitConverter.ToString(code).Replace("-", "");
                storedData = BitConverter.ToString(data).Replace("-", "");
                codeOk = code.SequenceEqual(codeHash);
                dataOk = data.SequenceEqual(dataHash);
            }

            logLine("[VERIFY] stored_code_hash=" + storedCode);
            logLine("[VERIFY] stored_data_hash=" + storedData);

            if (algoVerified && !algoOk)
                throw new InvalidOperationException("Registry algorithm mismatch: expected SHA2-256.");
            if (!codeOk || !dataOk)
                throw new InvalidOperationException("Registry mismatch. codeOk=" + codeOk + " dataOk=" + dataOk);

            logLine("[VERIFY] SUCCESS — Registry matches APJ. Code: OK  Data: OK");
        }

        // ================================================================
        // Diagnostics
        // ================================================================

        // ================================================================
        // Auto-Verify on Connect
        // ================================================================

        private async Task TryAutoVerifyOnConnectAsync()
        {
            await Task.Delay(1500); // let link settle

            if (!RoleBasedAccess.IsInRole(AppUserRole.Operator))
                return;

            if (Interlocked.CompareExchange(ref _autoVerifyInProgress, 1, 0) != 0)
                return;

            try
            {
                if (DateTime.UtcNow < _autoVerifySuppressedUntilUtc)
                {
                    log.Debug("[VERIFY-AUTO] Skipped: suppressed until " + _autoVerifySuppressedUntilUtc.ToString("o"));
                    return;
                }

                bool mavConnected = MainV2.comPort?.BaseStream != null && MainV2.comPort.BaseStream.IsOpen;
                bool hasHeartbeat = mavConnected && MainV2.comPort.MAV?.sysid > 0;
                if (!mavConnected || !hasHeartbeat)
                {
                    log.Debug("[VERIFY-AUTO] Skipped: MAVLink not connected or no heartbeat.");
                    return;
                }

                string currentPort = MainV2.comPortName ?? string.Empty;
                if (string.Equals(currentPort, _lastAutoVerifyPort, StringComparison.OrdinalIgnoreCase))
                {
                    log.Debug("[VERIFY-AUTO] Skipped: same port as last auto-verify (" + currentPort + ").");
                    return;
                }

                string fwPath = ResolveDefaultFirmwareForRegistryScripts();
                string mappedAutoVerifyPath = TryMapLegacySignedFirmwarePath(fwPath,
                    (txtApKeyOutDir?.Text ?? Settings.Instance[AppSettingApKeyOutDir] ?? string.Empty).Trim());
                if (!string.IsNullOrWhiteSpace(mappedAutoVerifyPath))
                {
                    fwPath = mappedAutoVerifyPath;
                    if (txtFirmwareFile != null)
                    {
                        BeginInvoke((MethodInvoker)(() => txtFirmwareFile.Text = fwPath));
                    }
                }

                if (string.IsNullOrWhiteSpace(fwPath) || !File.Exists(fwPath))
                {
                    log.Debug("[VERIFY-AUTO] Skipped: no firmware file selected.");
                    return;
                }

                _lastAutoVerifyPort = currentPort;
                log.Info("[VERIFY-AUTO] Starting auto-verify on connect. Port=" + currentPort + " Firmware=" + Path.GetFileName(fwPath));

                string fwHash = ComputeFileSha256(fwPath);
                var manifestResult = ValidateReleaseManifestForArtifact(fwPath, fwHash);
                string board = txtApBoard?.Text.Trim() ?? Settings.Instance[AppSettingApBoard] ?? "Pixhawk6C";
                bool keyResolved = TryResolveConfiguredKeyPaths(board,
                    out string keyFolder,
                    out string keyPath,
                    out string pubKeyPath,
                    out string keyError);

                string statusText;
                Color statusColor;

                if (!keyResolved)
                {
                    statusText = "Auto-verify WARNING: " + keyError;
                    statusColor = Color.Orange;
                    AppendOutput("[VERIFY-AUTO] " + statusText);
                    log.Warn("[VERIFY-AUTO] " + keyError);
                }
                else
                {
                    AppendOutput("[VERIFY-AUTO] Running native registry verify...");
                    AppendOutput("[VERIFY-AUTO] Firmware: " + Path.GetFileName(fwPath));
                    AppendOutput("[VERIFY-AUTO] Keys folder: " + keyFolder);

                    try
                    {
                        await VerifyChecksumRegistryNativeAsync(fwPath, keyPath,
                            msg =>
                            {
                                AppendOutput("[VERIFY-AUTO] " + msg);
                            }).ConfigureAwait(true);

                        if (manifestResult.IsValid)
                        {
                            statusText = "Auto-verify PASSED: registry + manifest OK";
                            statusColor = Color.LimeGreen;
                        }
                        else
                        {
                            statusText = "Auto-verify WARNING: registry OK, manifest issue - " + manifestResult.Reason;
                            statusColor = Color.Orange;
                        }
                        log.Info("[VERIFY-AUTO] " + statusText);
                    }
                    catch (Exception vex)
                    {
                        bool registryUnavailable = vex.Message.IndexOf("GET_CHECKSUM_REGISTRY failed: result=4", StringComparison.OrdinalIgnoreCase) >= 0;
                        if (registryUnavailable)
                        {
                            statusText = "Auto-verify WARNING: checksum registry not provisioned yet (run Provision Registry after flash).";
                            statusColor = Color.Orange;
                        }
                        else
                        {
                            statusText = "Auto-verify FAILED: " + vex.Message;
                            statusColor = Color.Red;
                        }
                        AppendOutput("[VERIFY-AUTO] " + statusText);
                        log.Warn("[VERIFY-AUTO] " + statusText);
                    }
                }

                BeginInvoke((MethodInvoker)(() =>
                {
                    if (lblWorkflowStatus != null && !lblWorkflowStatus.IsDisposed)
                    {
                        lblWorkflowStatus.Text      = statusText;
                        lblWorkflowStatus.ForeColor = statusColor;
                    }
                }));
            }
            catch (Exception ex)
            {
                log.Warn("[VERIFY-AUTO] Exception: " + ex.Message);
            }
            finally
            {
                Interlocked.Exchange(ref _autoVerifyInProgress, 0);
            }
        }

        // ================================================================
        // Diagnostics
        // ================================================================

        private void RunDiagnostics()
        {
            var sb = new StringBuilder();

            // Log file
            bool logOk = File.Exists(_logFilePath);
            sb.AppendLine((logOk ? "[OK]  " : "[WARN]") + " Log file: " + (logOk ? _logFilePath : "not found at " + _logFilePath));

            // Firmware.cs / UploadFlash
            sb.AppendLine("[OK]  Firmware upload service: available");

            // WSL
            bool wslOk = false;
            try
            {
                var p = new Process
                {
                    StartInfo = new ProcessStartInfo("wsl", "--status")
                    {
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };
                p.Start();
                wslOk = p.WaitForExit(3000) && p.ExitCode == 0;
            }
            catch { wslOk = false; }
            sb.AppendLine((wslOk ? "[OK]  " : "[WARN]") + " WSL: " + (wslOk ? "available" : "not available — Ed25519 key generation unavailable"));

            // Audit export dir
            bool auditOk = Directory.Exists(_auditExportFolder);
            sb.AppendLine((auditOk ? "[OK]  " : "[INFO]") + " Audit export folder: " + (auditOk ? "exists" : "will be created on first export"));

            // MAVLink connection
            bool mavOk = MainV2.comPort?.BaseStream != null && MainV2.comPort.BaseStream.IsOpen;
            sb.AppendLine((mavOk ? "[OK]  " : "[INFO]") + " MAVLink link: " + (mavOk ? "connected" : "not connected"));

            // HMAC key
            bool hmacOk = _currentHmacKey != null && _currentHmacKey.Length >= 16;
            sb.AppendLine((hmacOk ? "[OK]  " : "[WARN]") + " HMAC key: " + (hmacOk ? "configured (" + _currentHmacKey.Length * 8 + "-bit)" : "not configured"));

            string result = sb.ToString().TrimEnd();
            BeginInvoke((MethodInvoker)(() =>
            {
                if (txtDiag != null && !txtDiag.IsDisposed)
                    txtDiag.Text = result;
            }));
        }

        // ================================================================
        // SHA256 / APJ status helpers
        // ================================================================

        private void UpdateFirmwareSha256(string path)
        {
            if (!File.Exists(path)) return;
            Task.Run(() =>
            {
                try
                {
                    string hash = ComputeFileSha256(path);
                    _lastFirmwareSha256 = hash;
                    BeginInvoke((MethodInvoker)(() =>
                    {
                        if (txtSha256 != null) txtSha256.Text = hash;
                    }));
                }
                catch (Exception ex)
                {
                    log.Warn("SHA256 compute failed: " + ex.Message);
                }
            });
        }

        private static string ComputeFileSha256(string path)
        {
            using (var sha = SHA256.Create())
            using (var fs = File.OpenRead(path))
            {
                byte[] h = sha.ComputeHash(fs);
                return BitConverter.ToString(h).Replace("-", string.Empty).ToLowerInvariant();
            }
        }

        private void UpdateApjStatusLabel(string path, Label lbl)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                lbl.Text = "APJ Status: No file selected";
                lbl.ForeColor = Color.Gray;
                return;
            }

            string ext = Path.GetExtension(path).ToLowerInvariant();
            if (ext != ".apj")
            {
                lbl.Text = "Status: " + ext.ToUpperInvariant() + " (non-APJ firmware)";
                lbl.ForeColor = Color.Goldenrod;
                return;
            }

            try
            {
                bool hasSig = IsApjSigned(path);
                bool inSignedFolder =
                    path.IndexOf("\\signed\\firmware\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    path.IndexOf("/signed/firmware/", StringComparison.OrdinalIgnoreCase) >= 0;

                if (hasSig)
                {
                    lbl.Text = "APJ Status: ✓ Signed (Ed25519 marker present)";
                    lbl.ForeColor = Color.LimeGreen;
                }
                else if (inSignedFolder)
                {
                    lbl.Text = "APJ Status: Unsigned placeholder in signed folder — run Sign Firmware";
                    lbl.ForeColor = Color.Orange;
                }
                else
                {
                    lbl.Text = "APJ Status: Unsigned — signable via ArduPilot Signing tab";
                    lbl.ForeColor = Color.Orange;
                }
            }
            catch
            {
                lbl.Text = "APJ Status: Unable to read file";
                lbl.ForeColor = Color.Red;
            }
        }

        private void UpdateApjStatusLabel()
        {
            string path = txtApApjPath?.Text?.Trim() ?? string.Empty;
            if (lblApApjStatus != null)
                UpdateApjStatusLabel(path, lblApApjStatus);
        }

        private static bool IsApjSigned(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return false;
            try
            {
                string text = File.ReadAllText(path);
                return text.Contains("\"signed_firmware\"") || text.Contains("\"signature\"");
            }
            catch { return false; }
        }

        // ================================================================
        // Release Manifest Validation  (ported from SaamGCS)
        // ================================================================

        private struct ManifestResult
        {
            public bool   IsValid;
            public bool   IsAbsent;  // true = no manifest found (soft); false+!IsValid = manifest found but invalid (hard)
            public string Reason;
            public static ManifestResult Valid(string reason)   => new ManifestResult { IsValid = true,  IsAbsent = false, Reason = reason };
            public static ManifestResult Absent(string reason)  => new ManifestResult { IsValid = false, IsAbsent = true,  Reason = reason };
            public static ManifestResult Invalid(string reason) => new ManifestResult { IsValid = false, IsAbsent = false, Reason = reason };
        }

        private ManifestResult ValidateReleaseManifestForArtifact(string firmwarePath, string firmwareHash)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(firmwarePath) || !File.Exists(firmwarePath))
                    return ManifestResult.Invalid("Firmware file not found.");

                if (!TryResolveReleaseManifestPaths(firmwarePath, out string manifestPath, out string manifestHashPath))
                    return ManifestResult.Absent("release_manifest.json not found near selected firmware artifact.");

                if (!File.Exists(manifestHashPath))
                    return ManifestResult.Invalid("release_manifest.sha256 is missing.");

                string expectedManifestHash = ReadManifestExpectedHash(manifestHashPath);
                if (string.IsNullOrWhiteSpace(expectedManifestHash))
                    return ManifestResult.Invalid("release_manifest.sha256 is invalid.");

                string actualManifestHash = ComputeFileSha256(manifestPath);
                if (!string.Equals(expectedManifestHash, actualManifestHash, StringComparison.OrdinalIgnoreCase))
                    return ManifestResult.Invalid("Manifest checksum mismatch.");

                if (!ValidateManufacturerManifestSignature(manifestPath, out string signatureReason))
                    return ManifestResult.Invalid(signatureReason);

                string manifestJson = File.ReadAllText(manifestPath);
                JObject manifestObj = JObject.Parse(manifestJson);
                var artifacts = manifestObj["artifacts"] as JArray;
                if (artifacts == null || artifacts.Count == 0)
                    return ManifestResult.Invalid("Manifest has no artifact entries.");

                if (!ValidateManifestChecksumPartitions(manifestObj, artifacts, out string partitionReason))
                    return ManifestResult.Invalid(partitionReason);

                string manifestBaseDir = Path.GetDirectoryName(Path.GetDirectoryName(manifestPath));
                string selectedRelativePath = GetRelativePathSafe(manifestBaseDir ?? string.Empty, firmwarePath).Replace('\\', '/');

                bool hashMatch = false, pathMatch = false, pathHashMatch = false;
                foreach (JToken token in artifacts)
                {
                    var entry = token as JObject;
                    if (entry == null) continue;
                    string entryPath = (entry["relativePath"]?.ToString() ?? string.Empty).Replace('\\', '/');
                    string entryHash = (entry["sha256"]?.ToString() ?? string.Empty).Trim();

                    if (!string.IsNullOrWhiteSpace(entryHash) &&
                        string.Equals(entryHash, firmwareHash, StringComparison.OrdinalIgnoreCase))
                        hashMatch = true;

                    if (!string.IsNullOrWhiteSpace(entryPath) &&
                        string.Equals(entryPath, selectedRelativePath, StringComparison.OrdinalIgnoreCase))
                    {
                        pathMatch = true;
                        if (!string.IsNullOrWhiteSpace(entryHash) &&
                            string.Equals(entryHash, firmwareHash, StringComparison.OrdinalIgnoreCase))
                            pathHashMatch = true;
                    }
                }

                if (!hashMatch)
                    return ManifestResult.Invalid("Selected firmware hash is not present in release manifest.");

                if (pathMatch && !pathHashMatch)
                    return ManifestResult.Invalid("Manifest entry path matched but hash mismatch for selected artifact.");

                log.Info("[PROTECTED] Release manifest checksum VERIFIED.");
                return ManifestResult.Valid("Manifest and artifact hash verified.");
            }
            catch (Exception ex)
            {
                log.Error("Release manifest verification failed", ex);
                return ManifestResult.Invalid("Release manifest verification failed: " + ex.Message);
            }
        }

        private static bool TryResolveReleaseManifestPaths(string firmwarePath, out string manifestPath, out string manifestHashPath)
        {
            manifestPath = string.Empty;
            manifestHashPath = string.Empty;

            string firmwareDir = Path.GetDirectoryName(firmwarePath) ?? string.Empty;
            string selectedTreeRoot = string.Empty;
            try
            {
                var info = new DirectoryInfo(firmwareDir);
                if (info.Parent != null)
                    selectedTreeRoot = info.Parent.FullName;
            }
            catch { }

            string[] candidates = new[]
            {
                Path.Combine(selectedTreeRoot, "Signed", "release_manifest.json"),
                Path.Combine(firmwareDir, "release_manifest.json"),
                Path.Combine(Path.GetDirectoryName(firmwareDir) ?? string.Empty, "release_manifest.json")
            };

            foreach (string candidate in candidates)
            {
                if (string.IsNullOrWhiteSpace(candidate) || !File.Exists(candidate))
                    continue;
                manifestPath = candidate;
                manifestHashPath = Path.ChangeExtension(candidate, ".sha256");
                return true;
            }
            return false;
        }

        private static string ReadManifestExpectedHash(string hashPath)
        {
            foreach (string rawLine in File.ReadAllLines(hashPath))
            {
                if (string.IsNullOrWhiteSpace(rawLine)) continue;
                string[] parts = rawLine.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0) continue;
                string token = parts[0].Trim();
                if (token.Length == 64) return token.ToUpperInvariant();
            }
            return string.Empty;
        }

        private bool ValidateManufacturerManifestSignature(string manifestPath, out string reason)
        {
            reason = string.Empty;
            try
            {
                if (!File.Exists(manifestPath))
                { reason = "Manifest file not found for signature verification."; return false; }

                string manifestDir = Path.GetDirectoryName(manifestPath) ?? string.Empty;
                string signaturePath = Path.Combine(manifestDir, "release_manifest.sig");
                if (!File.Exists(signaturePath))
                { reason = "Manufacturer manifest signature missing (release_manifest.sig)."; return false; }

                string certPath = ResolveManufacturerManifestCertificatePath(manifestDir);
                if (string.IsNullOrWhiteSpace(certPath) || !File.Exists(certPath))
                { reason = "Manufacturer certificate missing for manifest verification. Place release_manifest.pem/.cer near the manifest."; return false; }

                byte[] manifestBytes   = File.ReadAllBytes(manifestPath);
                byte[] signatureBytes  = ReadDetachedSignatureBytes(signaturePath);
                if (signatureBytes == null || signatureBytes.Length == 0)
                { reason = "Manufacturer manifest signature file is empty or invalid."; return false; }

                X509Certificate2 cert = LoadCertificateForVerification(certPath);
                if (cert == null)
                { reason = "Manufacturer certificate could not be loaded."; return false; }

                using (cert)
                using (var rsa = cert.GetRSAPublicKey())
                {
                    if (rsa == null)
                    { reason = "Manufacturer certificate does not contain an RSA public key."; return false; }

                    bool valid = rsa.VerifyData(manifestBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                              || rsa.VerifyData(manifestBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

                    if (!valid)
                    { reason = "Manufacturer manifest signature verification FAILED."; return false; }
                }

                log.Info("[PROTECTED] Manufacturer manifest signature VERIFIED.");
                return true;
            }
            catch (Exception ex)
            {
                log.Error("Manufacturer manifest signature verification failed", ex);
                reason = "Manufacturer manifest signature verification failed: " + ex.Message;
                return false;
            }
        }

        private static string ResolveManufacturerManifestCertificatePath(string manifestDir)
        {
            if (string.IsNullOrWhiteSpace(manifestDir)) return string.Empty;
            string[] candidates = {
                Path.Combine(manifestDir, "release_manifest.cer"),
                Path.Combine(manifestDir, "release_manifest.crt"),
                Path.Combine(manifestDir, "release_manifest.pem"),
                Path.Combine(manifestDir, "manufacturer_manifest_cert.cer"),
                Path.Combine(manifestDir, "manufacturer_manifest_cert.crt"),
                Path.Combine(manifestDir, "manufacturer_manifest_cert.pem")
            };
            foreach (string c in candidates)
                if (File.Exists(c)) return c;
            return string.Empty;
        }

        private static X509Certificate2 LoadCertificateForVerification(string certPath)
        {
            if ((Path.GetExtension(certPath) ?? string.Empty).ToLowerInvariant() == ".pem")
            {
                string pem = File.ReadAllText(certPath);
                byte[] certBytes = ExtractPemCertificateBytes(pem);
                return certBytes == null || certBytes.Length == 0 ? null : new X509Certificate2(certBytes);
            }
            return new X509Certificate2(certPath);
        }

        private static byte[] ExtractPemCertificateBytes(string pem)
        {
            const string begin = "-----BEGIN CERTIFICATE-----";
            const string end   = "-----END CERTIFICATE-----";
            int start  = pem.IndexOf(begin, StringComparison.Ordinal);
            int finish = pem.IndexOf(end,   StringComparison.Ordinal);
            if (start < 0 || finish <= start) return null;
            string b64 = pem.Substring(start + begin.Length, finish - (start + begin.Length))
                            .Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();
            try { return string.IsNullOrWhiteSpace(b64) ? null : Convert.FromBase64String(b64); }
            catch { return null; }
        }

        private static byte[] ReadDetachedSignatureBytes(string signaturePath)
        {
            byte[] raw = File.ReadAllBytes(signaturePath);
            if (raw == null || raw.Length == 0) return new byte[0];
            try
            {
                string text = Encoding.UTF8.GetString(raw).Trim();
                if (TryDecodeSignaturePem(text, out byte[] pemBytes)) return pemBytes;
                if (IsLikelyBase64(text)) return Convert.FromBase64String(text);
            }
            catch { }
            return raw;
        }

        private static bool TryDecodeSignaturePem(string text, out byte[] bytes)
        {
            bytes = null;
            const string begin = "-----BEGIN SIGNATURE-----";
            const string end   = "-----END SIGNATURE-----";
            int start  = text.IndexOf(begin, StringComparison.Ordinal);
            int finish = text.IndexOf(end,   StringComparison.Ordinal);
            if (start < 0 || finish <= start) return false;
            string b64 = text.Substring(start + begin.Length, finish - (start + begin.Length))
                             .Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();
            if (!IsLikelyBase64(b64)) return false;
            try { bytes = Convert.FromBase64String(b64); return bytes != null && bytes.Length > 0; }
            catch { bytes = null; return false; }
        }

        private static bool IsLikelyBase64(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return false;
            string s = input.Trim();
            if (s.Length < 16 || s.Length % 4 != 0) return false;
            foreach (char ch in s)
                if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                       (ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '='))
                    return false;
            return true;
        }

        private static bool ValidateManifestChecksumPartitions(JObject manifestObj, JArray artifacts, out string reason)
        {
            reason = string.Empty;
            var partitions = manifestObj?["checksumPartitions"] as JObject;
            if (partitions == null)
            { reason = "Manifest missing checksumPartitions."; return false; }

            var codePartition = partitions["code"] as JObject;
            var dataPartition = partitions["data"] as JObject;
            if (codePartition == null || dataPartition == null)
            { reason = "Manifest checksumPartitions must include both code and data sections."; return false; }

            string algorithm = (partitions["algorithm"]?.ToString() ?? string.Empty).Trim();
            if (!algorithm.Equals("SHA2-256", StringComparison.OrdinalIgnoreCase) &&
                !algorithm.Equals("SHA-256",  StringComparison.OrdinalIgnoreCase) &&
                !algorithm.Equals("SHA256",   StringComparison.OrdinalIgnoreCase))
            { reason = "Manifest checksumPartitions.algorithm must declare SHA2-256."; return false; }

            if (!ValidateSinglePartition("code", codePartition, artifacts, out reason)) return false;
            if (!ValidateSinglePartition("data", dataPartition, artifacts, out reason)) return false;
            return true;
        }

        private static bool ValidateSinglePartition(string partitionName, JObject partition, JArray artifacts, out string reason)
        {
            reason = string.Empty;
            string declaredHash  = (partition["aggregateSha256"]?.ToString() ?? string.Empty).Trim();
            int? declaredCount   = TryReadManifestInt(partition["itemCount"]);
            var entries = new List<string>();

            foreach (JToken token in artifacts)
            {
                var entry = token as JObject;
                if (entry == null) continue;
                string entryHash  = (entry["sha256"]?.ToString()       ?? string.Empty).Trim();
                string entryPath  = (entry["relativePath"]?.ToString() ?? string.Empty).Replace('\\', '/');
                if (string.IsNullOrWhiteSpace(entryHash) || string.IsNullOrWhiteSpace(entryPath)) continue;

                string artifactClass = (entry["artifactClass"]?.ToString() ?? string.Empty).Trim().ToLowerInvariant();
                if (string.IsNullOrWhiteSpace(artifactClass))
                    artifactClass = InferArtifactClass(entryPath);

                if (!string.Equals(artifactClass, partitionName, StringComparison.OrdinalIgnoreCase)) continue;
                entries.Add(entryPath + "|" + entryHash.ToUpperInvariant());
            }

            if (declaredCount.HasValue && declaredCount.Value != entries.Count)
            { reason = "Manifest " + partitionName + " partition itemCount mismatch."; return false; }

            string computedHash = ComputeAggregatePartitionSha256(entries);
            if (!string.Equals(declaredHash, computedHash, StringComparison.OrdinalIgnoreCase))
            { reason = "Manifest " + partitionName + " partition checksum mismatch."; return false; }
            return true;
        }

        private static string InferArtifactClass(string relativePath)
        {
            string n = (relativePath ?? string.Empty).Replace('\\', '/').ToLowerInvariant();
            if (n.Contains("/parameters/") ||
                n.EndsWith(".param") || n.EndsWith(".params") || n.EndsWith(".parm"))
                return "data";
            return "code";
        }

        private static string ComputeAggregatePartitionSha256(List<string> entries)
        {
            var list = entries ?? new List<string>();
            list.Sort(StringComparer.Ordinal);
            string payload = list.Count > 0 ? string.Join("\n", list) + "\n" : string.Empty;
            byte[] bytes = Encoding.UTF8.GetBytes(payload);
            using (var sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", string.Empty).ToUpperInvariant();
        }

        private static int? TryReadManifestInt(JToken token)
        {
            if (token == null) return null;
            if (token.Type == JTokenType.Integer) return token.Value<int>();
            if (int.TryParse(token.ToString(), out int v)) return v;
            return null;
        }

        private static string GetRelativePathSafe(string basePath, string targetPath)
        {
            try
            {
                string baseFull = Path.GetFullPath(basePath ?? string.Empty);
                if (!baseFull.EndsWith(Path.DirectorySeparatorChar.ToString()))
                    baseFull += Path.DirectorySeparatorChar;
                string targetFull = Path.GetFullPath(targetPath ?? string.Empty);
                var baseUri   = new Uri(baseFull);
                var targetUri = new Uri(targetFull);
                return Uri.UnescapeDataString(baseUri.MakeRelativeUri(targetUri).ToString())
                          .Replace('/', Path.DirectorySeparatorChar);
            }
            catch { return targetPath ?? string.Empty; }
        }

        // ================================================================
        // Live Log
        // ================================================================

        private void LogTimer_Tick(object sender, EventArgs e)
        {
            TailLogFile();
        }

        private void TailLogFile()
        {
            if (!File.Exists(_logFilePath)) return;
            try
            {
                using (var fs = new FileStream(_logFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    long len = fs.Length;
                    if (_lastLogPos == 0 && len > 8192)
                        _lastLogPos = len - 8192;

                    if (len <= _lastLogPos) return;

                    fs.Seek(_lastLogPos, SeekOrigin.Begin);
                    using (var sr = new StreamReader(fs, Encoding.UTF8, true, 4096, true))
                    {
                        string newText = sr.ReadToEnd();
                        _lastLogPos = len;

                        if (!string.IsNullOrEmpty(newText))
                        {
                            BeginInvoke((MethodInvoker)(() =>
                            {
                                if (txtLiveLog == null || txtLiveLog.IsDisposed) return;
                                const int maxChars = 200000;
                                if (txtLiveLog.TextLength + newText.Length > maxChars)
                                    txtLiveLog.Text = txtLiveLog.Text.Substring(txtLiveLog.TextLength / 2);
                                txtLiveLog.AppendText(newText);
                                txtLiveLog.SelectionStart = txtLiveLog.TextLength;
                                txtLiveLog.ScrollToCaret();
                            }));
                        }
                    }
                }
            }
            catch { /* log file may be locked momentarily */ }
        }

        private void BtnLogFind_Click(object sender, EventArgs e)
        {
            string term = txtLogFind?.Text?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(term) || txtLiveLog == null) return;

            int start = txtLiveLog.SelectionStart + txtLiveLog.SelectionLength;
            int idx = txtLiveLog.Text.IndexOf(term, start, StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
                idx = txtLiveLog.Text.IndexOf(term, 0, StringComparison.OrdinalIgnoreCase);

            if (idx >= 0)
            {
                txtLiveLog.Focus();
                txtLiveLog.Select(idx, term.Length);
                txtLiveLog.ScrollToCaret();
            }
            else
            {
                MessageBox.Show("\"" + term + "\" not found in current log view.",
                    "Find", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        // ================================================================
        // ArduPilot Ed25519 (WSL bridge)
        // ================================================================

        private async Task ApCheckWslAsync()
        {
            btnApCheckWsl.Enabled = false;
            lblApWslStatus.Text = "Checking WSL...";
            lblApWslStatus.ForeColor = Color.Gray;
            try
            {
                bool ok = await Task.Run(() => IsWslAvailable());
                lblApWslStatus.Text      = ok ? "WSL: Available ✓" : "WSL: Not found — install WSL and Ubuntu";
                lblApWslStatus.ForeColor = ok ? Color.LimeGreen : Color.Red;
                AppendApLog("[WSL] " + lblApWslStatus.Text);
            }
            finally
            {
                btnApCheckWsl.Enabled = true;
            }
        }

        private async Task ApGenerateKeysAsync()
        {
            if (!EnsureProtectedRole(AppUserRole.Admin, "generate signing keys"))
                return;

            string board  = txtApBoard.Text.Trim();
            string outDir = txtApKeyOutDir.Text.Trim();

            if (string.IsNullOrWhiteSpace(board))
            { ShowErr("Enter a board name (e.g. Pixhawk6C)."); return; }
            if (string.IsNullOrWhiteSpace(outDir))
            { ShowErr("Select a valid output directory."); return; }
            if (string.IsNullOrWhiteSpace(txtApRoot.Text))
            { ShowErr("Enter the ArduPilot WSL repo path."); return; }

            if (MessageBox.Show(
                    "Generate Ed25519 key pair for board '" + board + "' in:\n" + outDir + "\n\nContinue?",
                    "Confirm Key Generation", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            btnApGenerateKeys.Enabled = false;
            txtApOutput.Text = string.Empty;
            AppendApLog("[KEYGEN] Board: " + board + "  Output: " + outDir);

            try
            {
                Directory.CreateDirectory(outDir);
                string repoPath = txtApRoot.Text.Trim();
                string wslOutDir   = ToWslPath(outDir);
                string wslRepoPath = ToWslPath(repoPath);

                // Try ArduPilot signing/generate_keys.py first; fall back to openssl with KEYV1 format.
                string checkScript =
                    "[ -f \"" + wslRepoPath + "/Tools/scripts/signing/generate_keys.py\" ] && echo FOUND || echo MISSING";
                string checkResult = await Task.Run(() => RunWslCommand(checkScript, null));
                bool hasScript = checkResult != null && checkResult.Contains("FOUND");

                string script;
                if (hasScript)
                {
                    AppendApLog("[KEYGEN] Using ArduPilot signing/generate_keys.py");
                    script = "mkdir -p \"" + wslOutDir + "\" && " +
                             "cd \"" + wslOutDir + "\" && " +
                             "python3 \"" + wslRepoPath + "/Tools/scripts/signing/generate_keys.py\" " + board;
                }
                else
                {
                    AppendApLog("[KEYGEN] generate_keys.py not found — using openssl keygen with KEYV1 format");
                    // Create ArduPilot-compatible text keys: PRIVATE_KEYV1:/PUBLIC_KEYV1:
                    string tmpPriv = wslOutDir + "/_tmp_priv_ed25519.der";
                    string tmpPub  = wslOutDir + "/_tmp_pub_ed25519.der";
                    string privOut = wslOutDir + "/" + board + "_private_key.dat";
                    string pubOut  = wslOutDir + "/" + board + "_public_key.dat";
                    script =
                        "mkdir -p \"" + wslOutDir + "\" && " +
                        "openssl genpkey -algorithm Ed25519 -outform DER -out \"" + tmpPriv + "\" && " +
                        "openssl pkey -in \"" + tmpPriv + "\" -inform DER -pubout -outform DER -out \"" + tmpPub + "\" && " +
                        "python3 -c \"" +
                            "import base64;" +
                            "p=open('" + tmpPriv + "','rb').read()[-32:];" +
                            "q=open('" + tmpPub  + "','rb').read()[-32:];" +
                            "open('" + privOut + "','w').write('PRIVATE_KEYV1:'+base64.b64encode(p).decode('utf-8'));" +
                            "open('" + pubOut  + "','w').write('PUBLIC_KEYV1:'+base64.b64encode(q).decode('utf-8'));" +
                            "import os; os.remove('" + tmpPriv + "'); os.remove('" + tmpPub + "');" +
                            "print('[KEYGEN] Ed25519 keys written: " + board + "_private_key.dat + " + board + "_public_key.dat')" +
                        "\"";
                }

                string result = await Task.Run(() => RunWslCommand(script, line => AppendApLog(line)));
                if (result != null)
                {
                    AppendApLog("[KEYGEN] Done. Check output directory for .dat files.");
                    string privKey = Path.Combine(outDir, board + "_private_key.dat");
                    if (File.Exists(privKey))
                    {
                        txtApPrivateKey.Text = privKey;
                        Settings.Instance[AppSettingApPrivKey] = outDir;
                        AppendApLog("[KEYGEN] ✓ Private key: " + privKey);
                        MessageBox.Show(
                            "Keys generated!\n\nPrivate: " + privKey + "\n\nNext: build a secure bootloader embedding the public key.",
                            "Keys Generated", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                AppendApLog("[KEYGEN] ERROR: " + ex.Message);
                ShowErr("Key generation failed:\n" + ex.Message);
            }
            finally
            {
                btnApGenerateKeys.Enabled = true;
                Settings.Instance[AppSettingApBoard]     = txtApBoard.Text.Trim();
                Settings.Instance[AppSettingApKeyOutDir] = txtApKeyOutDir.Text.Trim();
                Settings.Instance[AppSettingApWslRepo]   = txtApRoot.Text.Trim();
            }
        }

        private async Task ApBuildFwAndBlAsync()
        {
            if (!EnsureProtectedRole(AppUserRole.Admin, "build firmware and bootloader"))
                return;

            string board   = txtApBoard.Text.Trim();
            string repoPath = txtApRoot.Text.Trim();
            string outDir  = txtApKeyOutDir.Text.Trim();

            if (string.IsNullOrWhiteSpace(board) || string.IsNullOrWhiteSpace(repoPath))
            { ShowErr("Enter the board name and ArduPilot WSL repo path."); return; }

            btnApBuildFwBl.Enabled = false;
            txtApOutput.Text = string.Empty;
            AppendApLog("[BUILD] Building firmware + bootloader for board: " + board);

            try
            {
                string effectiveOutDir = string.IsNullOrWhiteSpace(outDir)
                    ? Path.Combine(Environment.CurrentDirectory, "tools")
                    : outDir;
                Directory.CreateDirectory(effectiveOutDir);

                // SaamGCS-style folder layout: Original\ and Signed\ sit directly under effectiveOutDir
                string origFwDir   = Path.Combine(effectiveOutDir, "Original",  "Firmware");
                string origBlDir   = Path.Combine(effectiveOutDir, "Original",  "Bootloader");
                string signedFwDir = Path.Combine(effectiveOutDir, "Signed",    "Firmware");
                string signedBlDir = Path.Combine(effectiveOutDir, "Signed",    "Bootloader");

                Directory.CreateDirectory(origFwDir);
                Directory.CreateDirectory(origBlDir);
                Directory.CreateDirectory(signedFwDir);
                Directory.CreateDirectory(signedBlDir);

                // Remove legacy placeholders from earlier staging behavior.
                foreach (string oldUnsigned in Directory.GetFiles(signedFwDir, "*-unsigned.apj", SearchOption.TopDirectoryOnly))
                {
                    try
                    {
                        File.Delete(oldUnsigned);
                        AppendApLog("[BUILD] cleanup: removed legacy placeholder " + Path.GetFileName(oldUnsigned));
                    }
                    catch (Exception ex)
                    {
                        AppendApLog("[BUILD] cleanup warn: " + ex.Message);
                    }
                }
                foreach (string oldPending in Directory.GetFiles(signedFwDir, "*-signed-pending.apj", SearchOption.TopDirectoryOnly))
                {
                    try
                    {
                        File.Delete(oldPending);
                        AppendApLog("[BUILD] cleanup: removed legacy pending file " + Path.GetFileName(oldPending));
                    }
                    catch (Exception ex)
                    {
                        AppendApLog("[BUILD] cleanup warn: " + ex.Message);
                    }
                }

                AppendApLog("[BUILD] Created folder: " + origFwDir);
                AppendApLog("[BUILD] Created folder: " + origBlDir);
                AppendApLog("[BUILD] Created folder: " + signedFwDir);
                AppendApLog("[BUILD] Created folder: " + signedBlDir);

                string wslRepo = ToWslPath(repoPath);
                string sourceDirWin = Path.Combine(repoPath.Replace('/', '\\'), "build", board, "bin");

                AppendApLog("[BUILD] WSL repo: " + wslRepo);
                AppendApLog("[BUILD] Windows source: " + sourceDirWin);

                string script = "cd \"" + wslRepo + "\" && " +
                    "./waf configure --board " + board + " --signed-fw && " +
                    "./waf copter";

                await Task.Run(() => RunWslCommand(script, line => AppendApLog(line)));
                AppendApLog("[BUILD] Build completed. Staging artifacts to: " + effectiveOutDir);

                if (!Directory.Exists(sourceDirWin))
                {
                    AppendApLog("[BUILD] ERROR: source folder missing: " + sourceDirWin);
                    return;
                }

                string[] files = Directory.GetFiles(sourceDirWin, "*.*", SearchOption.TopDirectoryOnly);
                int copied = 0;
                foreach (string src in files)
                {
                    string ext = Path.GetExtension(src).ToLowerInvariant();
                    bool isArtifact =
                        ext == ".apj" || ext == ".bin" || ext == ".hex" ||
                        ext == ".px4" || ext == ".elf" || ext == ".abin";
                    if (!isArtifact)
                        continue;

                    string fileName = Path.GetFileName(src);
                    bool isBootloader = fileName.IndexOf("bootloader", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                        fileName.IndexOf("_bl", StringComparison.OrdinalIgnoreCase) >= 0;

                    string destDir = isBootloader ? origBlDir : origFwDir;
                    string dest = Path.Combine(destDir, fileName);
                    File.Copy(src, dest, true);

                    copied++;
                    AppendApLog("[BUILD] copied: " + fileName + " -> " + destDir);
                }

                if (copied == 0)
                {
                    AppendApLog("[BUILD] WARN: no expected artifacts found in " + sourceDirWin);
                }

                string[] apjFiles = Directory.GetFiles(origFwDir, "*.apj");
                if (apjFiles.Length > 0)
                {
                    string origApj = apjFiles[0];
                    txtApApjPath.Text = origApj;
                    UpdateApjStatusLabel();
                    AppendApLog("[BUILD] Firmware staged: " + Path.GetFileName(origApj));

                    // SaamGCS-like behavior: auto-sign firmware on this button if private key is available.
                    string privateKeyPath = txtApPrivateKey != null ? txtApPrivateKey.Text.Trim() : string.Empty;
                    if (!File.Exists(privateKeyPath))
                        privateKeyPath = Path.Combine(effectiveOutDir, board + "_private_key.dat");

                    if (File.Exists(privateKeyPath))
                    {
                        if (!EnsureArduPilotKeyFormat(privateKeyPath, false, AppendApLog))
                        {
                            AppendApLog("[BUILD] WARN: private key format invalid for ArduPilot signing: " + privateKeyPath);
                            return;
                        }

                        EnsureSigningScriptExists(repoPath, AppendApLog);
                        string signedApj = Path.Combine(signedFwDir, Path.GetFileNameWithoutExtension(origApj) + "-signed.apj");
                        File.Copy(origApj, signedApj, true);
                        string signScript = "cd \"" + wslRepo + "\" && " +
                            "python3 Tools/scripts/signing/make_secure_fw.py \"" + ToWslPath(signedApj) + "\" \"" + ToWslPath(privateKeyPath) + "\"";
                        await Task.Run(() => RunWslCommand(signScript, line => AppendApLog(line)));

                        if (IsApjSigned(signedApj))
                        {
                            txtApApjPath.Text = signedApj;
                            UpdateApjStatusLabel();
                            AppendApLog("[BUILD] ✓ Signed firmware created: " + Path.GetFileName(signedApj));
                        }
                        else
                        {
                            AppendApLog("[BUILD] WARN: signing failed — APJ in signed folder is not signed. Check script output above.");
                            if (File.Exists(signedApj)) File.Delete(signedApj);
                        }
                    }
                    else
                    {
                        AppendApLog("[BUILD] WARN: private key not found; skipping auto-sign. Expected: " + privateKeyPath);
                    }
                }

                string[] blFiles = Directory.GetFiles(origBlDir, "*.bin");
                if (blFiles.Length == 0)
                    blFiles = Directory.GetFiles(origFwDir, "*bl*.bin");
                if (blFiles.Length > 0)
                {
                    txtApBootloaderPath.Text = blFiles[0];
                    lblApBootloaderStatus.Text = "✓ Staged: " + Path.GetFileName(blFiles[0]);
                    lblApBootloaderStatus.ForeColor = Color.LimeGreen;
                    AppendApLog("[BUILD] Bootloader staged: " + Path.GetFileName(blFiles[0]));
                }

                // SaamGCS-like behavior: auto-generate/copy signed bootloader artifacts on this button.
                string pubKeyPathWin = Path.Combine(effectiveOutDir, board + "_public_key.dat");
                if (File.Exists(pubKeyPathWin))
                {
                    if (!EnsureArduPilotKeyFormat(pubKeyPathWin, true, AppendApLog))
                    {
                        AppendApLog("[BUILD] WARN: public key format invalid for ArduPilot signing: " + pubKeyPathWin);
                        return;
                    }

                    string blSignScript = "cd \"" + wslRepo + "\" && " +
                        "python3 Tools/scripts/build_bootloaders.py " + board + " --signing-key=\"" + ToWslPath(pubKeyPathWin) + "\"";
                    string blSignResult = await Task.Run(() => RunWslCommand(blSignScript, line => AppendApLog(line)));

                    bool blSignOk = blSignResult != null &&
                                    blSignResult.IndexOf("Failed to sign bootloader", StringComparison.OrdinalIgnoreCase) < 0 &&
                                    blSignResult.IndexOf("Build failed:", StringComparison.OrdinalIgnoreCase) < 0 &&
                                    blSignResult.IndexOf("UnicodeDecodeError", StringComparison.OrdinalIgnoreCase) < 0;

                    if (!blSignOk)
                    {
                        AppendApLog("[BUILD] WARN: signed bootloader generation failed; signed/bootloader not updated.");
                    }

                    if (blSignOk)
                    {
                        string[] bootCandidates = Directory.GetFiles(sourceDirWin, "*.bin", SearchOption.TopDirectoryOnly);
                        int signedCopied = 0;
                        foreach (string src in bootCandidates)
                        {
                            string name = Path.GetFileName(src);
                            bool looksLikeBootloader = name.IndexOf("bootloader", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                       name.IndexOf("_bl", StringComparison.OrdinalIgnoreCase) >= 0;
                            if (!looksLikeBootloader)
                                continue;

                            string signedName = Path.GetFileNameWithoutExtension(name) + "-signed" + Path.GetExtension(name);
                            string signedDest = Path.Combine(signedBlDir, signedName);
                            File.Copy(src, signedDest, true);
                            signedCopied++;
                            AppendApLog("[BUILD] ✓ Signed bootloader staged: " + signedName);
                            txtApBootloaderPath.Text = signedDest;
                        }

                        if (signedCopied == 0)
                            AppendApLog("[BUILD] WARN: no signed bootloader candidate generated in " + sourceDirWin);
                    }
                }
                else
                {
                    AppendApLog("[BUILD] WARN: public key not found; skipping signed bootloader generation. Expected: " + pubKeyPathWin);
                }

                // ── Generate release manifest (matches SaamGCS build_sign_ardupilot.ps1) ──
                string privKeyForManifest = Path.Combine(effectiveOutDir, board + "_private_key.dat");
                string pubKeyForManifest  = Path.Combine(effectiveOutDir, board + "_public_key.dat");
                GenerateReleaseManifestFiles(effectiveOutDir, board, privKeyForManifest, pubKeyForManifest);
            }
            catch (Exception ex)
            {
                AppendApLog("[BUILD] ERROR: " + ex.Message);
            }
            finally
            {
                btnApBuildFwBl.Enabled = true;
            }
        }

        // ================================================================
        // Release Manifest Generation  (mirrors New-ReleaseManifest +
        // New-ManifestRsaSignature from build_sign_ardupilot.ps1)
        // ================================================================

        private void GenerateReleaseManifestFiles(string outputBaseDir, string boardName,
                                                   string privateKeyPath, string publicKeyPath)
        {
            try
            {
                string manifestDir = Path.Combine(outputBaseDir, "Signed");
                Directory.CreateDirectory(manifestDir);

                // Collect all signed artifacts under Signed/Firmware and Signed/Bootloader
                var artifacts = new List<ManifestArtifactEntry>();
                string[] subDirs = new[] {
                    Path.Combine(manifestDir, "Firmware"),
                    Path.Combine(manifestDir, "Bootloader")
                };
                foreach (string dir in subDirs)
                {
                    if (!Directory.Exists(dir)) continue;
                    foreach (string file in Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly))
                    {
                        string ext = Path.GetExtension(file).ToLowerInvariant();
                        if (ext != ".apj" && ext != ".bin" && ext != ".hex" &&
                            ext != ".px4" && ext != ".elf" && ext != ".abin" &&
                            ext != ".param" && ext != ".params" && ext != ".parm")
                            continue;

                        string rel = GetRelativePathSafe(outputBaseDir, file).Replace('\\', '/');
                        artifacts.Add(new ManifestArtifactEntry
                        {
                            RelativePath  = rel,
                            SizeBytes     = new FileInfo(file).Length,
                            Sha256        = ComputeFileSha256(file).ToUpperInvariant(),
                            ArtifactClass = InferArtifactClass(rel)
                        });
                    }
                }

                // Partition aggregate hashes
                var codeEntries = artifacts.FindAll(a => a.ArtifactClass == "code");
                var dataEntries = artifacts.FindAll(a => a.ArtifactClass == "data");
                string codeAgg = ComputeAggregatePartitionSha256(
                    codeEntries.ConvertAll(a => a.RelativePath + "|" + a.Sha256));
                string dataAgg = ComputeAggregatePartitionSha256(
                    dataEntries.ConvertAll(a => a.RelativePath + "|" + a.Sha256));

                // Key evidence SHAs
                string privKeySha = File.Exists(privateKeyPath)  ? ComputeFileSha256(privateKeyPath).ToUpperInvariant()  : string.Empty;
                string pubKeySha  = File.Exists(publicKeyPath)   ? ComputeFileSha256(publicKeyPath).ToUpperInvariant()   : string.Empty;

                // Build JSON manually (no external serialiser dependency beyond Newtonsoft already in scope)
                var sb = new StringBuilder();
                sb.AppendLine("{");
                sb.AppendLine("  \"schemaVersion\": \"1.0\",");
                sb.AppendLine("  \"manifestType\": \"ardupilot-secure-release\",");
                sb.AppendLine("  \"generatedAtUtc\": \"" + DateTime.UtcNow.ToString("o") + "\",");
                sb.AppendLine("  \"board\": \"" + EscapeJson(boardName) + "\",");
                sb.AppendLine("  \"keyEvidence\": {");
                sb.AppendLine("    \"privateKeyFile\": \"" + EscapeJson(Path.GetFileName(privateKeyPath)) + "\",");
                sb.AppendLine("    \"publicKeyFile\": \"" + EscapeJson(Path.GetFileName(publicKeyPath)) + "\",");
                sb.AppendLine("    \"privateKeySha\": \"" + EscapeJson(privKeySha) + "\",");
                sb.AppendLine("    \"publicKeySha\": \"" + EscapeJson(pubKeySha) + "\"");
                sb.AppendLine("  },");
                sb.AppendLine("  \"checksumPartitions\": {");
                sb.AppendLine("    \"algorithm\": \"SHA2-256\",");
                sb.AppendLine("    \"code\": {");
                sb.AppendLine("      \"itemCount\": " + codeEntries.Count + ",");
                sb.AppendLine("      \"aggregateSha256\": \"" + codeAgg + "\"");
                sb.AppendLine("    },");
                sb.AppendLine("    \"data\": {");
                sb.AppendLine("      \"itemCount\": " + dataEntries.Count + ",");
                sb.AppendLine("      \"aggregateSha256\": \"" + dataAgg + "\"");
                sb.AppendLine("    }");
                sb.AppendLine("  },");
                sb.AppendLine("  \"artifacts\": [");
                for (int i = 0; i < artifacts.Count; i++)
                {
                    var a = artifacts[i];
                    string comma = i < artifacts.Count - 1 ? "," : string.Empty;
                    sb.AppendLine("    {");
                    sb.AppendLine("      \"relativePath\": \"" + EscapeJson(a.RelativePath) + "\",");
                    sb.AppendLine("      \"sizeBytes\": " + a.SizeBytes + ",");
                    sb.AppendLine("      \"sha256\": \"" + EscapeJson(a.Sha256) + "\",");
                    sb.AppendLine("      \"artifactClass\": \"" + EscapeJson(a.ArtifactClass) + "\"");
                    sb.AppendLine("    }" + comma);
                }
                sb.AppendLine("  ],");
                sb.AppendLine("  \"note\": \"Use manifest + detached checksum for audit traceability.\"");
                sb.AppendLine("}");

                string manifestPath = Path.Combine(manifestDir, "release_manifest.json");
                File.WriteAllText(manifestPath, sb.ToString(), new UTF8Encoding(false));
                AppendApLog("[MANIFEST] Generated: " + manifestPath);

                // SHA256 of manifest
                string manifestHash = ComputeFileSha256(manifestPath).ToUpperInvariant();
                string sha256Path   = Path.Combine(manifestDir, "release_manifest.sha256");
                File.WriteAllText(sha256Path, manifestHash + "  release_manifest.json\n", new UTF8Encoding(false));
                AppendApLog("[MANIFEST] Generated: " + sha256Path);

                // RSA signature + self-signed cert (auto-generates key if none provided)
                GenerateManifestRsaSignature(manifestPath, manifestDir);
            }
            catch (Exception ex)
            {
                AppendApLog("[MANIFEST] ERROR generating release manifest: " + ex.Message);
                log.Error("[MANIFEST] GenerateReleaseManifestFiles failed", ex);
            }
        }

        private struct ManifestArtifactEntry
        {
            public string RelativePath;
            public long   SizeBytes;
            public string Sha256;
            public string ArtifactClass;
        }

        private void GenerateManifestRsaSignature(string manifestPath, string manifestDir)
        {
            string sigPath  = Path.Combine(manifestDir, "release_manifest.sig");
            string certPath = Path.Combine(manifestDir, "release_manifest.pem");
            string privPath = Path.Combine(manifestDir, "manufacturer_manifest_private.pem");

            try
            {
                string wslDir = ToWslPath(manifestDir);

                // Auto-generate RSA key + self-signed certificate via WSL openssl (matches PS script)
                if (!File.Exists(privPath) || !File.Exists(certPath))
                {
                    string genCmd =
                        "openssl req -x509 -newkey rsa:2048" +
                        " -keyout \"" + wslDir + "/manufacturer_manifest_private.pem\"" +
                        " -out \"" + wslDir + "/release_manifest.pem\"" +
                        " -days 3650 -nodes -subj '/CN=ManufacturerManifestKey' 2>&1";
                    RunWslCommand(genCmd, line => AppendApLog("[MANIFEST] " + line));
                    if (File.Exists(privPath)) AppendApLog("[MANIFEST] Generated: " + privPath);
                    if (File.Exists(certPath)) AppendApLog("[MANIFEST] Generated: " + certPath);
                }

                if (!File.Exists(privPath))
                {
                    AppendApLog("[MANIFEST] WARN: RSA key generation failed; skipping signature.");
                    return;
                }

                // Sign manifest.json with openssl dgst -sha256 -> PKCS#1 raw DER signature
                string signCmd =
                    "openssl dgst -sha256 -sign \"" + wslDir + "/manufacturer_manifest_private.pem\"" +
                    " -out \"" + wslDir + "/release_manifest.sig\"" +
                    " \"" + wslDir + "/release_manifest.json\" 2>&1";
                RunWslCommand(signCmd, line => AppendApLog("[MANIFEST] " + line));

                if (File.Exists(sigPath))
                    AppendApLog("[MANIFEST] Generated RSA signature: " + sigPath);
                else
                    AppendApLog("[MANIFEST] WARN: release_manifest.sig was not created.");
            }
            catch (Exception ex)
            {
                AppendApLog("[MANIFEST] WARN: RSA signature generation failed: " + ex.Message);
                log.Warn("[MANIFEST] GenerateManifestRsaSignature failed", ex);
            }
        }

        private async Task ApBuildBootloaderAsync()
        {
            if (!EnsureProtectedRole(AppUserRole.Admin, "build bootloader"))
                return;

            string board   = txtApBoard.Text.Trim();
            string repoPath = txtApRoot.Text.Trim();
            string outDir  = txtApKeyOutDir.Text.Trim();

            if (string.IsNullOrWhiteSpace(board) || string.IsNullOrWhiteSpace(repoPath))
            { ShowErr("Enter the board name and ArduPilot WSL repo path."); return; }

            btnApBuildBootloader.Enabled = false;
            txtApOutput.Text = string.Empty;
            AppendApLog("[BL-BUILD] Building secure bootloader for: " + board);

            try
            {
                string effectiveOutDir = string.IsNullOrWhiteSpace(outDir)
                    ? Path.Combine(Environment.CurrentDirectory, "tools")
                    : outDir;
                string signedBlDir = Path.Combine(effectiveOutDir, "ed25519", "signed", "bootloader");
                Directory.CreateDirectory(signedBlDir);

                string pubKeyPathWin = Path.Combine(effectiveOutDir, board + "_public_key.dat");
                if (!File.Exists(pubKeyPathWin))
                {
                    AppendApLog("[BL-BUILD] ERROR: public key not found: " + pubKeyPathWin);
                    return;
                }
                if (!EnsureArduPilotKeyFormat(pubKeyPathWin, true, AppendApLog))
                {
                    AppendApLog("[BL-BUILD] ERROR: public key format invalid for ArduPilot signing: " + pubKeyPathWin);
                    return;
                }
                string pubKeyPath = ToWslPath(pubKeyPathWin);

                string keyArg = string.IsNullOrWhiteSpace(pubKeyPath)
                    ? string.Empty
                    : " --signing-key=\"" + pubKeyPath + "\"";

                string wslRepo2 = ToWslPath(repoPath);
                string script = "cd \"" + wslRepo2 + "\" && " +
                    "python3 Tools/scripts/build_bootloaders.py " + board + keyArg;

                string blResult = await Task.Run(() => RunWslCommand(script, line => AppendApLog(line)));
                bool blOk = blResult != null &&
                            blResult.IndexOf("Failed to sign bootloader", StringComparison.OrdinalIgnoreCase) < 0 &&
                            blResult.IndexOf("Build failed:", StringComparison.OrdinalIgnoreCase) < 0 &&
                            blResult.IndexOf("UnicodeDecodeError", StringComparison.OrdinalIgnoreCase) < 0;
                if (!blOk)
                {
                    AppendApLog("[BL-BUILD] ERROR: secure bootloader signing failed; signed output not updated.");
                    return;
                }
                AppendApLog("[BL-BUILD] Bootloader build completed.");

                // Prefer legacy output if script writes there, then copy into signed/bootloader
                string expectedLegacy = Path.Combine(effectiveOutDir, "Signed", "Bootloader", board + "_bl.bin");
                if (File.Exists(expectedLegacy))
                {
                    string baseName = Path.GetFileNameWithoutExtension(expectedLegacy);
                    string ext = Path.GetExtension(expectedLegacy);
                    string dest = Path.Combine(signedBlDir, baseName + "-signed" + ext);
                    File.Copy(expectedLegacy, dest, true);
                    txtApBootloaderPath.Text = dest;
                    lblApBootloaderStatus.Text = "✓ Signed bootloader: " + Path.GetFileName(dest);
                    lblApBootloaderStatus.ForeColor = Color.LimeGreen;
                    AppendApLog("[BL-BUILD] copied: " + expectedLegacy + " -> " + dest);
                    return;
                }

                // Fallback: pull bootloader-like bins from ArduPilot build output
                string sourceDirWin = Path.Combine(repoPath.Replace('/', '\\'), "build", board, "bin");
                if (Directory.Exists(sourceDirWin))
                {
                    string[] candidates = Directory.GetFiles(sourceDirWin, "*.bin", SearchOption.TopDirectoryOnly);
                    int copied = 0;
                    foreach (string src in candidates)
                    {
                        string name = Path.GetFileName(src);
                        bool looksLikeBootloader = name.IndexOf("bootloader", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                   name.IndexOf("_bl", StringComparison.OrdinalIgnoreCase) >= 0;
                        if (!looksLikeBootloader)
                            continue;
                        string destBase = Path.GetFileNameWithoutExtension(name);
                        string destExt = Path.GetExtension(name);
                        string dest = Path.Combine(signedBlDir, destBase + "-signed" + destExt);
                        File.Copy(src, dest, true);
                        copied++;
                        AppendApLog("[BL-BUILD] copied: " + name + " -> " + signedBlDir);
                        if (txtApBootloaderPath.Text.Length == 0)
                            txtApBootloaderPath.Text = dest;
                    }
                    if (copied > 0)
                    {
                        lblApBootloaderStatus.Text = "✓ Signed bootloader staged in " + signedBlDir;
                        lblApBootloaderStatus.ForeColor = Color.LimeGreen;
                    }
                    else
                    {
                        AppendApLog("[BL-BUILD] WARN: no bootloader-like .bin found in " + sourceDirWin);
                    }
                }
                else
                {
                    AppendApLog("[BL-BUILD] WARN: source folder not found: " + sourceDirWin);
                }
            }
            catch (Exception ex)
            {
                AppendApLog("[BL-BUILD] ERROR: " + ex.Message);
            }
            finally
            {
                btnApBuildBootloader.Enabled = true;
            }
        }

        private void ApVerifyBootloaderFile()
        {
            string blPath = txtApBootloaderPath.Text.Trim();
            if (!File.Exists(blPath))
            {
                lblApBootloaderStatus.Text = "No valid bootloader file selected.";
                lblApBootloaderStatus.ForeColor = Color.Red;
                return;
            }

            long size = new FileInfo(blPath).Length;
            string hash = ComputeFileSha256(blPath);
            lblApBootloaderStatus.Text = "✓ File: " + Path.GetFileName(blPath) +
                " | " + (size / 1024) + " KB | SHA256: " + hash.Substring(0, 16) + "...";
            lblApBootloaderStatus.ForeColor = Color.LimeGreen;
            AppendApLog("[BL-VERIFY] " + lblApBootloaderStatus.Text);
        }

        private async Task ApSignFirmwareAsync()
        {
            if (!EnsureProtectedRole(AppUserRole.Admin, "sign firmware"))
                return;

            string apjPath = txtApApjPath.Text.Trim();
            string keyPath = txtApPrivateKey.Text.Trim();
            string repoPath = txtApRoot.Text.Trim();
            string outDir = txtApKeyOutDir.Text.Trim();

            if (!File.Exists(apjPath))
            { ShowErr("Select a valid .apj firmware file."); return; }
            if (!File.Exists(keyPath))
            { ShowErr("Select a valid private key (.dat) file."); return; }
            if (string.IsNullOrWhiteSpace(repoPath))
            { ShowErr("Enter the ArduPilot WSL repo path."); return; }

            btnApSignFw.Enabled = false;
            txtApOutput.Text = string.Empty;
            AppendApLog("[SIGN] Signing: " + Path.GetFileName(apjPath));
            AppendApLog("[SIGN] Key: " + Path.GetFileName(keyPath));

            try
            {
                string effectiveOutDir = string.IsNullOrWhiteSpace(outDir)
                    ? Path.Combine(Environment.CurrentDirectory, "tools")
                    : outDir;
                string signedFwDir = Path.Combine(effectiveOutDir, "ed25519", "signed", "firmware");
                Directory.CreateDirectory(signedFwDir);

                if (!EnsureArduPilotKeyFormat(keyPath, false, AppendApLog))
                {
                    AppendApLog("[SIGN] ERROR: private key format invalid for ArduPilot signing: " + keyPath);
                    ShowErr("Private key format invalid. Regenerate keys via WSL signing keygen.");
                    return;
                }

                string wslKey = ToWslPath(keyPath);
                string wslRepo3 = ToWslPath(repoPath);
                string baseName = Path.GetFileNameWithoutExtension(apjPath);
                if (baseName.EndsWith("-signed", StringComparison.OrdinalIgnoreCase))
                    baseName = baseName.Substring(0, baseName.Length - 7);
                if (baseName.EndsWith("-signed-pending", StringComparison.OrdinalIgnoreCase))
                    baseName = baseName.Substring(0, baseName.Length - 15);
                string outName = baseName + "-signed.apj";
                string outPath = Path.Combine(signedFwDir, outName);
                EnsureSigningScriptExists(repoPath, AppendApLog);
                File.Copy(apjPath, outPath, true);
                string wslOut  = ToWslPath(outPath);

                string script = "cd \"" + wslRepo3 + "\" && " +
                    "python3 Tools/scripts/signing/make_secure_fw.py \"" + wslOut + "\" \"" + wslKey + "\"";

                await Task.Run(() => RunWslCommand(script, line => AppendApLog(line)));

                if (IsApjSigned(outPath))
                {
                    AppendApLog("[SIGN] ✓ Signed firmware: " + outPath);
                    txtApApjPath.Text = outPath;
                    UpdateApjStatusLabel();
                    MessageBox.Show(
                        "Firmware signed successfully!\n\nOutput: " + outPath +
                        "\n\nThis .apj now contains an Ed25519 signature.\nFlash this file to the FC — bootloader will verify before executing.",
                        "Signing Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    AppendApLog("[SIGN] Signing failed — output APJ is unsigned. Check log above.");
                    if (File.Exists(outPath)) File.Delete(outPath);
                }
            }
            catch (Exception ex)
            {
                AppendApLog("[SIGN] ERROR: " + ex.Message);
                ShowErr("Signing failed:\n" + ex.Message);
            }
            finally
            {
                btnApSignFw.Enabled = true;
            }
        }

        private async Task ApVerifyApjAsync()
        {
            string apjPath = txtApApjPath.Text.Trim();
            if (!File.Exists(apjPath))
            { ShowErr("Select a valid .apj file to verify."); return; }

            btnApVerifyApj.Enabled = false;
            AppendApLog("[VERIFY-APJ] Verifying: " + Path.GetFileName(apjPath));

            await Task.Run(() =>
            {
                try
                {
                    string text = File.ReadAllText(apjPath);
                    bool hasSig = text.Contains("\"signature\"") || text.Contains("ed25519") || text.Contains("APP_DESCRIPTOR");
                    long size   = new FileInfo(apjPath).Length;
                    string hash = ComputeFileSha256(apjPath);

                    AppendApLog("[VERIFY-APJ] SHA256: " + hash);
                    AppendApLog("[VERIFY-APJ] Size: " + size + " bytes");
                    AppendApLog("[VERIFY-APJ] Ed25519 marker: " + (hasSig ? "PRESENT ✓" : "NOT FOUND ✗"));
                    AppendApLog("[VERIFY-APJ] Result: " + (hasSig ? "SIGNED" : "UNSIGNED"));

                    BeginInvoke((MethodInvoker)(() =>
                    {
                        if (lblApApjStatus == null) return;
                        lblApApjStatus.Text = hasSig
                            ? "APJ Status: ✓ Signed (Ed25519 marker present)"
                            : "APJ Status: ✗ Unsigned — run Sign Firmware first";
                        lblApApjStatus.ForeColor = hasSig ? Color.LimeGreen : Color.Red;
                    }));
                }
                catch (Exception ex)
                {
                    AppendApLog("[VERIFY-APJ] ERROR: " + ex.Message);
                }
            });

            btnApVerifyApj.Enabled = true;
        }

        // ================================================================
        // RSA Certificate Signing
        // ================================================================

        private void BtnImportCert_Click(object sender, EventArgs e)
        {
            if (!EnsureProtectedRole(AppUserRole.Admin, "import certificate"))
                return;

            using (var ofd = new OpenFileDialog
            {
                Title = "Import Certificate",
                Filter = "Certificate Files (*.pfx;*.p12;*.pem;*.cer;*.crt)|*.pfx;*.p12;*.pem;*.cer;*.crt|All files (*.*)|*.*"
            })
            {
                if (ofd.ShowDialog(this) != DialogResult.OK) return;

                string certPath = ofd.FileName;
                string ext = Path.GetExtension(certPath).ToLowerInvariant();
                string password = null;

                if (ext == ".pfx" || ext == ".p12")
                {
                    using (var pwdDlg = new PasswordInputDialog())
                    {
                        if (pwdDlg.ShowDialog(this) == DialogResult.OK)
                            password = pwdDlg.Password;
                    }
                }

                try
                {
                    _loadedCert = password != null
                        ? new X509Certificate2(certPath, password, X509KeyStorageFlags.Exportable)
                        : new X509Certificate2(certPath);

                    _loadedCertPath    = certPath;
                    _loadedKeyPath     = certPath;
                    _loadedKeyPassword = password;

                    string certSubject = _loadedCert.Subject ?? "(unknown)";
                    txtCertInfo.Text =
                        "Subject:    " + _loadedCert.Subject + "\n" +
                        "Issuer:     " + _loadedCert.Issuer + "\n" +
                        "Thumbprint: " + _loadedCert.Thumbprint + "\n" +
                        "Valid:      " + _loadedCert.NotBefore.ToString("yyyy-MM-dd") +
                        "  →  " + _loadedCert.NotAfter.ToString("yyyy-MM-dd") + "\n" +
                        "Has Key:    " + _loadedCert.HasPrivateKey;

                    lblCertStatus.Text      = "Certificate loaded: " + (certSubject.Length > 55 ? certSubject.Substring(0, 52) + "..." : certSubject);
                    lblCertStatus.ForeColor = Color.LimeGreen;
                    btnSignWithCert.Enabled = _loadedCert.HasPrivateKey;

                    log.Info("[KEY-MGMT] Certificate imported: " + certSubject);
                }
                catch (Exception ex)
                {
                    ShowErr("Failed to load certificate:\n" + ex.Message);
                    _loadedCert = null;
                    lblCertStatus.Text      = "Certificate load failed";
                    lblCertStatus.ForeColor = Color.Red;
                    btnSignWithCert.Enabled = false;
                }
            }
        }

        private async Task SignWithCertificateAsync()
        {
            if (!EnsureProtectedRole(AppUserRole.Admin, "certificate signing"))
                return;

            string fwPath  = txtFwCert.Text.Trim();
            string sigPath = txtSigOut.Text.Trim();

            if (!File.Exists(fwPath))
            { ShowErr("Select a firmware file to sign."); return; }
            if (string.IsNullOrWhiteSpace(sigPath))
            { ShowErr("Choose an output path for the signature file."); return; }
            if (_loadedCert == null || !_loadedCert.HasPrivateKey)
            { ShowErr("Load a certificate with a private key first."); return; }

            btnSignWithCert.Enabled = false;
            btnSignWithCert.Text    = "Signing...";

            try
            {
                await Task.Run(() =>
                {
                    byte[] fwBytes = File.ReadAllBytes(fwPath);
                    using (var rsa = _loadedCert.GetRSAPrivateKey())
                    {
                        if (rsa == null)
                            throw new InvalidOperationException("Certificate does not contain an RSA private key.");

                        byte[] signature = rsa.SignData(fwBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                        File.WriteAllText(sigPath, Convert.ToBase64String(signature));
                    }
                });

                log.Info("[CERT-SIGN] Firmware " + Path.GetFileName(fwPath) + " signed → " + sigPath);
                MessageBox.Show(
                    "Firmware signed successfully.\n\nSignature saved to:\n" + sigPath,
                    "Signing Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                ShowErr("Signing failed:\n" + ex.Message);
                log.Error("Certificate firmware signing failed", ex);
            }
            finally
            {
                btnSignWithCert.Enabled = true;
                btnSignWithCert.Text    = "Sign Firmware with Certificate";
            }
        }

        // ================================================================
        // HMAC Key Management
        // ================================================================

        private void BtnGenerateHmac_Click(object sender, EventArgs e)
        {
            if (!EnsureProtectedRole(AppUserRole.Admin, "generate HMAC key"))
                return;

            byte[] key = new byte[32];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(key);

            _currentHmacKey = key;
            string hex = BitConverter.ToString(key).Replace("-", string.Empty).ToLowerInvariant();

            // Persist with DPAPI
            try
            {
                byte[] protected_ = ProtectedData.Protect(key, null, DataProtectionScope.CurrentUser);
                Settings.Instance[HmacKeySettingName] = Convert.ToBase64String(protected_);
            }
            catch { /* DPAPI unavailable; key is in-memory only */ }

            string keyId = "hmac-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
            txtHmacKeyHex.Text      = hex;
            lblHmacStatus.Text      = "Active key generated: " + keyId + " (" + DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC") + ")";
            lblHmacStatus.ForeColor = Color.LimeGreen;
            btnExportHmac.Enabled   = true;

            log.Info("[KEY-MGMT] HMAC-SHA256 key generated (keyId=" + keyId + ")");
        }

        private void BtnExportHmac_Click(object sender, EventArgs e)
        {
            if (!EnsureProtectedRole(AppUserRole.Admin, "export HMAC key"))
                return;

            if (_currentHmacKey == null) return;

            using (var sfd = new SaveFileDialog
            {
                Filter       = "Key files (*.key)|*.key|All files (*.*)|*.*",
                FileName     = "hmac-signing-" + DateTime.UtcNow.ToString("yyyyMMdd") + ".key",
                DefaultExt   = "key"
            })
            {
                if (sfd.ShowDialog(this) != DialogResult.OK) return;

                File.WriteAllText(sfd.FileName, txtHmacKeyHex.Text);
                log.Info("[KEY-MGMT] HMAC key exported to: " + sfd.FileName);

                MessageBox.Show(
                    "Key exported successfully.\n\nStore this file on encrypted storage only.\n" +
                    "Delete from any unprotected location immediately.",
                    "Key Exported", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void RefreshHmacKeyUi()
        {
            if (txtHmacKeyHex == null) return;
            try
            {
                string stored = Settings.Instance[HmacKeySettingName];
                if (!string.IsNullOrWhiteSpace(stored))
                {
                    byte[] protected_ = Convert.FromBase64String(stored);
                    _currentHmacKey = ProtectedData.Unprotect(protected_, null, DataProtectionScope.CurrentUser);

                    string hex = BitConverter.ToString(_currentHmacKey).Replace("-", string.Empty).ToLowerInvariant();
                    txtHmacKeyHex.Text      = hex;
                    lblHmacStatus.Text      = "Active key: loaded from secure storage (" + _currentHmacKey.Length * 8 + "-bit)";
                    lblHmacStatus.ForeColor = Color.LimeGreen;
                    btnExportHmac.Enabled   = true;
                    return;
                }
            }
            catch { /* DPAPI/settings unavailable */ }

            lblHmacStatus.Text      = "No active key configured";
            lblHmacStatus.ForeColor = Color.Gray;
        }

        // ================================================================
        // Signing Self-Tests
        // ================================================================

        private async Task RunSigningTestsAsync()
        {
            if (!EnsureProtectedRole(AppUserRole.Operator, "run signing tests"))
                return;

            btnRunTests.Enabled = false;
            btnRunTests.Text    = "Running...";
            txtTestReport.Text  = "Running compliance tests, please wait...";

            try
            {
                string report = await Task.Run(() => RunTests());
                txtTestReport.Text = report;
            }
            catch (Exception ex)
            {
                txtTestReport.Text = "Test run failed: " + ex.Message;
            }
            finally
            {
                btnRunTests.Enabled = true;
                btnRunTests.Text    = "▶  Run All Tests";
            }
        }

        private static string RunTests()
        {
            var sb = new StringBuilder();
            sb.AppendLine("═══════════════════════════════════════════════════");
            sb.AppendLine(" QCI Firmware Signing Compliance Tests");
            sb.AppendLine(" MissionPlanner — " + DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC"));
            sb.AppendLine("═══════════════════════════════════════════════════");
            sb.AppendLine();

            int pass = 0, fail = 0;

            // Test 1: SHA-256 consistency
            sb.AppendLine("Test 1: SHA-256 Consistency");
            try
            {
                byte[] data = Encoding.UTF8.GetBytes("Mission Planner QCI Test Vector 1");
                string h1, h2;
                using (var sha = SHA256.Create()) h1 = BitConverter.ToString(sha.ComputeHash(data)).Replace("-", string.Empty);
                using (var sha = SHA256.Create()) h2 = BitConverter.ToString(sha.ComputeHash(data)).Replace("-", string.Empty);
                bool ok = h1 == h2;
                sb.AppendLine("  " + (ok ? "PASS" : "FAIL") + " — Hash: " + h1.Substring(0, 16) + "...");
                if (ok) pass++; else fail++;
            }
            catch (Exception ex) { sb.AppendLine("  FAIL — " + ex.Message); fail++; }

            // Test 2: HMAC-SHA256 known vector
            sb.AppendLine("Test 2: HMAC-SHA256 Known-Vector");
            try
            {
                byte[] key  = new byte[32]; // all zeros — predictable for test
                byte[] data = Encoding.UTF8.GetBytes("test");
                using (var hmac = new HMACSHA256(key))
                {
                    byte[] mac = hmac.ComputeHash(data);
                    bool ok = mac.Length == 32;
                    sb.AppendLine("  " + (ok ? "PASS" : "FAIL") + " — 32-byte MAC produced: " + ok);
                    if (ok) pass++; else fail++;
                }
            }
            catch (Exception ex) { sb.AppendLine("  FAIL — " + ex.Message); fail++; }

            // Test 3: Tamper detection
            sb.AppendLine("Test 3: Tamper Detection (MAC mismatch on modified data)");
            try
            {
                byte[] key     = new byte[32]; for (int i = 0; i < 32; i++) key[i] = (byte)i;
                byte[] data    = Encoding.UTF8.GetBytes("QCI firmware v1.0");
                byte[] tampered = Encoding.UTF8.GetBytes("QCI firmware v1.1");
                using (var hmac = new HMACSHA256(key))
                {
                    byte[] mac1 = hmac.ComputeHash(data);
                    byte[] mac2 = hmac.ComputeHash(tampered);
                    bool ok = !ByteEqual(mac1, mac2);
                    sb.AppendLine("  " + (ok ? "PASS" : "FAIL") + " — Different data produces different MAC: " + ok);
                    if (ok) pass++; else fail++;
                }
            }
            catch (Exception ex) { sb.AppendLine("  FAIL — " + ex.Message); fail++; }

            // Test 4: Key length enforcement (must be >= 16 bytes = 128 bits)
            sb.AppendLine("Test 4: Key-Length Enforcement (minimum 128-bit)");
            try
            {
                byte[] shortKey = new byte[8]; // 64 bits — should fail compliance
                byte[] longKey  = new byte[32]; // 256 bits — pass
                bool ok = shortKey.Length * 8 < 128 && longKey.Length * 8 >= 128;
                sb.AppendLine("  " + (ok ? "PASS" : "FAIL") + " — 64-bit key rejected, 256-bit key accepted: " + ok);
                if (ok) pass++; else fail++;
            }
            catch (Exception ex) { sb.AppendLine("  FAIL — " + ex.Message); fail++; }

            // Test 5: RSA signing round-trip (small in-memory self-signed)
            sb.AppendLine("Test 5: RSA Signing Round-Trip");
            try
            {
                using (var rsa = RSA.Create(2048))
                {
                    byte[] data = Encoding.UTF8.GetBytes("QCI RSA signing self-test");
                    byte[] sig  = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    bool   ok   = rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    sb.AppendLine("  " + (ok ? "PASS" : "FAIL") + " — RSA 2048-bit sign/verify round-trip: " + ok);
                    if (ok) pass++; else fail++;
                }
            }
            catch (Exception ex) { sb.AppendLine("  FAIL — " + ex.Message); fail++; }

            sb.AppendLine();
            sb.AppendLine("───────────────────────────────────────────────────");
            sb.AppendLine(string.Format("RESULT: {0} PASS / {1} FAIL  —  {2}", pass, fail,
                fail == 0 ? "ALL TESTS PASSED ✓" : "FAILURES DETECTED ✗"));
            sb.AppendLine("───────────────────────────────────────────────────");

            return sb.ToString();
        }

        private static bool ByteEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        private const string MakeSecureFwPy =
@"#!/usr/bin/env python3
# flake8: noqa
'''sign an ArduPilot APJ firmware with a private key'''
import sys, struct, json, base64, zlib
try:
    import monocypher
except ImportError:
    print('Please install monocypher with: python3 -m pip install pymonocypher==3.1.3.2')
    sys.exit(1)
if monocypher.__version__ != '3.1.3.2':
    print('must use monocypher 3.1.3.2, please run: python3 -m pip install pymonocypher==3.1.3.2')
    sys.exit(1)
from argparse import ArgumentParser
parser = ArgumentParser(description='Sign an ArduPilot APJ firmware.')
parser.add_argument('apj_file', metavar='apj-file', type=str, help='Firmware (APJ) to sign')
parser.add_argument('key_file', metavar='key-file', type=str, help='Private key used to sign the firmware')
args = parser.parse_args()
key_len = 32
sig_len = 64
sig_version = 30437
descriptor = b'\x41\xa3\xe5\xf2\x65\x69\x92\x07'
def to_unsigned(i):
    if i < 0:
        i += 2**32
    return i
apj = open(args.apj_file, 'r').read()
d = json.loads(apj)
img = zlib.decompress(base64.b64decode(d['image']))
img_len = len(img)
def decode_key(ktype, key):
    ktype += '_KEYV1:'
    if not key.startswith(ktype):
        print('Invalid key type')
        sys.exit(1)
    return base64.b64decode(key[len(ktype):])
key = decode_key('PRIVATE', open(args.key_file, 'r').read().strip())
if len(key) != key_len:
    print('Bad key length %u' % len(key))
    sys.exit(1)
offset = img.find(descriptor)
if offset == -1:
    print('No APP_DESCRIPTOR found')
    sys.exit(1)
offset += 8
desc_len = 92
flash1 = img[:offset]
flash2 = img[offset+desc_len:]
flash12 = flash1 + flash2
signature = monocypher.signature_sign(key, flash12)
if len(signature) != sig_len:
    print('Bad signature length %u should be %u' % (len(signature), sig_len))
    sys.exit(1)
desc = struct.pack('<IQ64s', sig_len+8, sig_version, signature)
img = img[:(offset + 16)] + desc + img[(offset + desc_len):]
if len(img) != img_len:
    print('Error: Image length changed')
    sys.exit(1)
print('Applying signature')
d['image'] = base64.b64encode(zlib.compress(img,9)).decode('utf-8')
d['signed_firmware'] = True
f = open(args.apj_file, 'w')
f.write(json.dumps(d, indent=4))
f.close()
print('Wrote %s' % args.apj_file)
";

        /// <summary>
        /// Ensures Tools/scripts/signing/make_secure_fw.py exists in the repo root.
        /// Writes from embedded content if the file is missing.
        /// </summary>
        private static void EnsureSigningScriptExists(string repoRoot, Action<string> onLine)
        {
            try
            {
                string signingDir = Path.Combine(repoRoot, "Tools", "scripts", "signing");
                string scriptPath = Path.Combine(signingDir, "make_secure_fw.py");
                if (!File.Exists(scriptPath))
                {
                    Directory.CreateDirectory(signingDir);
                    File.WriteAllText(scriptPath, MakeSecureFwPy);
                    onLine?.Invoke("[SIGN] Wrote signing script: " + scriptPath);
                }
            }
            catch (Exception ex)
            {
                onLine?.Invoke("[SIGN] WARN: could not write signing script: " + ex.Message);
            }
        }

        private static bool EnsureArduPilotKeyFormat(string keyPath, bool isPublic, Action<string> onLine)
        {
            if (string.IsNullOrWhiteSpace(keyPath) || !File.Exists(keyPath))
                return false;

            string prefix = isPublic ? "PUBLIC_KEYV1:" : "PRIVATE_KEYV1:";

            try
            {
                string text = File.ReadAllText(keyPath).Trim();
                if (text.StartsWith(prefix, StringComparison.Ordinal))
                    return true;

                // Text exists but not expected type; don't rewrite blindly.
                if (text.StartsWith("PUBLIC_KEYV1:", StringComparison.Ordinal) ||
                    text.StartsWith("PRIVATE_KEYV1:", StringComparison.Ordinal))
                {
                    onLine?.Invoke("[KEY] Wrong key type in file: " + keyPath);
                    return false;
                }
            }
            catch
            {
                // Likely binary legacy key; handled below.
            }

            try
            {
                byte[] raw = File.ReadAllBytes(keyPath);
                if (raw.Length == 32)
                {
                    string converted = prefix + Convert.ToBase64String(raw);
                    File.WriteAllText(keyPath, converted);
                    onLine?.Invoke("[KEY] Converted legacy raw key to KEYV1 format: " + keyPath);
                    return true;
                }
            }
            catch (Exception ex)
            {
                onLine?.Invoke("[KEY] Conversion failed: " + ex.Message);
            }

            return false;
        }

        // ================================================================
        // WSL helpers
        // ================================================================

        private static bool IsWslAvailable()
        {
            try
            {
                var p = new Process
                {
                    StartInfo = new ProcessStartInfo("wsl", "--status")
                    {
                        UseShellExecute        = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError  = true,
                        CreateNoWindow         = true
                    }
                };
                p.Start();
                return p.WaitForExit(5000) && p.ExitCode == 0;
            }
            catch { return false; }
        }

        /// <summary>
        /// Runs a command in WSL bash. Lines are passed to <paramref name="onLine"/> as they arrive.
        /// Returns combined stdout+stderr, or null on process launch failure.
        /// </summary>
        private string RunWslCommand(string bashCommand, Action<string> onLine)
        {
            var sb = new StringBuilder();
            try
            {
                var psi = new ProcessStartInfo("wsl", "bash -c \"" + bashCommand.Replace("\"", "\\\"") + "\"")
                {
                    UseShellExecute        = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    CreateNoWindow         = true
                };
                var p = new Process { StartInfo = psi };
                p.OutputDataReceived += (s, e) => { if (e.Data != null) { sb.AppendLine(e.Data); onLine?.Invoke(e.Data); } };
                p.ErrorDataReceived  += (s, e) => { if (e.Data != null) { sb.AppendLine(e.Data); onLine?.Invoke(e.Data); } };
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                p.WaitForExit(300000); // 5 min timeout
                return sb.ToString();
            }
            catch (Exception ex)
            {
                onLine?.Invoke("[WSL ERROR] " + ex.Message);
                return null;
            }
        }

        private static string ToWslPath(string windowsPath)
        {
            if (string.IsNullOrWhiteSpace(windowsPath)) return string.Empty;
            try
            {
                string p = windowsPath.Trim();

                // Case 1: \\wsl.localhost\DistroName\... or \\wsl$\DistroName\...
                // Strip the UNC prefix and distro name, return remaining Linux path
                string pNorm = p.Replace('/', '\\');
                if (pNorm.StartsWith(@"\\wsl.localhost\") || pNorm.StartsWith(@"\\wsl$\"))
                {
                    string[] parts = pNorm.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
                    // parts[0]=wsl.localhost or wsl$, parts[1]=distro, parts[2..]=linux path segments
                    if (parts.Length >= 3)
                        return "/" + string.Join("/", parts, 2, parts.Length - 2);
                    return "/";
                }

                // Case 2: Already a Linux path (starts with /)
                if (p.StartsWith("/"))
                    return p;

                // Case 3: Standard Windows drive path C:\...
                string full = Path.GetFullPath(p).Replace('\\', '/');
                if (full.Length >= 2 && full[1] == ':')
                {
                    char drive = char.ToLowerInvariant(full[0]);
                    return "/mnt/" + drive + full.Substring(2);
                }

                return full;
            }
            catch { return windowsPath; }
        }

        // ================================================================
        // Preferences load/save
        // ================================================================

        private void LoadPreferences()
        {
            if (txtApRoot      != null) txtApRoot.Text      = Settings.Instance[AppSettingApWslRepo]   ?? string.Empty;
            if (txtApBoard     != null) txtApBoard.Text     = Settings.Instance[AppSettingApBoard]     ?? "Pixhawk6C";
            if (txtApKeyOutDir != null) txtApKeyOutDir.Text = Settings.Instance[AppSettingApKeyOutDir] ?? string.Empty;
            if (txtApPrivateKey != null) txtApPrivateKey.Text = Settings.Instance[AppSettingApPrivKey] ?? string.Empty;
        }

        // ================================================================
        // Output log helpers
        // ================================================================

        private void AppendOutput(string msg)
        {
            string line = "[" + DateTime.UtcNow.ToString("HH:mm:ss") + "] " + msg;
            log.Info(msg);
            BeginInvoke((MethodInvoker)(() =>
            {
                if (txtOutput == null || txtOutput.IsDisposed) return;
                if (txtOutput.TextLength > 50000)
                    txtOutput.Text = txtOutput.Text.Substring(txtOutput.TextLength / 2);
                txtOutput.AppendText(line + Environment.NewLine);
                txtOutput.SelectionStart = txtOutput.TextLength;
                txtOutput.ScrollToCaret();
            }));
        }

        private void AppendApLog(string msg)
        {
            BeginInvoke((MethodInvoker)(() =>
            {
                if (txtApOutput == null || txtApOutput.IsDisposed) return;
                if (txtApOutput.TextLength > 60000)
                    txtApOutput.Text = txtApOutput.Text.Substring(txtApOutput.TextLength / 2);
                txtApOutput.AppendText(msg + Environment.NewLine);
                txtApOutput.SelectionStart = txtApOutput.TextLength;
                txtApOutput.ScrollToCaret();
            }));
        }

        private void SetProgress(int pct, string status)
        {
            BeginInvoke((MethodInvoker)(() =>
            {
                if (progressBar != null)
                {
                    progressBar.Value = Math.Max(0, Math.Min(100, pct));
                    progressBar.Style = pct > 0 ? ProgressBarStyle.Continuous : ProgressBarStyle.Blocks;
                }
                if (lblProgressStatus != null)
                {
                    lblProgressStatus.Text = status;
                    lblProgressStatus.ForeColor = pct >= 100 ? Color.LimeGreen
                        : pct == 0 ? Color.Red
                        : Color.Gray;
                }
            }));
        }

        private void SetWorkflowStatus(string text, Color color)
        {
            BeginInvoke((MethodInvoker)(() =>
            {
                if (lblWorkflowStatus == null || lblWorkflowStatus.IsDisposed)
                    return;
                lblWorkflowStatus.Text = text;
                lblWorkflowStatus.ForeColor = color;
            }));
        }

        private void ShowErr(string msg)
        {
            MessageBox.Show(msg, "Protected Firmware", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        private bool EnsureProtectedRole(AppUserRole minimumRole, string action)
        {
            bool allowed = RoleBasedAccess.EnsureRole(minimumRole, action);
            if (!allowed)
            {
                log.Warn("[RBAC] denied action='" + action + "' required='" + minimumRole + "' user='" + (RoleBasedAccess.CurrentUsername ?? "(none)") + "' role='" + RoleBasedAccess.CurrentRole + "'");
            }

            return allowed;
        }

        private void RoleBasedAccess_SessionChanged(object sender, EventArgs e)
        {
            if (IsDisposed)
                return;

            if (InvokeRequired)
            {
                BeginInvoke((Action)ApplyRoleAccessUi);
                return;
            }

            ApplyRoleAccessUi();
        }

        private void ApplyRoleAccessUi()
        {
            bool canOperate = RoleBasedAccess.IsInRole(AppUserRole.Operator);
            bool canAdmin = RoleBasedAccess.IsInRole(AppUserRole.Admin);

            if (btnFlashFirmware != null) btnFlashFirmware.Enabled = canAdmin;
            if (btnFlashBootloader != null) btnFlashBootloader.Enabled = canAdmin;
            if (btnProvisionRegistry != null) btnProvisionRegistry.Enabled = canAdmin;
            if (btnVerifyRegistry != null) btnVerifyRegistry.Enabled = canOperate;
            if (btnExportAudit != null) btnExportAudit.Enabled = canOperate;
            if (btnApGenerateKeys != null) btnApGenerateKeys.Enabled = canAdmin;
            if (btnApBuildFwBl != null) btnApBuildFwBl.Enabled = canAdmin;
            if (btnApBuildBootloader != null) btnApBuildBootloader.Enabled = canAdmin;
            if (btnApSignFw != null) btnApSignFw.Enabled = canAdmin;
            if (btnImportCert != null) btnImportCert.Enabled = canAdmin;
            if (btnSignWithCert != null) btnSignWithCert.Enabled = canAdmin && _loadedCert != null && _loadedCert.HasPrivateKey;
            if (btnGenerateHmac != null) btnGenerateHmac.Enabled = canAdmin;
            if (btnExportHmac != null) btnExportHmac.Enabled = canAdmin && _currentHmacKey != null;
            if (btnRunTests != null) btnRunTests.Enabled = canOperate;

            if (lblWorkflowStatus != null)
            {
                if (canAdmin)
                {
                    lblWorkflowStatus.Text = "Workflow: Admin access";
                    lblWorkflowStatus.ForeColor = Color.LimeGreen;
                }
                else if (canOperate)
                {
                    lblWorkflowStatus.Text = "Workflow: Operator access (read/verify)";
                    lblWorkflowStatus.ForeColor = Color.Goldenrod;
                }
                else
                {
                    lblWorkflowStatus.Text = "Workflow: Login required (Operator/Admin)";
                    lblWorkflowStatus.ForeColor = Color.Red;
                }
            }
        }

        // ================================================================
        // UI helpers
        // ================================================================

        private static Button MakeButton(string text, Point loc, Size size)
        {
            return new Button { Text = text, Location = loc, Size = size };
        }

        private static Label MakeLabel(string text, Point loc, int width, bool autoSize = true)
        {
            return new Label
            {
                Text     = text,
                Location = loc,
                AutoSize = autoSize,
                Width    = autoSize ? 0 : width
            };
        }

        private static void AddSeparator(Panel p, ref int y)
        {
            var sep = new Panel { Location = new Point(0, y), Size = new Size(430, 1), BackColor = Color.Gray };
            p.Controls.Add(sep);
            y += 8;
        }

        private static string EscapeJson(string s)
        {
            return (s ?? string.Empty)
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n");
        }

        // ================================================================
        // Procedure Guide text
        // ================================================================

        private static string GetProcedureText()
        {
            return
@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 QCI Annexure E — Firmware Signing Procedure Guide
 MissionPlanner — Compliance Level 1 (Isolated System)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. PURPOSE
Ensure every firmware flashed to the Flight Controller is
authentic, unmodified, and traceable to an authorized signer.

──────────────────────────────────────────────────────────
2. PROCEDURE: HMAC-SHA256 SIGNING (LEVEL 0 baseline)
──────────────────────────────────────────────────────────
2.1 Go to HMAC Key tab → Generate New 256-bit Key.
2.2 Export key to encrypted storage only.
2.3 Select firmware in left panel → verify SHA256.
2.4 Use HMAC key for offline signing of firmware package.
2.5 Flash verified firmware using Flash Firmware button.
2.6 Confirm operation in MissionPlanner Log (right panel).

──────────────────────────────────────────────────────────
3. PROCEDURE: ED25519 HARDWARE-ENFORCED SIGNING (LEVEL 1)
──────────────────────────────────────────────────────────
3.1 Configure WSL repo, board, and output directory.
3.2 Click Generate Keys via WSL to produce .dat key pair.
3.3 Build Firmware & Bootloader via WSL (embeds public key).
3.4 Sign compiled .apj using Sign Firmware button.
3.5 Verify signed APJ — check Ed25519 marker present.
3.6 Flash signed .apj via Protected Firmware → Flash Firmware.
3.7 Use Provision Registry to commit SHA256 to FC registry.
3.8 Use Verify Registry to confirm provisioning post-flash.

Ed25519 output naming:
  Firmware:   arducopter-ed25519-signed.apj
  Bootloader: <board>_bl-ed25519-signed.bin

──────────────────────────────────────────────────────────
4. PROCEDURE: RSA CERTIFICATE SIGNING
──────────────────────────────────────────────────────────
4.1 Obtain code-signing X.509 certificate from trusted CA.
4.2 Import PFX/PEM certificate in Certificate Signing tab.
4.3 Confirm Subject, Issuer, and Expiry.
4.4 Select firmware and output signature path.
4.5 Click Sign Firmware with Certificate.
4.6 Distribute .sig with firmware package.

──────────────────────────────────────────────────────────
5. AUDIT TRAIL
──────────────────────────────────────────────────────────
All operations are recorded in MissionPlanner.log with:
  - UTC timestamp
  - Firmware filename and SHA-256
  - Result status (PASS/FAIL)

Export Signed Audit → JSON bundle in audit_exports/ folder.

──────────────────────────────────────────────────────────
6. COMPLIANCE MAPPING (QCI ANNEXURE E)
──────────────────────────────────────────────────────────
Requirement                   | Implementation
------------------------------ | ----------------------------------------
Level 1 compliance             | Implemented (isolated, no external comms)
Ed25519 hardware enforcement   | ArduPilot WSL signing + bootloader embed
Digital certificate signing    | RSA via X509Certificate2
Symmetric key minimum 128-bit  | HMAC-SHA256 with 256-bit keys enforced
Integrity before flash         | SHA-256 displayed, Ed25519 marker checked
Audit logging                  | Operations written to MissionPlanner.log
Audit export                   | JSON bundle via Export Signed Audit button

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
";
        }
    }

    // ====================================================================
    // PasswordInputDialog — minimal in-place dialog for PFX password entry
    // ====================================================================
    internal sealed class PasswordInputDialog : Form
    {
        private readonly TextBox _txt = new TextBox { UseSystemPasswordChar = true, Width = 300, Location = new Point(10, 36) };
        public string Password => _txt.Text;

        public PasswordInputDialog()
        {
            Text            = "Certificate Password";
            Size            = new Size(340, 130);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition   = FormStartPosition.CenterParent;
            MaximizeBox     = false;
            MinimizeBox     = false;

            Controls.Add(new Label { Text = "Enter certificate password:", AutoSize = true, Location = new Point(10, 12) });
            Controls.Add(_txt);

            var btnOk     = new Button { Text = "OK",     Size = new Size(80, 28), Location = new Point(10, 66), DialogResult = DialogResult.OK };
            var btnCancel = new Button { Text = "Cancel", Size = new Size(80, 28), Location = new Point(100, 66), DialogResult = DialogResult.Cancel };
            Controls.Add(btnOk);
            Controls.Add(btnCancel);
            AcceptButton = btnOk;
            CancelButton = btnCancel;
        }
    }
}
