using MissionPlanner.ArduPilot.Mavlink;
using MissionPlanner.Controls;
using MissionPlanner.Utilities;
using System;
using System.Drawing;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace MissionPlanner.GCSViews
{
    public class Security : MyUserControl, IActivate
    {
        private const string SettingSigningEnabled = "MavlinkSigningEnabled";
        private const string SettingRequireSignedIncoming = "MavlinkRequireSignedIncoming";
        private const string SettingSigningLinkId = "MavlinkSigningLinkId";
        private const string SettingSigningKey = "MavlinkSigningKey";

        private readonly CheckBox _chkSignTx = new CheckBox();
        private readonly CheckBox _chkRequireSignedRx = new CheckBox();
        private readonly NumericUpDown _numLinkId = new NumericUpDown();
        private readonly TextBox _txtKey = new TextBox();
        private readonly Button _btnToggleKey = new Button();
        private readonly Button _btnGenerateHex = new Button();
        private readonly Button _btnGenerateBase64 = new Button();
        private readonly Button _btnCopyKey = new Button();
        private readonly Button _btnApplyLocal = new Button();
        private readonly Button _btnPushKey = new Button();
        private readonly Button _btnApplyAndPush = new Button();
        private readonly Button _btnRemoveSecurity = new Button();
        private readonly Button _btnProbe = new Button();
        private readonly Button _btnRefresh = new Button();
        private readonly Label _lblTarget = new Label();
        private readonly Label _lblRuntime = new Label();
        private readonly Label _lblStatus = new Label();
        private readonly Timer _statusTimer = new Timer();

        private bool _busy;
        private bool _maskKey = true;

        public Security()
        {
            BuildUi();
            LoadUiFromSettings();
            UpdateStatusSnapshot();

            _statusTimer.Interval = 1000;
            _statusTimer.Tick += (s, e) => UpdateStatusSnapshot();
            _statusTimer.Start();
        }

        public void Activate()
        {
            LoadUiFromSettings();
            UpdateStatusSnapshot();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _statusTimer.Stop();
                _statusTimer.Dispose();
            }

            base.Dispose(disposing);
        }

        private void BuildUi()
        {
            Dock = DockStyle.Fill;

            var root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 4,
                Padding = new Padding(12)
            };
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 188));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 102));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Controls.Add(root);

            var title = new Label
            {
                AutoSize = true,
                Font = new Font(Font.FontFamily, 12f, FontStyle.Bold),
                Text = "MAVLink Security"
            };
            root.Controls.Add(title, 0, 0);

            var configPanel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8) };
            root.Controls.Add(configPanel, 0, 1);

            _chkSignTx.AutoSize = true;
            _chkSignTx.Location = new Point(10, 8);
            _chkSignTx.Text = "Sign outgoing packets (TX)";
            configPanel.Controls.Add(_chkSignTx);

            _chkRequireSignedRx.AutoSize = true;
            _chkRequireSignedRx.Location = new Point(10, 33);
            _chkRequireSignedRx.Text = "Require signed incoming packets (strict RX)";
            configPanel.Controls.Add(_chkRequireSignedRx);

            var lblLinkId = new Label
            {
                AutoSize = true,
                Location = new Point(10, 64),
                Text = "Link ID"
            };
            configPanel.Controls.Add(lblLinkId);

            _numLinkId.Location = new Point(64, 62);
            _numLinkId.Minimum = 0;
            _numLinkId.Maximum = 255;
            _numLinkId.Width = 64;
            configPanel.Controls.Add(_numLinkId);

            var lblKey = new Label
            {
                AutoSize = true,
                Location = new Point(152, 64),
                Text = "Signing Key (hex64 or base64)"
            };
            configPanel.Controls.Add(lblKey);

            _txtKey.Location = new Point(154, 82);
            _txtKey.Width = 680;
            _txtKey.UseSystemPasswordChar = true;
            configPanel.Controls.Add(_txtKey);

            _btnToggleKey.Location = new Point(842, 80);
            _btnToggleKey.Size = new Size(84, 24);
            _btnToggleKey.Text = "Show Key";
            _btnToggleKey.Click += (s, e) =>
            {
                _maskKey = !_maskKey;
                _txtKey.UseSystemPasswordChar = _maskKey;
                _btnToggleKey.Text = _maskKey ? "Show Key" : "Hide Key";
            };
            configPanel.Controls.Add(_btnToggleKey);

            _btnGenerateHex.Location = new Point(154, 114);
            _btnGenerateHex.Size = new Size(106, 26);
            _btnGenerateHex.Text = "Generate HEX";
            _btnGenerateHex.Click += (s, e) =>
            {
                _txtKey.Text = ToLowerHex(GenerateRandomKey32());
                SetStatus("Generated a new 32-byte key (hex).", false);
            };
            configPanel.Controls.Add(_btnGenerateHex);

            _btnGenerateBase64.Location = new Point(268, 114);
            _btnGenerateBase64.Size = new Size(124, 26);
            _btnGenerateBase64.Text = "Generate Base64";
            _btnGenerateBase64.Click += (s, e) =>
            {
                _txtKey.Text = Convert.ToBase64String(GenerateRandomKey32());
                SetStatus("Generated a new 32-byte key (base64).", false);
            };
            configPanel.Controls.Add(_btnGenerateBase64);

            _btnCopyKey.Location = new Point(400, 114);
            _btnCopyKey.Size = new Size(84, 26);
            _btnCopyKey.Text = "Copy Key";
            _btnCopyKey.Click += (s, e) =>
            {
                var key = (_txtKey.Text ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(key))
                {
                    SetStatus("No key to copy.", true);
                    return;
                }

                try
                {
                    Clipboard.SetText(key);
                    SetStatus("Signing key copied to clipboard.", false);
                }
                catch (Exception ex)
                {
                    SetStatus("Copy failed: " + ex.Message, true);
                }
            };
            configPanel.Controls.Add(_btnCopyKey);

            var actionsPanel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8) };
            root.Controls.Add(actionsPanel, 0, 2);

            _btnApplyLocal.Location = new Point(8, 8);
            _btnApplyLocal.Size = new Size(112, 30);
            _btnApplyLocal.Text = "Apply Local";
            _btnApplyLocal.Click += (s, e) => RunBusy(ApplyLocal);
            actionsPanel.Controls.Add(_btnApplyLocal);

            _btnPushKey.Location = new Point(128, 8);
            _btnPushKey.Size = new Size(120, 30);
            _btnPushKey.Text = "Push Key To FC";
            _btnPushKey.Click += (s, e) => RunBusy(PushKey);
            actionsPanel.Controls.Add(_btnPushKey);

            _btnApplyAndPush.Location = new Point(256, 8);
            _btnApplyAndPush.Size = new Size(118, 30);
            _btnApplyAndPush.Text = "Apply + Push";
            _btnApplyAndPush.Click += (s, e) => RunBusy(ApplyAndPush);
            actionsPanel.Controls.Add(_btnApplyAndPush);

            _btnRemoveSecurity.Location = new Point(382, 8);
            _btnRemoveSecurity.Size = new Size(126, 30);
            _btnRemoveSecurity.Text = "Remove Security";
            _btnRemoveSecurity.Click += (s, e) => RunBusy(RemoveSecurity);
            actionsPanel.Controls.Add(_btnRemoveSecurity);

            _btnProbe.Location = new Point(516, 8);
            _btnProbe.Size = new Size(80, 30);
            _btnProbe.Text = "Probe";
            _btnProbe.Click += (s, e) => RunBusy(Probe);
            actionsPanel.Controls.Add(_btnProbe);

            _btnRefresh.Location = new Point(604, 8);
            _btnRefresh.Size = new Size(80, 30);
            _btnRefresh.Text = "Refresh";
            _btnRefresh.Click += (s, e) =>
            {
                LoadUiFromCurrentMav();
                UpdateStatusSnapshot();
            };
            actionsPanel.Controls.Add(_btnRefresh);

            _lblTarget.AutoSize = false;
            _lblTarget.Location = new Point(8, 48);
            _lblTarget.Size = new Size(860, 16);
            _lblTarget.Text = "Target: waiting for telemetry";
            actionsPanel.Controls.Add(_lblTarget);

            _lblRuntime.AutoSize = false;
            _lblRuntime.Font = new Font(Font.FontFamily, 9f, FontStyle.Bold);
            _lblRuntime.Location = new Point(8, 68);
            _lblRuntime.Size = new Size(980, 18);
            _lblRuntime.Text = "Runtime: security stats unavailable";
            actionsPanel.Controls.Add(_lblRuntime);

            var notesAndCompliance = new Panel { Dock = DockStyle.Fill };

            var notes = new Label
            {
                Padding = new Padding(4),
                Text =
                    "Security Workflow:\r\n" +
                    "1) Set key + link ID and click Apply + Push.\r\n" +
                    "2) Use Probe to send a MAVLink ping with current signing settings.\r\n" +
                    "3) Use Refresh to sync from the current link/session state.\r\n" +
                    "4) Remove Security sends a zero-key SETUP_SIGNING disable request.\r\n" +
                    "Note: on this backend, strict RX uses signature validation on signed packets but cannot force all incoming packets to be signed.",
                Left = 0,
                Top = 0,
                Width = 980,
                Height = 80,
                AutoSize = false
            };
            notesAndCompliance.Controls.Add(notes);

            var complianceIndicator = new MissionPlanner.Controls.ComplianceIndicator
            {
                Left = 0,
                Top = 84,
                Width = 980,
                Height = 95,
                CurrentLevel = MissionPlanner.Controls.ComplianceLevel.Level1
            };
            notesAndCompliance.Controls.Add(complianceIndicator);

            root.Controls.Add(notesAndCompliance, 0, 3);

            _lblStatus.AutoSize = false;
            _lblStatus.Dock = DockStyle.Bottom;
            _lblStatus.Height = 22;
            _lblStatus.Text = "Ready";
            Controls.Add(_lblStatus);
        }

        private MAVState CurrentMav => MainV2.comPort?.MAV;

        private void RunBusy(Action action)
        {
            if (_busy)
                return;

            _busy = true;
            SetUiEnabled(false);
            try
            {
                action();
            }
            catch (Exception ex)
            {
                SetStatus("Operation failed: " + ex.Message, true);
            }
            finally
            {
                _busy = false;
                SetUiEnabled(true);
            }
        }

        private void SetUiEnabled(bool enabled)
        {
            var mav = CurrentMav;
            bool linkReady = mav != null && MainV2.comPort.BaseStream != null && MainV2.comPort.BaseStream.IsOpen;

            _chkSignTx.Enabled = enabled;
            _chkRequireSignedRx.Enabled = enabled;
            _numLinkId.Enabled = enabled;
            _txtKey.Enabled = enabled;
            _btnToggleKey.Enabled = enabled;
            _btnGenerateHex.Enabled = enabled;
            _btnGenerateBase64.Enabled = enabled;
            _btnCopyKey.Enabled = enabled;
            _btnApplyLocal.Enabled = enabled && mav != null;
            _btnPushKey.Enabled = enabled && linkReady && mav != null;
            _btnApplyAndPush.Enabled = enabled && linkReady && mav != null;
            _btnRemoveSecurity.Enabled = enabled && linkReady && mav != null;
            _btnProbe.Enabled = enabled && linkReady && mav != null;
            _btnRefresh.Enabled = enabled;
        }

        private void ApplyLocal()
        {
            var mav = CurrentMav;
            if (mav == null)
            {
                SetStatus("No MAVLink session available.", true);
                return;
            }

            bool signTx = _chkSignTx.Checked;
            bool strictRx = _chkRequireSignedRx.Checked;
            bool enableSigning = signTx || strictRx;

            if (strictRx && !signTx)
            {
                signTx = true;
                _chkSignTx.Checked = true;
                SetStatus("Strict RX requires TX signing in this backend. TX signing enabled.", false);
            }

            byte[] keyBytes = null;
            string keyText = (_txtKey.Text ?? string.Empty).Trim();

            if (!EnsureTarget(out var sysid, out var compid))
                return;

            if (enableSigning)
            {
                if (!TryParseSigningKey(keyText, out keyBytes, out var keyError))
                {
                    SetStatus("Invalid key: " + keyError, true);
                    return;
                }
            }

            byte linkId = EnsureEffectiveLinkId(enableSigning);

            if (enableSigning)
            {
                bool ok = MainV2.comPort.setupSigning(sysid, compid, string.Empty, keyBytes);
                if (!ok)
                {
                    SetStatus("Apply failed while enabling signing.", true);
                    return;
                }

                mav.linkid = linkId;
                mav.signingignore = !strictRx;
            }
            else
            {
                bool ok = MainV2.comPort.setupSigning(sysid, compid, string.Empty);
                if (!ok)
                {
                    SetStatus("Apply failed while disabling signing.", true);
                    return;
                }

                mav.signingignore = true;
                mav.linkid = 0;
            }

            PersistSettings(signTx, strictRx, linkId, keyText);
            SetStatus("Security settings applied.", false);
            UpdateStatusSnapshot();
        }

        private void PushKey()
        {
            var mav = CurrentMav;
            if (mav == null)
            {
                SetStatus("No MAVLink session available.", true);
                return;
            }

            if (!EnsureTarget(out var sysid, out var compid))
                return;

            var keyText = (_txtKey.Text ?? string.Empty).Trim();
            if (!TryParseSigningKey(keyText, out var keyBytes, out var keyError))
            {
                SetStatus("Invalid key: " + keyError, true);
                return;
            }

            byte linkId = EnsureEffectiveLinkId(true);
            bool strictRx = _chkRequireSignedRx.Checked;

            mav.linkid = linkId;
            mav.signingignore = !strictRx;

            bool ok = MainV2.comPort.setupSigning(sysid, compid, string.Empty, keyBytes);
            if (!ok)
            {
                SetStatus("Push key failed.", true);
                return;
            }

            _chkSignTx.Checked = true;
            PersistSettings(true, strictRx, linkId, keyText);
            SetStatus("Signing key pushed to FC/SITL and local signing enabled.", false);
            UpdateStatusSnapshot();
        }

        private void ApplyAndPush()
        {
            ApplyLocal();
            if (_lblStatus.ForeColor == Color.DarkRed)
                return;

            PushKey();
        }

        private void RemoveSecurity()
        {
            var mav = CurrentMav;
            if (mav == null)
            {
                SetStatus("No MAVLink session available.", true);
                return;
            }

            if (!EnsureTarget(out var sysid, out var compid))
                return;

            bool ok = MainV2.comPort.setupSigning(sysid, compid, string.Empty);
            if (!ok)
            {
                SetStatus("Remove security failed.", true);
                return;
            }

            _chkSignTx.Checked = false;
            _chkRequireSignedRx.Checked = false;
            _numLinkId.Value = 0;
            _txtKey.Text = string.Empty;

            PersistSettings(false, false, 0, string.Empty);
            SetStatus("Security disable sent. Local signing disabled.", false);
            UpdateStatusSnapshot();
        }

        private void Probe()
        {
            var mav = CurrentMav;
            if (mav == null)
            {
                SetStatus("No MAVLink session available.", true);
                return;
            }

            if (!EnsureTarget(out var sysid, out var compid))
                return;

            var ping = new MAVLink.mavlink_ping_t
            {
                time_usec = (ulong)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalMilliseconds * 1000UL,
                seq = (uint)Environment.TickCount,
                target_system = sysid,
                target_component = compid
            };

            MainV2.comPort.sendPacket(ping, sysid, compid);
            SetStatus("Probe ping sent to target " + sysid + ":" + compid + ".", false);
        }

        private bool EnsureTarget(out byte sysid, out byte compid)
        {
            sysid = CurrentMav?.sysid ?? 0;
            compid = CurrentMav?.compid ?? 0;

            if (sysid == 0)
            {
                SetStatus("No target system detected yet. Wait for heartbeat.", true);
                return false;
            }

            return true;
        }

        private void LoadUiFromCurrentMav()
        {
            var mav = CurrentMav;
            if (mav == null)
                return;

            _chkSignTx.Checked = mav.signing;
            _chkRequireSignedRx.Checked = !mav.signingignore;
            _numLinkId.Value = mav.linkid;
            _txtKey.Text = ReadStringSetting(SettingSigningKey, string.Empty);
        }

        private void UpdateStatusSnapshot()
        {
            var mav = CurrentMav;
            if (mav == null)
            {
                _lblTarget.Text = "Target: no MAVLink session";
                _lblRuntime.Text = "Runtime: unavailable";
                SetUiEnabled(true);
                return;
            }

            var age = mav.lastvalidpacket == DateTime.MinValue
                ? TimeSpan.MaxValue
                : DateTime.Now - mav.lastvalidpacket;
            bool linkOpen = MainV2.comPort.BaseStream != null && MainV2.comPort.BaseStream.IsOpen;
            bool hbSeen = age.TotalSeconds < 5;

            _lblTarget.Text = hbSeen
                ? string.Format(CultureInfo.InvariantCulture, "Target: {0}:{1}", mav.sysid, mav.compid)
                : "Target: waiting for heartbeat";

            _lblRuntime.Text =
                "Runtime: mode=" + (mav.signing ? "Signed" : "Off") +
                ", strict-rx=" + (!mav.signingignore ? "on" : "off") +
                ", key=" + (TryParseSigningKey(ReadStringSetting(SettingSigningKey, string.Empty), out _, out _) ? "configured" : "missing") +
                ", link=" + (linkOpen ? "up" : "down") +
                ", packets=" + (mav.packetsnotlost + mav.packetslost).ToString("0", CultureInfo.InvariantCulture);

            _lblRuntime.ForeColor = (mav.signing && !TryParseSigningKey(ReadStringSetting(SettingSigningKey, string.Empty), out _, out _))
                ? Color.DarkRed
                : Color.DarkGreen;

            SetUiEnabled(true);
        }

        private static byte[] GenerateRandomKey32()
        {
            byte[] key = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return key;
        }

        private byte EnsureEffectiveLinkId(bool signingWillBeEnabled)
        {
            byte linkId = (byte)_numLinkId.Value;
            if (!signingWillBeEnabled || linkId != 0)
                return linkId;

            byte[] one = new byte[1];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(one);
            }

            linkId = one[0] == 0 ? (byte)1 : one[0];
            _numLinkId.Value = linkId;
            SetStatus("Auto-assigned Link ID for signing: " + linkId.ToString(CultureInfo.InvariantCulture), false);
            return linkId;
        }

        private static bool TryParseSigningKey(string text, out byte[] key, out string error)
        {
            key = null;
            error = string.Empty;

            string input = (text ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(input))
            {
                error = "empty key";
                return false;
            }

            string compactHex = Regex.Replace(input, "[^0-9a-fA-F]", string.Empty);
            if (compactHex.Length == 64 && Regex.IsMatch(compactHex, "^[0-9a-fA-F]{64}$"))
            {
                key = HexToBytes(compactHex);
                return true;
            }

            try
            {
                key = Convert.FromBase64String(input);
                if (key.Length != 32)
                {
                    error = "base64 key must decode to exactly 32 bytes";
                    key = null;
                    return false;
                }

                return true;
            }
            catch
            {
                error = "expecting hex64 or base64 encoding";
                return false;
            }
        }

        private static byte[] HexToBytes(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = byte.Parse(hex.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            return bytes;
        }

        private static string ToLowerHex(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
            {
                sb.Append(bytes[i].ToString("x2", CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }

        private void LoadUiFromSettings()
        {
            bool signingEnabled = ReadBoolSetting(SettingSigningEnabled, false);
            bool requireSignedIncoming = ReadBoolSetting(SettingRequireSignedIncoming, false);
            byte linkId = ReadByteSetting(SettingSigningLinkId, 0);
            string key = ReadStringSetting(SettingSigningKey, string.Empty);

            _chkSignTx.Checked = signingEnabled;
            _chkRequireSignedRx.Checked = requireSignedIncoming;
            _numLinkId.Value = linkId;
            _txtKey.Text = key;
        }

        private void PersistSettings(bool signingEnabled, bool requireSignedIncoming, byte linkId, string key)
        {
            Settings.Instance[SettingSigningEnabled] = signingEnabled.ToString().ToLowerInvariant();
            Settings.Instance[SettingRequireSignedIncoming] = requireSignedIncoming.ToString().ToLowerInvariant();
            Settings.Instance[SettingSigningLinkId] = linkId.ToString(CultureInfo.InvariantCulture);
            Settings.Instance[SettingSigningKey] = key ?? string.Empty;
        }

        private static bool ReadBoolSetting(string key, bool defaultValue)
        {
            var value = Settings.Instance[key];
            if (value == null)
                return defaultValue;

            return bool.TryParse(value.ToString(), out var parsed) ? parsed : defaultValue;
        }

        private static byte ReadByteSetting(string key, byte defaultValue)
        {
            var value = Settings.Instance[key];
            if (value == null)
                return defaultValue;

            return byte.TryParse(value.ToString(), out var parsed) ? parsed : defaultValue;
        }

        private static string ReadStringSetting(string key, string defaultValue)
        {
            var value = Settings.Instance[key];
            return value == null ? defaultValue : value.ToString();
        }

        private void SetStatus(string text, bool isError)
        {
            _lblStatus.Text = (text ?? string.Empty).Trim();
            _lblStatus.ForeColor = isError ? Color.DarkRed : Color.DarkGreen;
        }
    }
}
