using System;
using System.Drawing;
using System.Windows.Forms;

namespace MissionPlanner.Controls
{
    /// <summary>
    /// QCI Compliance Level Indicator for Flight Module.
    /// Annexure E:
    ///   Level 0 - Multi-module with 128-bit+ symmetric encryption for inter-module communication.
    ///   Level 1 - Single/isolated module with no external communication risk.
    /// </summary>
    public enum ComplianceLevel
    {
        /// <summary>Multi-module architecture with secure inter-module communication (128-bit+ encryption).</summary>
        Level0,
        /// <summary>Single/isolated module architecture with no external communication risk.</summary>
        Level1,
        /// <summary>Compliance level not yet determined.</summary>
        Unknown
    }

    public sealed class ComplianceIndicator : UserControl
    {
        private ComplianceLevel _level = ComplianceLevel.Level1;
        private readonly Panel _badge;
        private readonly Label _lblTitle;
        private readonly Label _lblLevel;
        private readonly Label _lblDesc;

        public ComplianceLevel CurrentLevel
        {
            get => _level;
            set
            {
                if (_level == value) return;
                _level = value;
                RefreshDisplay();
            }
        }

        public ComplianceIndicator()
        {
            BackColor = Color.FromArgb(25, 25, 25);

            _badge = new Panel
            {
                Dock = DockStyle.Fill,
                BorderStyle = BorderStyle.FixedSingle,
                BackColor = Color.FromArgb(35, 35, 35),
                Padding = new Padding(8)
            };

            _lblTitle = new Label
            {
                Text = "QCI Flight Module Compliance",
                ForeColor = Color.LightGray,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                AutoSize = true,
                Left = 8,
                Top = 6
            };

            _lblLevel = new Label
            {
                Text = "Level 1",
                ForeColor = Color.White,
                BackColor = Color.FromArgb(76, 175, 80),
                Font = new Font("Segoe UI", 14f, FontStyle.Bold),
                Padding = new Padding(8, 4, 8, 4),
                Left = 8,
                Top = 30,
                AutoSize = true
            };

            _lblDesc = new Label
            {
                Text = "Isolated module \u2022 No external communication \u2022 Firmware signed & audited",
                ForeColor = Color.Gainsboro,
                Font = new Font("Segoe UI", 9f),
                AutoSize = true,
                Left = 8,
                Top = 66,
                MaximumSize = new Size(640, 40)
            };

            _badge.Controls.Add(_lblTitle);
            _badge.Controls.Add(_lblLevel);
            _badge.Controls.Add(_lblDesc);
            Controls.Add(_badge);
        }

        private void RefreshDisplay()
        {
            switch (_level)
            {
                case ComplianceLevel.Level0:
                    _lblLevel.Text = "Level 0";
                    _lblLevel.BackColor = Color.FromArgb(255, 152, 0);
                    _lblDesc.Text = "Multi-module system \u2022 128-bit+ encrypted inter-module communication \u2022 All modules signed";
                    break;
                case ComplianceLevel.Level1:
                    _lblLevel.Text = "Level 1";
                    _lblLevel.BackColor = Color.FromArgb(76, 175, 80);
                    _lblDesc.Text = "Isolated module \u2022 No external communication \u2022 Firmware signed & audited";
                    break;
                default:
                    _lblLevel.Text = "Unknown";
                    _lblLevel.BackColor = Color.FromArgb(158, 158, 158);
                    _lblDesc.Text = "Compliance level not determined. Review system architecture.";
                    break;
            }

            Refresh();
        }

        /// <summary>Returns a brief compliance status string for logging/display.</summary>
        public static string GetStatusString(ComplianceLevel level)
        {
            switch (level)
            {
                case ComplianceLevel.Level0: return "QCI Compliance Level 0 (Multi-module, 128-bit+ encrypted)";
                case ComplianceLevel.Level1: return "QCI Compliance Level 1 (Isolated, no external communication)";
                default: return "QCI Compliance Level Unknown";
            }
        }

        /// <summary>Determines compliance level based on whether external communication is active.</summary>
        public static ComplianceLevel Determine(bool hasExternalCommunication)
        {
            return hasExternalCommunication ? ComplianceLevel.Level0 : ComplianceLevel.Level1;
        }
    }
}
