using MissionPlanner.Controls;
using System;
using System.Drawing;
using System.Windows.Forms;

namespace MissionPlanner.Controls
{
    public class LoginDialog : Form
    {
        private readonly TextBox _txtUsername;
        private readonly TextBox _txtPassword;

        public string Username => (_txtUsername.Text ?? string.Empty).Trim();
        public string Password => _txtPassword.Text ?? string.Empty;

        public LoginDialog()
        {
            Text = "User Login";
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            ClientSize = new Size(360, 155);

            var lblUser = new Label { Left = 16, Top = 18, Width = 90, Text = "Username" };
            _txtUsername = new TextBox { Left = 112, Top = 15, Width = 225 };

            var lblPass = new Label { Left = 16, Top = 52, Width = 90, Text = "Password" };
            _txtPassword = new TextBox { Left = 112, Top = 49, Width = 225, UseSystemPasswordChar = true };

            var btnOk = new MyButton { Left = 182, Top = 106, Width = 75, Text = "Login", DialogResult = DialogResult.OK };
            var btnCancel = new MyButton { Left = 262, Top = 106, Width = 75, Text = "Cancel", DialogResult = DialogResult.Cancel };

            AcceptButton = btnOk;
            CancelButton = btnCancel;

            Controls.Add(lblUser);
            Controls.Add(_txtUsername);
            Controls.Add(lblPass);
            Controls.Add(_txtPassword);
            Controls.Add(btnOk);
            Controls.Add(btnCancel);
        }
    }
}
