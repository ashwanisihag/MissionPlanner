using MissionPlanner.Controls;
using MissionPlanner.Utilities;
using System;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace MissionPlanner.GCSViews
{
    public class UserManagement : MyUserControl, IActivate
    {
        private readonly ListBox _lstUsers = new ListBox();
        private readonly TextBox _txtUsername = new TextBox();
        private readonly TextBox _txtPassword = new TextBox();
        private readonly ComboBox _cmbRole = new ComboBox();
        private readonly CheckBox _chkEnabled = new CheckBox();
        private readonly Label _lblStatus = new Label();
        private readonly Button _btnNew = new Button();
        private readonly Button _btnSave = new Button();
        private readonly Button _btnDelete = new Button();
        private readonly Label _lblHint = new Label();

        public UserManagement()
        {
            BuildUi();
            RefreshUsers();
        }

        public void Activate()
        {
            RefreshUsers();
        }

        private void BuildUi()
        {
            Dock = DockStyle.Fill;

            var split = new SplitContainer
            {
                Dock = DockStyle.Fill,
                SplitterDistance = 260,
                Padding = new Padding(8)
            };
            Controls.Add(split);

            _lstUsers.Dock = DockStyle.Fill;
            _lstUsers.SelectedIndexChanged += (s, e) => LoadSelectedUser();
            split.Panel1.Controls.Add(_lstUsers);

            var right = new Panel { Dock = DockStyle.Fill };
            split.Panel2.Controls.Add(right);

            int y = 8;
            right.Controls.Add(new Label { Left = 8, Top = y, Width = 120, Text = "Username" });
            y += 18;
            _txtUsername.Left = 8;
            _txtUsername.Top = y;
            _txtUsername.Width = 320;
            right.Controls.Add(_txtUsername);

            y += 34;
            right.Controls.Add(new Label { Left = 8, Top = y, Width = 170, Text = "Password (leave blank to keep)" });
            y += 18;
            _txtPassword.Left = 8;
            _txtPassword.Top = y;
            _txtPassword.Width = 320;
            _txtPassword.UseSystemPasswordChar = true;
            right.Controls.Add(_txtPassword);

            y += 34;
            right.Controls.Add(new Label { Left = 8, Top = y, Width = 100, Text = "Role" });
            y += 18;
            _cmbRole.Left = 8;
            _cmbRole.Top = y;
            _cmbRole.Width = 180;
            _cmbRole.DropDownStyle = ComboBoxStyle.DropDownList;
            _cmbRole.Items.AddRange(Enum.GetNames(typeof(AppUserRole)).Cast<object>().ToArray());
            _cmbRole.SelectedIndex = 0;
            right.Controls.Add(_cmbRole);

            _chkEnabled.Left = 200;
            _chkEnabled.Top = y + 3;
            _chkEnabled.Width = 120;
            _chkEnabled.Text = "Enabled";
            _chkEnabled.Checked = true;
            right.Controls.Add(_chkEnabled);

            y += 40;
            _btnNew.Left = 8;
            _btnNew.Top = y;
            _btnNew.Width = 80;
            _btnNew.Text = "New";
            _btnNew.Click += (s, e) => ClearEditor();
            right.Controls.Add(_btnNew);

            _btnSave.Left = 96;
            _btnSave.Top = y;
            _btnSave.Width = 80;
            _btnSave.Text = "Save";
            _btnSave.Click += (s, e) => SaveUser();
            right.Controls.Add(_btnSave);

            _btnDelete.Left = 184;
            _btnDelete.Top = y;
            _btnDelete.Width = 80;
            _btnDelete.Text = "Delete";
            _btnDelete.Click += (s, e) => DeleteUser();
            right.Controls.Add(_btnDelete);

            y += 42;
            _lblHint.Left = 8;
            _lblHint.Top = y;
            _lblHint.Width = 520;
            _lblHint.Height = 48;
            _lblHint.Text = "Default seed account is admin/admin. Change password immediately.";
            _lblHint.ForeColor = Color.DimGray;
            right.Controls.Add(_lblHint);

            y += 52;
            _lblStatus.Left = 8;
            _lblStatus.Top = y;
            _lblStatus.Width = 600;
            _lblStatus.Height = 22;
            _lblStatus.Text = "Ready";
            right.Controls.Add(_lblStatus);
        }

        private void RefreshUsers()
        {
            bool isAdmin = RoleBasedAccess.IsInRole(AppUserRole.Admin);
            _lstUsers.Items.Clear();

            if (!isAdmin)
            {
                SetStatus("Admin role required to manage users.", true);
                SetEditorEnabled(false);
                return;
            }

            foreach (var user in RoleBasedAccess.GetUsers().OrderBy(u => u.Username, StringComparer.OrdinalIgnoreCase))
            {
                _lstUsers.Items.Add(user.Username);
            }

            SetEditorEnabled(true);
            if (_lstUsers.Items.Count > 0)
                _lstUsers.SelectedIndex = 0;
            else
                ClearEditor();
        }

        private void SetEditorEnabled(bool enabled)
        {
            _lstUsers.Enabled = enabled;
            _txtUsername.Enabled = enabled;
            _txtPassword.Enabled = enabled;
            _cmbRole.Enabled = enabled;
            _chkEnabled.Enabled = enabled;
            _btnNew.Enabled = enabled;
            _btnSave.Enabled = enabled;
            _btnDelete.Enabled = enabled;
        }

        private void LoadSelectedUser()
        {
            if (_lstUsers.SelectedItem == null)
                return;

            var username = _lstUsers.SelectedItem.ToString();
            var user = RoleBasedAccess.GetUsers().FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));
            if (user == null)
                return;

            _txtUsername.Text = user.Username;
            _txtPassword.Text = string.Empty;
            _cmbRole.SelectedItem = user.Role;
            _chkEnabled.Checked = user.Enabled;
            SetStatus("Loaded user: " + user.Username, false);
        }

        private void SaveUser()
        {
            if (!RoleBasedAccess.EnsureRole(AppUserRole.Admin, "user management"))
                return;

            if (!Enum.TryParse<AppUserRole>(_cmbRole.SelectedItem?.ToString() ?? string.Empty, true, out var role))
            {
                role = AppUserRole.Operator;
            }

            if (RoleBasedAccess.UpsertUser(_txtUsername.Text, role, _chkEnabled.Checked, _txtPassword.Text, out var message))
            {
                SetStatus("User saved.", false);
                RefreshUsers();
                SelectUser(_txtUsername.Text);
                _txtPassword.Text = string.Empty;
                return;
            }

            SetStatus(message, true);
        }

        private void DeleteUser()
        {
            if (!RoleBasedAccess.EnsureRole(AppUserRole.Admin, "user management"))
                return;

            var username = (_txtUsername.Text ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(username))
            {
                SetStatus("Select a user to delete.", true);
                return;
            }

            if (MessageBox.Show("Delete user '" + username + "'?", "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            if (RoleBasedAccess.DeleteUser(username, out var message))
            {
                SetStatus("User deleted.", false);
                RefreshUsers();
                return;
            }

            SetStatus(message, true);
        }

        private void SelectUser(string username)
        {
            for (int i = 0; i < _lstUsers.Items.Count; i++)
            {
                if (string.Equals(_lstUsers.Items[i].ToString(), username, StringComparison.OrdinalIgnoreCase))
                {
                    _lstUsers.SelectedIndex = i;
                    return;
                }
            }
        }

        private void ClearEditor()
        {
            _lstUsers.ClearSelected();
            _txtUsername.Text = string.Empty;
            _txtPassword.Text = string.Empty;
            _cmbRole.SelectedItem = AppUserRole.Operator.ToString();
            _chkEnabled.Checked = true;
            SetStatus("New user entry.", false);
        }

        private void SetStatus(string text, bool error)
        {
            _lblStatus.Text = text;
            _lblStatus.ForeColor = error ? Color.DarkRed : Color.DarkGreen;
        }
    }
}
