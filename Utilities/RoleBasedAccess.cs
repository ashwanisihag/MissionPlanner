using MissionPlanner.Controls;
using log4net;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace MissionPlanner.Utilities
{
    public enum AppUserRole
    {
        Operator = 0,
        Admin = 1
    }

    public class AppUserRecord
    {
        public string Username { get; set; }
        public string PasswordHash { get; set; }
        public string Salt { get; set; }
        public string Role { get; set; }
        public bool Enabled { get; set; }
    }

    public static class RoleBasedAccess
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(RoleBasedAccess));

        private const string UsersSettingKey = "RbacUsersJson";
        private const string SessionUserKey = "RbacCurrentUser";
        private const string SessionRoleKey = "RbacCurrentRole";

        private static readonly object SyncRoot = new object();
        private static List<AppUserRecord> _users;

        public static event EventHandler SessionChanged;

        static RoleBasedAccess()
        {
            EnsureSeedUser();
            LoadSessionFromSettings();
        }

        public static string CurrentUsername { get; private set; }

        public static AppUserRole CurrentRole { get; private set; } = AppUserRole.Operator;

        public static bool IsAuthenticated => !string.IsNullOrWhiteSpace(CurrentUsername);

        public static bool IsInRole(AppUserRole minimumRole)
        {
            return IsAuthenticated && CurrentRole >= minimumRole;
        }

        public static IReadOnlyList<AppUserRecord> GetUsers()
        {
            lock (SyncRoot)
            {
                return LoadUsers().Select(Clone).ToList();
            }
        }

        public static bool TryLogin(string username, string password, out string message)
        {
            message = string.Empty;
            string attemptedUser = (username ?? string.Empty).Trim();

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                message = "Username and password are required.";
                log.Warn("[RBAC] login failed reason='missing credentials' user='" + attemptedUser + "'");
                return false;
            }

            lock (SyncRoot)
            {
                var user = LoadUsers().FirstOrDefault(u => string.Equals(u.Username, username.Trim(), StringComparison.OrdinalIgnoreCase));
                if (user == null || !user.Enabled)
                {
                    message = "User not found or disabled.";
                    log.Warn("[RBAC] login failed reason='user missing or disabled' user='" + attemptedUser + "'");
                    return false;
                }

                if (!VerifyPassword(password, user.Salt, user.PasswordHash))
                {
                    message = "Invalid credentials.";
                    log.Warn("[RBAC] login failed reason='invalid password' user='" + attemptedUser + "'");
                    return false;
                }

                CurrentUsername = user.Username;
                CurrentRole = ParseRole(user.Role);
                PersistSession();
                log.Info("[RBAC] login success user='" + CurrentUsername + "' role='" + CurrentRole + "'");
            }

            RaiseSessionChanged();
            return true;
        }

        public static void Logout()
        {
            string previousUser = CurrentUsername ?? string.Empty;
            AppUserRole previousRole = CurrentRole;

            CurrentUsername = null;
            CurrentRole = AppUserRole.Operator;
            PersistSession();
            log.Info("[RBAC] logout user='" + previousUser + "' role='" + previousRole + "'");
            RaiseSessionChanged();
        }

        public static bool UpsertUser(string username, AppUserRole role, bool enabled, string password, out string message)
        {
            message = string.Empty;
            username = (username ?? string.Empty).Trim();

            if (string.IsNullOrWhiteSpace(username))
            {
                message = "Username is required.";
                return false;
            }

            lock (SyncRoot)
            {
                var users = LoadUsers();
                var existing = users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));

                if (existing == null)
                {
                    if (string.IsNullOrWhiteSpace(password))
                    {
                        message = "Password is required for a new user.";
                        return false;
                    }

                    CreateHash(password, out var salt, out var hash);
                    users.Add(new AppUserRecord
                    {
                        Username = username,
                        Role = role.ToString(),
                        Enabled = enabled,
                        Salt = salt,
                        PasswordHash = hash
                    });
                    log.Info("[RBAC] user created user='" + username + "' role='" + role + "' enabled='" + enabled + "'");
                }
                else
                {
                    existing.Role = role.ToString();
                    existing.Enabled = enabled;

                    if (!string.IsNullOrWhiteSpace(password))
                    {
                        CreateHash(password, out var salt, out var hash);
                        existing.Salt = salt;
                        existing.PasswordHash = hash;
                    }

                    log.Info("[RBAC] user updated user='" + existing.Username + "' role='" + existing.Role + "' enabled='" + existing.Enabled + "' passwordChanged='" + (!string.IsNullOrWhiteSpace(password)) + "'");
                }

                if (!users.Any(u => u.Enabled && ParseRole(u.Role) == AppUserRole.Admin))
                {
                    message = "At least one enabled admin user is required.";
                    log.Warn("[RBAC] user upsert blocked reason='no enabled admin would remain' target='" + username + "'");
                    return false;
                }

                SaveUsers(users);
            }

            return true;
        }

        public static bool DeleteUser(string username, out string message)
        {
            message = string.Empty;
            username = (username ?? string.Empty).Trim();

            if (string.IsNullOrWhiteSpace(username))
            {
                message = "Username is required.";
                return false;
            }

            lock (SyncRoot)
            {
                var users = LoadUsers();
                var existing = users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));
                if (existing == null)
                {
                    message = "User not found.";
                    log.Warn("[RBAC] user delete failed reason='not found' user='" + username + "'");
                    return false;
                }

                users.Remove(existing);
                log.Info("[RBAC] user deleted user='" + existing.Username + "'");

                if (!users.Any(u => u.Enabled && ParseRole(u.Role) == AppUserRole.Admin))
                {
                    message = "Cannot remove the last enabled admin.";
                    log.Warn("[RBAC] user delete blocked reason='last enabled admin' user='" + username + "'");
                    return false;
                }

                SaveUsers(users);
            }

            if (string.Equals(CurrentUsername, username, StringComparison.OrdinalIgnoreCase))
            {
                Logout();
            }

            return true;
        }

        public static bool EnsureRole(AppUserRole minimumRole, string actionLabel)
        {
            if (IsInRole(minimumRole))
                return true;

            string msg = IsAuthenticated
                ? "You need role '" + minimumRole + "' for " + actionLabel + ". Current role: " + CurrentRole + "."
                : "You need to login for " + actionLabel + ".";

            CustomMessageBox.Show(msg, "Access denied");
            log.Warn("[RBAC] access denied action='" + actionLabel + "' required='" + minimumRole + "' user='" + (CurrentUsername ?? "(none)") + "' role='" + CurrentRole + "'");
            return false;
        }

        private static void EnsureSeedUser()
        {
            lock (SyncRoot)
            {
                var users = LoadUsers();
                bool changed = false;

                if (!users.Exists(u => string.Equals(u.Username, "admin", StringComparison.OrdinalIgnoreCase)))
                {
                    CreateHash("admin", out var salt, out var hash);
                    users.Add(new AppUserRecord
                    {
                        Username = "admin",
                        Role = AppUserRole.Admin.ToString(),
                        Enabled = true,
                        Salt = salt,
                        PasswordHash = hash
                    });
                    log.Warn("[RBAC] seed user created: admin (Admin)");
                    changed = true;
                }

                if (!users.Exists(u => string.Equals(u.Username, "operator", StringComparison.OrdinalIgnoreCase)))
                {
                    CreateHash("operator", out var opSalt, out var opHash);
                    users.Add(new AppUserRecord
                    {
                        Username = "operator",
                        Role = AppUserRole.Operator.ToString(),
                        Enabled = true,
                        Salt = opSalt,
                        PasswordHash = opHash
                    });
                    log.Warn("[RBAC] seed user created: operator (Operator)");
                    changed = true;
                }

                if (changed)
                    SaveUsers(users);
            }
        }

        private static void LoadSessionFromSettings()
        {
            var username = (Settings.Instance[SessionUserKey] ?? string.Empty).ToString();
            var roleText = (Settings.Instance[SessionRoleKey] ?? AppUserRole.Operator.ToString()).ToString();
            var role = ParseRole(roleText);

            lock (SyncRoot)
            {
                var user = LoadUsers().FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase) && u.Enabled);
                if (user == null)
                {
                    CurrentUsername = null;
                    CurrentRole = AppUserRole.Operator;
                    PersistSession();
                    return;
                }

                CurrentUsername = user.Username;
                CurrentRole = ParseRole(user.Role);
            }
        }

        private static List<AppUserRecord> LoadUsers()
        {
            if (_users != null)
                return _users;

            try
            {
                var json = (Settings.Instance[UsersSettingKey] ?? string.Empty).ToString();
                _users = string.IsNullOrWhiteSpace(json)
                    ? new List<AppUserRecord>()
                    : JsonConvert.DeserializeObject<List<AppUserRecord>>(json) ?? new List<AppUserRecord>();
            }
            catch
            {
                _users = new List<AppUserRecord>();
            }

            NormalizeUsers(_users);
            return _users;
        }

        private static void SaveUsers(List<AppUserRecord> users)
        {
            NormalizeUsers(users);
            _users = users;
            Settings.Instance[UsersSettingKey] = JsonConvert.SerializeObject(users);
        }

        private static void NormalizeUsers(List<AppUserRecord> users)
        {
            for (int i = users.Count - 1; i >= 0; i--)
            {
                var u = users[i];
                if (u == null || string.IsNullOrWhiteSpace(u.Username) || string.IsNullOrWhiteSpace(u.Salt) || string.IsNullOrWhiteSpace(u.PasswordHash))
                {
                    users.RemoveAt(i);
                    continue;
                }

                u.Username = u.Username.Trim();
                u.Role = ParseRole(u.Role).ToString();
            }
        }

        private static AppUserRecord Clone(AppUserRecord user)
        {
            return new AppUserRecord
            {
                Username = user.Username,
                PasswordHash = user.PasswordHash,
                Salt = user.Salt,
                Role = user.Role,
                Enabled = user.Enabled
            };
        }

        private static AppUserRole ParseRole(string role)
        {
            if (Enum.TryParse(role, true, out AppUserRole parsed))
                return parsed;

            return AppUserRole.Operator;
        }

        private static void PersistSession()
        {
            Settings.Instance[SessionUserKey] = CurrentUsername ?? string.Empty;
            Settings.Instance[SessionRoleKey] = CurrentRole.ToString();
        }

        private static void RaiseSessionChanged()
        {
            SessionChanged?.Invoke(null, EventArgs.Empty);
        }

        private static void CreateHash(string password, out string saltBase64, out string hashBase64)
        {
            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            using (var derive = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256))
            {
                byte[] hash = derive.GetBytes(32);
                saltBase64 = Convert.ToBase64String(salt);
                hashBase64 = Convert.ToBase64String(hash);
            }
        }

        private static bool VerifyPassword(string password, string saltBase64, string expectedHashBase64)
        {
            try
            {
                byte[] salt = Convert.FromBase64String(saltBase64);
                byte[] expected = Convert.FromBase64String(expectedHashBase64);

                using (var derive = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256))
                {
                    byte[] actual = derive.GetBytes(32);
#if NET6_0_OR_GREATER
                    return CryptographicOperations.FixedTimeEquals(actual, expected);
#else
                    if (actual.Length != expected.Length)
                        return false;

                    int diff = 0;
                    for (int i = 0; i < actual.Length; i++)
                        diff |= actual[i] ^ expected[i];

                    return diff == 0;
#endif
                }
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Role-based visibility rules applied to a DisplayView instance.
    /// Operator: Flight Data monitoring only (no configuration access).
    /// Admin   : Full access — all flags left at their defaults.
    /// </summary>
    public static class RoleDisplayPolicy
    {
        public static void Apply(DisplayView dv, AppUserRole role)
        {
            if (role == AppUserRole.Admin)
            {
                // Admin sees everything — restore defaults
                ApplyAdmin(dv);
            }
            else
            {
                // Operator (authenticated) and unauthenticated — minimal monitoring access
                ApplyOperator(dv);
            }
        }

        private static void ApplyAdmin(DisplayView dv)
        {
            // Top-level tabs
            dv.displayInitialSetup = true;
            dv.displayConfigTuning = true;
            dv.displaySimulation = false;   // keep simulation off (hardware GCS)
            dv.displayHelp = false;
            dv.displayTerminal = false;
            dv.displayDonate = false;

            // Flight Data
            dv.displayQuickTab = true;
            dv.displayPreFlightTab = true;
            dv.displayAdvActionsTab = true;
            dv.displaySimpleActionsTab = false;
            dv.displayGaugesTab = true;
            dv.displayStatusTab = true;
            dv.displayServoTab = true;
            dv.displayScriptsTab = false;
            dv.displayTelemetryTab = true;
            dv.displayDataflashTab = true;
            dv.displayMessagesTab = true;

            // Flight Plan
            dv.displayGeoFenceMenu = true;
            dv.displayRallyPointsMenu = true;
            dv.displaySplineCircleAutoWp = true;
            dv.displayPoiMenu = true;
            dv.displayTrackerHomeMenu = true;
            dv.displayCheckHeightBox = true;

            // Initial Setup
            dv.displayInstallFirmware = true;
            dv.displayFrameType = true;
            dv.displayInitialParams = true;
            dv.displayAccelCalibration = true;
            dv.displayCompassConfiguration = true;
            dv.displayRadioCalibration = true;
            dv.displayServoOutput = true;
            dv.displayEscCalibration = true;
            dv.displayFlightModes = true;
            dv.displayFailSafe = true;
            dv.displayHWIDs = true;
            dv.optionalHardware = true;
            dv.displayRTKInject = true;
            dv.displaySikRadio = true;
            dv.displayBattMonitor = true;
            dv.displayCAN = true;
            dv.displayJoystick = true;
            dv.displayCompassMotorCalib = true;
            dv.displayRangeFinder = true;
            dv.displayAirSpeed = true;
            dv.displayOpticalFlow = true;
            dv.displayOsd = true;
            dv.displayCameraGimbal = true;
            dv.displayMotorTest = true;
            dv.displayParachute = true;
            dv.displayAntennaTracker = true;
            dv.displaySerialPorts = true;
            dv.displayADSB = true;
            dv.displayGPSOrder = true;

            // Config / Tuning
            dv.displayBasicTuning = true;
            dv.displayExtendedTuning = true;
            dv.displayStandardParams = false;
            dv.displayAdvancedParams = false;
            dv.displayFullParamList = true;
            dv.displayFullParamTree = true;
            dv.displayOSD = true;
            dv.mavFTP = true;
            dv.displayUserParam = true;
            dv.displayPlannerSettings = true;
            dv.displayFFTSetup = true;
            dv.secure = false;
        }

        private static void ApplyOperator(DisplayView dv)
        {
            // Top-level tabs — Setup and Config/Tuning visible for calibration + geofence settings
            dv.displayInitialSetup = true;
            dv.displayConfigTuning = true;
            dv.displaySimulation = false;
            dv.displayHelp = false;
            dv.displayTerminal = false;
            dv.displayDonate = false;

            // Flight Data — monitoring only, no actions
            dv.displayQuickTab = true;
            dv.displayPreFlightTab = false;
            dv.displayAdvActionsTab = false;
            dv.displaySimpleActionsTab = false;
            dv.displayGaugesTab = true;
            dv.displayStatusTab = true;
            dv.displayServoTab = false;
            dv.displayScriptsTab = false;
            dv.displayTelemetryTab = false;
            dv.displayDataflashTab = false;
            dv.displayMessagesTab = true;

            // Flight Plan — geo fence allowed, hide edit/rally menus
            dv.displayGeoFenceMenu = true;
            dv.displayRallyPointsMenu = false;
            dv.displaySplineCircleAutoWp = false;
            dv.displayPoiMenu = false;
            dv.displayTrackerHomeMenu = false;
            dv.displayCheckHeightBox = false;

            // Initial Setup — calibration access only
            dv.displayInstallFirmware = false;
            dv.displayFrameType = false;
            dv.displayInitialParams = false;
            dv.displayAccelCalibration = true;
            dv.displayCompassConfiguration = true;
            dv.displayRadioCalibration = true;
            dv.displayServoOutput = false;
            dv.displayEscCalibration = true;
            dv.displayFlightModes = false;
            dv.displayFailSafe = false;
            dv.displayHWIDs = false;
            dv.optionalHardware = false;
            dv.displayRTKInject = false;
            dv.displaySikRadio = false;
            dv.displayBattMonitor = false;
            dv.displayCAN = false;
            dv.displayJoystick = false;
            dv.displayCompassMotorCalib = false;
            dv.displayRangeFinder = false;
            dv.displayAirSpeed = false;
            dv.displayOpticalFlow = false;
            dv.displayOsd = false;
            dv.displayCameraGimbal = false;
            dv.displayMotorTest = false;
            dv.displayParachute = false;
            dv.displayAntennaTracker = false;
            dv.displaySerialPorts = false;
            dv.displayADSB = false;
            dv.displayGPSOrder = false;

            // Config / Tuning — none
            dv.displayBasicTuning = false;
            dv.displayExtendedTuning = false;
            dv.displayStandardParams = false;
            dv.displayAdvancedParams = false;
            dv.displayFullParamList = false;
            dv.displayFullParamTree = false;
            dv.displayOSD = false;
            dv.mavFTP = false;
            dv.displayUserParam = false;
            dv.displayPlannerSettings = false;
            dv.displayFFTSetup = false;
            dv.secure = false;
        }

    }
}
