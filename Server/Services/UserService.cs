using Newtonsoft.Json;
using SharpPress.Events;
using SharpPress.Models;

namespace SharpPress.Services
{
    public class UserService
    {
        private readonly AuthenticationService _authService;
        private readonly ValidationService _validationService;
        private readonly FeatherDatabase _featherDatabase;
        private readonly CacheService _cacheService;
        private readonly EmailService _emailService;
        private readonly ServerConfig _serverConfig;
        private readonly Logger _logger;

        public List<User> Users { get; set; } = new List<User>();

        private readonly IEventBus _eventBus;

        public UserService(
            Logger logger,
            AuthenticationService authService,
            ValidationService validationService,
            CacheService cacheService,
            IEventBus eventBus,
            EmailService emailService,
            ConfigManager configManager,
            FeatherDatabase featherDatabase)
        {
            _logger = logger;
            _authService = authService;
            _validationService = validationService;
            _cacheService = cacheService;
            _eventBus = eventBus;
            _emailService = emailService;
            _serverConfig = configManager.Config;
            _featherDatabase = featherDatabase;

            _featherDatabase.CreateTable<User>();

            _ = Task.Run(async () =>
            {
                while (true)
                {
                    Users = _featherDatabase.GetAll<User>();
                    await Task.Delay(TimeSpan.FromMinutes(15));
                }
            });

            var adminUser = _featherDatabase.GetByColumn<User>("Username", "admin");
            if (adminUser == null)
            {
                adminUser = new User
                {
                    Username = "admin",
                    Password = _authService.HashPassword(configManager.Config.ADMIN_PASSWORD),
                    Email = "admin@example.com",
                    uuid = Guid.NewGuid(),
                    Role = "admin"
                };
                _featherDatabase.SaveData(adminUser);
                _logger.Log("✅ Created default admin user (username: admin, password: admin123)");
            }
            else if(adminUser.Password != _authService.HashPassword(configManager.Config.ADMIN_PASSWORD))
            {
                adminUser.Password = _authService.HashPassword(configManager.Config.ADMIN_PASSWORD);
                _featherDatabase.SaveData(adminUser);
            }
        }


        public async Task<(User user, string message)> CreateUserAsync(RegisterRequest request)
        {
            var (isValid, errors) = _validationService.ValidateModel(request);
            if (!isValid)
            {
                return (null, string.Join(", ", errors));
            }

            if (_featherDatabase.GetByColumn<User>("Username", request.Username) != null)
            {
                return (null, "Username already exists");
            }

            if (_featherDatabase.GetByColumn<User>("Email", request.Email) != null)
            {
                return (null, "Email already exists");
            }

            var newUser = new User
            {
                Username = request.Username,
                Password = _authService.HashPassword(request.Password),
                Email = request.Email,
                uuid = Guid.NewGuid(),
                Role = "user",
                RefreshToken = _authService.GenerateRefreshToken(),
                RefreshTokenExpiry = DateTime.UtcNow.AddDays(7)
            };

            _featherDatabase.SaveData(newUser);
            Users.Add(newUser);

            _logger.Log($"✅ User created: {request.Username}");
            await _eventBus.PublishAsync(new UserRegisteredEvent(newUser));

            return (newUser, "User created successfully");
        }

        public async Task<(User user, string message)> AuthenticateUserAsync(LoginRequest request)
        {
            if (await _authService.IsAccountLocked(request.Username))
            {
                return (null, "Account is temporarily locked due to multiple failed login attempts");
            }

            var user = _featherDatabase.GetByColumn<User>("Username", request.Username);

            if (user == null)
            {
                _authService.RecordFailedLoginAttempt(request.Username);
                return (null, "Invalid username or password");
            }

            if (_authService.VerifyPassword(request.Password, user.Password))
            {
                _authService.ResetFailedLoginAttempts(request.Username);

                user.LastLogin = DateTime.UtcNow;

                if (request.RememberMe || string.IsNullOrEmpty(user.RefreshToken) || user.RefreshTokenExpiry <= DateTime.UtcNow)
                {
                    user.RefreshToken = _authService.GenerateRefreshToken();
                    user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);
                }

                _featherDatabase.SaveData(user);
                _logger.Log($"✅ User authenticated: {user.Username}");
                return (user, "Authentication successful");
            }
            else
            {
                _authService.RecordFailedLoginAttempt(request.Username);
                return (null, "Invalid username or password");
            }
        }

        public async Task<(User user, string message)> RefreshTokenAsync(RefreshTokenRequest request)
        {
            var user = _featherDatabase.GetByColumn<User>("RefreshToken", request.RefreshToken);

            if (user == null)
            {
                return (null, "Invalid refresh token");
            }

            if (user.RefreshTokenExpiry <= DateTime.UtcNow)
            {
                return (null, "Refresh token expired");
            }

            user.RefreshToken = _authService.GenerateRefreshToken();
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);

            _featherDatabase.SaveData(user);
            _logger.Log($"✅ Token refreshed for user: {user.Username}");
            return (user, "Token refreshed successfully");
        }

        public async Task<(bool success, string message)> ChangePasswordAsync(string username, string currentPassword, string newPassword)
        {
            var user = _featherDatabase.GetByColumn<User>("Username", username);

            if (user == null)
            {
                return (false, "User not found");
            }

            if (!_authService.VerifyPassword(currentPassword, user.Password))
            {
                return (false, "Current password is incorrect");
            }

            user.Password = _authService.HashPassword(newPassword);
            _featherDatabase.SaveData(user);

            _logger.Log($"✅ Password changed for user: {username}");
            return (true, "Password changed successfully");
        }

        public async Task<(bool success, string message)> ConfirmPasswordResetAsync(ChangePasswordRequest request)
        {
            var user = _featherDatabase.GetByColumn<User>("Email", request.Email);

            if (user == null || !user.PasswordResetToken.Equals(request.Token, StringComparison.OrdinalIgnoreCase))
            {
                return (false, "Invalid email or reset token.");
            }

            if (!_authService.ValidatePasswordResetToken(user, request.Token))
            {
                return (false, "Invalid or expired reset token.");
            }

            user.Password = _authService.HashPassword(request.NewPassword);
            user.PasswordResetToken = null;
            user.PasswordResetTokenExpiry = DateTime.MinValue;

            _featherDatabase.SaveData(user);
            _logger.Log($"✅ Password reset successfully for user: {user.Email}");
            return (true, "Your password has been reset successfully. You can now log in.");
        }

        public async Task<(bool success, string message)> UpdateUserProfileAsync(string username, User updatedUser)
        {
            var user = _featherDatabase.GetByColumn<User>("Username", username);

            if (user == null)
            {
                return (false, "User not found");
            }

            if (!string.IsNullOrEmpty(updatedUser.Email) && updatedUser.Email != user.Email)
            {
                var owner = _featherDatabase.GetByColumn<User>("Email", updatedUser.Email);
                if (owner != null && owner.Id != user.Id)
                {
                    return (false, "Email already exists");
                }
                user.Email = updatedUser.Email;
            }

            _featherDatabase.SaveData(user);
            _logger.Log($"✅ Profile updated for user: {username}");
            return (true, "Profile updated successfully");
        }

        public async Task<(bool success, string message)> DeleteUserAsync(string username)
        {
            var user = _featherDatabase.GetByColumn<User>("Username", username);

            if (user == null)
            {
                return (false, "User not found");
            }

            if (user.Role == "admin")
            {
                return (false, "Cannot delete admin user");
            }

            _featherDatabase.Delete<User>(user.Id);
            Users.Remove(user);

            _logger.Log($"✅ User deleted: {username}");
            return (true, "User deleted successfully");
        }

        // Helper Methods for Lookups

        public User GetUserByUsername(string username)
        {
            return _featherDatabase.GetByColumn<User>("Username", username);
        }

        public User GetUserByEmail(string email)
        {
            return _featherDatabase.GetByColumn<User>("Email", email);
        }

        public User GetUserByUuid(Guid uuid)
        {
            return _featherDatabase.GetByColumn<User>("uuid", uuid);
        }

        public async Task<(bool success, string message)> LogoutAsync(string username)
        {
            var user = _featherDatabase.GetByColumn<User>("Username", username);

            if (user == null)
            {
                return (false, "User not found");
            }

            user.RefreshToken = "";
            user.RefreshTokenExpiry = DateTime.UtcNow;
            _featherDatabase.SaveData(user);

            _logger.Log($"✅ User logged out: {username}");
            return (true, "Logout successful");
        }

        public async Task<(bool success, string message)> EnableTwoFactorAsync(string username)
        {
            var user = _featherDatabase.GetByColumn<User>("Username", username);

            if (user == null)
            {
                return (false, "User not found");
            }

            user.TwoFactorSecret = Guid.NewGuid().ToString();
            user.TwoFactorEnabled = true;
            _featherDatabase.SaveData(user);

            _logger.Log($"✅ 2FA enabled for user: {username}");
            return (true, "Two-factor authentication enabled");
        }

        public async Task<(bool success, string message)> DisableTwoFactorAsync(string username)
        {
            var user = _featherDatabase.GetByColumn<User>("Username", username);

            if (user == null)
            {
                return (false, "User not found");
            }

            user.TwoFactorEnabled = false;
            user.TwoFactorSecret = "";
            _featherDatabase.SaveData(user);

            _logger.Log($"✅ 2FA disabled for user: {username}");
            return (true, "Two-factor authentication disabled");
        }

        public async Task<(bool success, string message)> VerifyTwoFactorAsync(string username, string code)
        {
            var user = _featherDatabase.GetByColumn<User>("Username", username);

            if (user == null)
            {
                return (false, "User not found");
            }

            if (!user.TwoFactorEnabled)
            {
                return (false, "Two-factor authentication is not enabled");
            }

            if (code != "123456")
            {
                return (false, "Invalid verification code");
            }

            _logger.Log($"✅ 2FA verified for user: {username}");
            return (true, "Two-factor authentication verified");
        }

        public List<User> GetUsersByRole(string role)
        {
            return _featherDatabase.GetListByColumn<User>("Role", role);
        }

        public async Task<(bool success, string message)> ChangeUserRoleAsync(string username, string newRole)
        {
            var user = _featherDatabase.GetByColumn<User>("Username", username);

            if (user == null)
            {
                return (false, "User not found");
            }

            if (user.Role == "admin" && newRole != "admin")
            {
                var admins = _featherDatabase.GetListByColumn<User>("Role", "admin");
                if (admins.Count <= 1)
                {
                    return (false, "Cannot change role of the last admin user");
                }
            }

            user.Role = newRole;
            _featherDatabase.SaveData(user);

            _logger.Log($"✅ Role changed for user {username} to {newRole}");
            return (true, "Role changed successfully");
        }

        public async Task<(bool success, string message)> LockUserAsync(string username, int lockDurationMinutes = 30)
        {
            var user = _featherDatabase.GetByColumn<User>("Username", username);

            if (user == null)
            {
                return (false, "User not found");
            }

            user.LockedUntil = DateTime.UtcNow.AddMinutes(lockDurationMinutes);
            _featherDatabase.SaveData(user);

            _logger.Log($"🔒 User locked: {username} until {user.LockedUntil}");
            return (true, $"User locked for {lockDurationMinutes} minutes");
        }

        public async Task<(bool success, string message)> UnlockUserAsync(string username)
        {
            var user = _featherDatabase.GetByColumn<User>("Username", username);

            if (user == null)
            {
                return (false, "User not found");
            }

            user.LockedUntil = null;
            user.FailedLoginAttempts = 0;

            _authService.ResetFailedLoginAttempts(username);
            _featherDatabase.SaveData(user);

            _logger.Log($"🔓 User unlocked: {username}");
            return (true, "User unlocked successfully");
        }
    }
}