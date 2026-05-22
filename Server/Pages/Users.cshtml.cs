using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SharpPress.Models;
using SharpPress.Services;

namespace SharpPress.Pages
{
    public class UsersModel : PageModel
    {
        private readonly UserService _userService;
        private readonly FeatherDatabase _database;
        private readonly Logger _logger;

        public UsersModel(UserService userService, FeatherDatabase database, Logger logger)
        {
            _userService = userService;
            _database = database;
            _logger = logger;
        }

        [BindProperty(SupportsGet = true)]
        public string? SearchQuery { get; set; }

        public async Task<IActionResult> OnGet()
        {
            var user = await _userService.GetUserAsync(User);
            if (user == null || !user.HasRole(UserRole.Admin))
                return RedirectToPage("/Login");

            return Page();
        }

        public async Task<IActionResult> OnGetViewUser(string uuid)
        {
            var admin = await _userService.GetUserAsync(User);
            if (admin == null || !admin.HasRole(UserRole.Admin))
                return Forbid();

            var user = await _database.GetByLinq<User>(u => u.UUID == uuid);
            if (user == null)
                return NotFound();

            return new JsonResult(new
            {
                id = user.Id,
                username = user.Username,
                email = user.Email,
                uuid = user.UUID,
                roles = user.Roles.ToString(),
                isActive = user.IsActive,
                isVerified = user.IsVerified,
                twoFactorEnabled = user.TwoFactorEnabled,
                lastActive = user.LastActive,
                lastLogin = user.LastLogin,
                failedLoginAttempts = user.FailedLoginAttempts,
                isLocked = user.LockedUntil.HasValue && user.LockedUntil > DateTime.UtcNow
            });
        }

        public async Task<IActionResult> OnPostBanUser([FromForm] string uuid)
        {
            var admin = await _userService.GetUserAsync(User);
            if (admin == null || !admin.HasRole(UserRole.Admin))
                return Forbid();

            var user = await _database.GetByLinq<User>(u => u.UUID == uuid);
            if (user == null)
                return NotFound();

            if (user.HasRole(UserRole.Admin))
                return new JsonResult(new { success = false, message = "Cannot ban admin users" });

            user.Roles = UserRole.Banned;
            user.UpdatedAt = DateTime.UtcNow;

            await _database.SaveData(user);
            _logger.Log($"User '{user.Username}' (UUID: {user.UUID}) was banned by {admin.Username}");

            return new JsonResult(new { success = true, message = $"User {user.Username} has been banned" });
        }

        public async Task<IActionResult> OnPostUnbanUser([FromForm] string uuid)
        {
            var admin = await _userService.GetUserAsync(User);
            if (admin == null || !admin.HasRole(UserRole.Admin))
                return Forbid();

            var user = await _database.GetByLinq<User>(u => u.UUID == uuid);
            if (user == null)
                return NotFound();

            user.Roles = UserRole.User;
            user.UpdatedAt = DateTime.UtcNow;

            await _database.SaveData(user);
            _logger.Log($"User '{user.Username}' (UUID: {user.UUID}) was unbanned by {admin.Username}");

            return new JsonResult(new { success = true, message = $"User {user.Username} has been unbanned" });
        }

        public async Task<IActionResult> OnPostLockUser([FromForm] string uuid, [FromForm] int minutes = 60)
        {
            var admin = await _userService.GetUserAsync(User);
            if (admin == null || !admin.HasRole(UserRole.Admin))
                return Forbid();

            var user = await _database.GetByLinq<User>(u => u.UUID == uuid);
            if (user == null)
                return NotFound();

            user.LockedUntil = DateTime.UtcNow.AddMinutes(minutes);
            user.UpdatedAt = DateTime.UtcNow;

            await _database.SaveData(user);
            _logger.Log($"User '{user.Username}' (UUID: {user.UUID}) was locked for {minutes} minutes by {admin.Username}");

            return new JsonResult(new { success = true, message = $"User {user.Username} locked for {minutes} minutes" });
        }

        public async Task<IActionResult> OnPostUnlockUser([FromForm] string uuid)
        {
            var admin = await _userService.GetUserAsync(User);
            if (admin == null || !admin.HasRole(UserRole.Admin))
                return Forbid();

            var user = await _database.GetByLinq<User>(u => u.UUID == uuid);
            if (user == null)
                return NotFound();

            user.LockedUntil = null;
            user.FailedLoginAttempts = 0;
            user.UpdatedAt = DateTime.UtcNow;

            await _database.SaveData(user);
            _logger.Log($"User '{user.Username}' (UUID: {user.UUID}) was unlocked by {admin.Username}");

            return new JsonResult(new { success = true, message = $"User {user.Username} has been unlocked" });
        }

        public async Task<IActionResult> OnPostChangeRole([FromForm] string uuid, [FromForm] UserRole newRole)
        {
            var admin = await _userService.GetUserAsync(User);
            if (admin == null || !admin.HasRole(UserRole.Admin))
                return Forbid();

            var user = await _database.GetByLinq<User>(u => u.UUID == uuid);
            if (user == null)
                return NotFound();

            var oldRole = user.Roles;
            user.Roles = newRole;
            user.UpdatedAt = DateTime.UtcNow;

            await _database.SaveData(user);
            _logger.Log($"User '{user.Username}' (UUID: {user.UUID}) role changed from {oldRole} to {newRole} by {admin.Username}");

            return new JsonResult(new { success = true, message = $"User role changed to {newRole}" });
        }

        public async Task<IActionResult> OnPostResetPassword([FromForm] string uuid)
        {
            var admin = await _userService.GetUserAsync(User);
            if (admin == null || !admin.HasRole(UserRole.Admin))
                return Forbid();

            var user = await _database.GetByLinq<User>(u => u.UUID == uuid);
            if (user == null)
                return NotFound();

            user.PasswordResetToken = Guid.NewGuid().ToString();
            user.PasswordResetTokenExpiry = DateTime.UtcNow.AddHours(24);
            user.UpdatedAt = DateTime.UtcNow;

            await _database.SaveData(user);
            _logger.Log($"Password reset initiated for user '{user.Username}' (UUID: {user.UUID}) by {admin.Username}");

            return new JsonResult(new
            {
                success = true,
                message = $"Password reset link generated for {user.Username}",
                resetToken = user.PasswordResetToken
            });
        }

        public async Task<IActionResult> OnPostDisable2FA([FromForm] string uuid)
        {
            var admin = await _userService.GetUserAsync(User);
            if (admin == null || !admin.HasRole(UserRole.Admin))
                return Forbid();

            var user = await _database.GetByLinq<User>(u => u.UUID == uuid);
            if (user == null)
                return NotFound();

            user.TwoFactorEnabled = false;
            user.TwoFactorSecret = "";
            user.UpdatedAt = DateTime.UtcNow;

            await _database.SaveData(user);
            _logger.Log($"2FA disabled for user '{user.Username}' (UUID: {user.UUID}) by {admin.Username}");

            return new JsonResult(new { success = true, message = $"2FA disabled for {user.Username}" });
        }

        public async Task<IActionResult> OnPostDeleteUser([FromForm] string uuid)
        {
            var admin = await _userService.GetUserAsync(User);
            if (admin == null || !admin.HasRole(UserRole.Admin))
                return Forbid();

            var user = await _database.GetByLinq<User>(u => u.UUID == uuid);
            if (user == null)
                return NotFound();

            if (user.HasRole(UserRole.Admin))
                return new JsonResult(new { success = false, message = "Cannot delete admin users" });

            var username = user.Username;
            await _database.Delete<User>(user.Id);
            _logger.Log($"User '{username}' (UUID: {user.UUID}) was deleted by {admin.Username}");

            return new JsonResult(new { success = true, message = $"User {username} has been deleted" });
        }
    }
}