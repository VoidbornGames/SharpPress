using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using SharpPress.Services;

namespace SharpPress.Models
{
    public class PluginSecurityOptions
    {
        public string DefaultMode { get; set; } = "Deny";
        public List<ServicePolicyEntry> Policies { get; set; } = new();
    }

    public class ServicePolicyEntry
    {
        public string ServiceType { get; set; } = "";
        public int RequiredPermission { get; set; }
    }
    public interface IManualServer
    {
        Task Start();
        Task StopAsync();
    }

    public class MarketPlugin
    {
        public string Name { get; set; } = "plugin";
        public string Description { get; set; } = "description";
        public string DownloadLink { get; set; } = "";
        public bool isPackaged = false;
    }

    public class Data
    {
        public int protocolv { get; set; } = 1;
        public string command { get; set; } = "";
        public string jsond { get; set; } = "";
    }

    public class User : FeatherData
    {
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string Email { get; set; } = "";
        public Guid uuid { get; set; }
        public string Role { get; set; } = "player";
        public bool TwoFactorEnabled { get; set; } = false;
        public string TwoFactorSecret { get; set; } = "";
        public DateTime LastLogin { get; set; } = DateTime.UtcNow;
        public int FailedLoginAttempts { get; set; } = 0;
        public DateTime? LockedUntil { get; set; }
        public string RefreshToken { get; set; } = "";
        public DateTime RefreshTokenExpiry { get; set; } = DateTime.UtcNow.AddDays(7);
        public string PasswordResetToken { get; set; }
        public DateTime PasswordResetTokenExpiry { get; set; }
    }

    public class FeatherData
    {
        public int Id { get; set; }
    }

    public class ServerConfig
    {
        public bool DebugMode { get; set; } = false;
        public string JwtSecret { get; set; } = "your-super-secret-jwt-key-change-this-in-production-32-chars-min";
        public string PanelDomain { get; set; } = "example.com";
        public int MaxFailedLoginAttempts { get; set; } = 5;
        public int LockoutDurationMinutes { get; set; } = 3;
        public int JwtExpiryHours { get; set; } = 24;
        public bool EnableCompression { get; set; } = true;
        public bool EnableStaticFileCache { get; set; } = true;
        public int CacheExpiryMinutes { get; set; } = 15;
        public string email_host { get; set; } = "smtp.gmail.com";
        public int email_port { get; set; } = 587;
        public string email_username { get; set; } = "your-smtp-email-username";
        public string email_password { get; set; } = "your-smtp-email-password";
        public bool email_useSsl { get; set; } = false;
    }

    public class LoginRequest
    {
        [Required]
        [StringLength(50, MinimumLength = 3)]
        public string Username { get; set; }

        [Required]
        [StringLength(100, MinimumLength = 6)]
        public string Password { get; set; }

        public bool RememberMe { get; set; } = false;
    }

    public class RegisterRequest
    {
        [Required]
        [StringLength(50, MinimumLength = 3)]
        public string Username { get; set; }

        [Required]
        [StringLength(100, MinimumLength = 8)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$",
            ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, one digit and one special character")]
        public string Password { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        public string Role { get; set; } = "player";
    }

    public class PasswordResetRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }

    public class CreateSiteRequest
    {
        [StringLength(100, MinimumLength = 4)]
        [Required] public string Name { get; set; }

        [Length(50000, 1000)]
        [Required] public int Port { get; set; }
    }

    public class DeleteSiteRequest
    {
        [StringLength(100, MinimumLength = 4)]
        public string Name { get; set; }
    }

    public class ChangePasswordRequest
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Token { get; set; }
        [Required]
        [StringLength(100, MinimumLength = 8)]
        [RegularExpression(@"^(?=.[a-z])(?=.[A-Z])(?=.\d)(?=.[^\da-zA-Z]).{8,}$",
        ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, one digit and one special character")]
        public string NewPassword { get; set; }
    }

    public class RefreshTokenRequest
    {
        [Required]
        public string RefreshToken { get; set; }
    }

    public class ApiResponse<T>
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public T Data { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }


    /// <summary>
    /// Holds all file path and folder constants for the application.
    /// </summary>
    public class FilePaths
    {
        public string ConfigFile { get; set; } = "config.json";
        public string UsersFile { get; set; } = "users.json";
        public string VideosFolder { get; set; } = "videos";
        public string LogsFolder { get; set; } = "logs";
    }


    /// <summary>
    /// Holds all startup settings for the server, such as port numbers.
    /// </summary>
    public class ServerSettings
    {
        public int httpPort { get; set; }
        public int sftpPort { get; set; }
    }

    public interface IServerTemplate
    {
        [Required] public string Name { get; set; }
        [Required] public string Version { get; set; }
        [Required] public string ServerFilesDownloadLink { get; set; }
        [Required] [Length(1000, 60000)] public int[] AllowedPorts { get; set; }
        [Required] public int MaxRamMB { get; set; }
        [Required] public string ServerPath { get; set; }
        [Required] public Process Process { get; set; }


        Task<string> GetConsoleOutput();
        Task DownloadServerFiles();
        Task InstallServerFiles();
        Task RunServer();
        Task StopServer();
        Task UninstallServer();
    }

    /// <summary>
    /// Base exception for all MiniDB related errors.
    /// </summary>
    public class MiniDBException : Exception
    {
        public MiniDBException(string message) : base(message) { }
        public MiniDBException(string message, Exception innerException) : base(message, innerException) { }
    }

    /// <summary>
    /// Thrown when a requested key is not found in the database.
    /// </summary>
    public class MiniDBKeyNotFoundException : MiniDBException
    {
        public MiniDBKeyNotFoundException(string key) : base($"The key '{key}' was not found in the database.") { }
    }

    /// <summary>
    /// Thrown when there is a type mismatch between the requested type and the stored object's type.
    /// </summary>
    public class MiniDBTypeMismatchException : MiniDBException
    {
        public MiniDBTypeMismatchException(string key, Type requestedType, Type actualType)
            : base($"Type mismatch for key '{key}'. Requested type: {requestedType.Name}, Actual type: {actualType.Name}.") { }
    }

    public class StopProcessRequest
    {
        public string ProcessName { get; set; }
    }
}
