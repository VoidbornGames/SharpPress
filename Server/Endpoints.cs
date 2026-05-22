using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.StaticFiles;
using Newtonsoft.Json;
using SharpPress.Helpers;
using SharpPress.Models;
using SharpPress.Services;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SharpPress
{
    public static class Endpoints
    {
        public static bool disableDefaultLoginRoute = false;
        public static bool disableDefaultRegisterRoute = false;


        private static readonly ConcurrentDictionary<string, CachedFile> _fileCache = new();
        private static readonly ConcurrentDictionary<string, int> _readCounts = new();
        private static readonly ConcurrentDictionary<string, SemaphoreSlim> _fileLocks = new();
        private static readonly FileExtensionContentTypeProvider _contentTypeProvider = new();
        private static readonly object _cacheLock = new object();

        private static readonly HashSet<string> _compressibleTypes = new(StringComparer.OrdinalIgnoreCase)
        {
            "text/html", "text/css", "text/javascript", "application/javascript",
            "application/json", "application/xml", "text/xml", "text/plain",
            "image/svg+xml", "application/x-javascript"
        };

        private static readonly HashSet<string> _cacheableExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".html",".htm",".php",".phtm", ".css", ".js", ".json", ".svg", ".xml", ".txt",
            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot"
        };

        private static readonly IPAddress[] TrustedProxies =
        {
            IPAddress.Loopback,
            IPAddress.IPv6Loopback
        };

        private static bool _cacheEnabled = true;
        private const int CACHE_THRESHOLD_READS = 5;
        private const int MAX_CACHE_SIZE_MB = 1024;
        private const long MAX_FILE_SIZE_FOR_CACHE = 12 * 1024 * 1024;
        private const long MAX_REQUEST_BODY_SIZE = 50 * 1024 * 1024;
        private static long _currentCacheSize = 0;
        private static double _lastCpuUsage = 0;
        private static string _phpExecutablePath = "php";
        private static bool allowRegisters = true;
        private static bool _isShuttingDown = false;


        static Endpoints()
        {
            var phpPath = Environment.GetEnvironmentVariable("PHP_EXECUTABLE_PATH");
            if (!string.IsNullOrEmpty(phpPath) && File.Exists(phpPath))
            {
                _phpExecutablePath = phpPath;
            }
            else
            {
                var commonPaths = new[]
                {
                    "/usr/local/bin/php",
                    "/usr/bin/php",
                    "/bin/php",
                    "C:\\php\\php.exe",
                    "C:\\xampp\\php\\php.exe",
                    "C:\\wamp64\\bin\\php\\php8.2.0\\php.exe",
                    "C:\\wamp\\bin\\php\\php5.6.40\\php.exe"
                };

                foreach (var path in commonPaths)
                {
                    if (File.Exists(path))
                    {
                        _phpExecutablePath = path;
                        break;
                    }
                }
            }

            _ = Task.Run(async () =>
            {
                try
                {
                    var proc = Process.GetCurrentProcess();
                    TimeSpan prevCpu = proc.TotalProcessorTime;
                    DateTime prevTime = DateTime.UtcNow;

                    while (!_isShuttingDown)
                    {
                        await Task.Delay(1000);

                        if (_isShuttingDown) break;

                        TimeSpan currCpu = proc.TotalProcessorTime;
                        DateTime currTime = DateTime.UtcNow;

                        double cpuUsedMs = (currCpu - prevCpu).TotalMilliseconds;
                        double elapsedMs = (currTime - prevTime).TotalMilliseconds;
                        int cores = Environment.ProcessorCount;

                        if (elapsedMs > 0 && cores > 0)
                        {
                            _lastCpuUsage = Math.Round(cpuUsedMs / (elapsedMs * cores) * 100, 2);
                        }

                        prevCpu = currCpu;
                        prevTime = currTime;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Critical Error] CPU Monitor crashed: {ex.Message}");
                }
            });

            _ = Task.Run(async () =>
            {
                try
                {
                    while (!_isShuttingDown)
                    {
                        await Task.Delay(TimeSpan.FromSeconds(60));
                        if (_isShuttingDown) break;
                        _readCounts.Clear();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Critical Error] ReadCounts Cleaner crashed: {ex.Message}");
                }
            });

            _ = Task.Run(async () =>
            {
                try
                {
                    while (!_isShuttingDown)
                    {
                        await Task.Delay(TimeSpan.FromMinutes(30));
                        if (_isShuttingDown) break;
                        ClearCache();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Critical Error] Cache Cleaner crashed: {ex.Message}");
                }
            });
        }

        public static void Map(WebApplication app, PluginManager pluginManager)
        {
            app.Use(async (context, next) =>
            {
                AddSecurityHeaders(context);
                await next();
            });

            bool ValidateAdmin(HttpRequest request, AuthenticationService authService)
            {
                string authHeader = request.Headers["Authorization"].ToString();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ")) return false;
                string token = authHeader.Substring("Bearer ".Length);
                return authService.ValidateJwtToken(token) && authService.GetRoleFromToken(token).ToLower() == "admin";
            }

            //app.MapGet("/health", () => Results.Ok(new { status = "Healthy", timestamp = DateTime.UtcNow }));

            if (disableDefaultLoginRoute == false)
            {
                app.MapPost("/api/login", async (
                    HttpContext context,
                    [FromBody] LoginRequest loginRequest,
                    UserService userService,
                    AuthenticationService authService,
                    Logger logger) =>
                {
                    if (loginRequest == null) return Results.BadRequest(new { success = false, message = "Invalid request" });

                    var (user, message) = await userService.AuthenticateUserAsync(loginRequest);
                    if (user != null)
                    {
                        var token = authService.GenerateJwtToken(user);
                        logger.Log($"✅ User logged in: {user.Username} | IP: {ResolveClientIp(context.Request)}");
                        return Results.Ok(new
                        {
                            success = true,
                            token,
                            refreshToken = user.RefreshToken,
                            user = new { username = user.Username, role = user.Roles, email = user.Email }
                        });
                    }
                    return Results.Unauthorized();
                });
            }

            if (disableDefaultRegisterRoute == false)
            {
                app.MapPost("/api/register", async (
                    HttpContext context,
                    [FromBody] RegisterRequest registerRequest,
                    UserService userService,
                    AuthenticationService authService,
                    Logger logger) =>
                {
                    if (registerRequest == null) return Results.BadRequest(new { success = false, message = "Invalid request" });
                    if (!allowRegisters) return Results.BadRequest(new { success = false, message = "Registration is disabled" });

                    var (user, message) = await userService.CreateUserAsync(registerRequest);
                    if (user != null)
                    {
                        var token = authService.GenerateJwtToken(user);
                        logger.Log($"✅ User registered: {user.Username} | IP: {ResolveClientIp(context.Request)}");
                        return Results.Ok(new
                        {
                            success = true,
                            token,
                            refreshToken = user.RefreshToken,
                            user = new { username = user.Username, role = user.Roles, email = user.Email }
                        });
                    }
                    return Results.BadRequest(new { success = false, message });
                });
            }

            app.MapGet("/api/plugins", (
                HttpRequest request,
                [FromServices] AuthenticationService authService) =>
            {
        
                if (!ValidateAdmin(request, authService)) return Results.Unauthorized();

                var plugins = pluginManager.GetLoadedPlugins();
                var pluginList = plugins.Select(p => new
                {
                    id = p.Key,
                    name = p.Value.Name,
                    version = p.Value.Version,
                    enabled = true
                }).ToList();

                return Results.Ok(new { success = true, plugins = pluginList });
            });

            app.MapPost("/api/plugins/upload", async (
                HttpRequest request,
                PackageManager packageManager,
                Logger logger,
                [FromServices] AuthenticationService authService) =>
            {
                if (!ValidateAdmin(request, authService)) return Results.Unauthorized();

                if (!request.HasFormContentType) return Results.BadRequest(new { success = false, message = "Invalid content type" });

                var form = await request.ReadFormAsync();
                var file = form.Files["file"];

                if (file == null || file.Length == 0) return Results.BadRequest(new { success = false, message = "No file uploaded" });

                string pluginsDirectory = Path.Combine(AppContext.BaseDirectory, "plugins");
                Directory.CreateDirectory(pluginsDirectory);

                string safeFileName = Path.GetFileName(file.FileName);
                if (string.IsNullOrEmpty(safeFileName)) return Results.BadRequest(new { success = false, message = "Invalid file name" });

                if (safeFileName.StartsWith(".") || safeFileName.Contains(".."))
                    return Results.BadRequest(new { success = false, message = "Invalid file name" });

                string tempFilePath = Path.Combine(pluginsDirectory, $"{safeFileName}.tmp");
                string finalFilePath = Path.Combine(pluginsDirectory, safeFileName);

                try
                {
                    logger.Log("📤 Receiving plugin file...");
                    using (var stream = new FileStream(tempFilePath, FileMode.Create))
                    {
                        await file.CopyToAsync(stream);
                    }

                    if (Path.GetExtension(safeFileName) == ".dll")
                    {
                        await pluginManager.UnloadAllPluginsAsync();

                        if (File.Exists(finalFilePath))
                        {
                            try { File.Delete(finalFilePath); }
                            catch (IOException ioEx)
                            {
                                logger.LogError($"Could not delete old plugin (locked?): {ioEx.Message}. Overwriting may fail or require restart.");
                            }
                        }

                        if (File.Exists(finalFilePath)) File.Delete(finalFilePath);
                        File.Move(tempFilePath, finalFilePath);
                        tempFilePath = null;

                        await pluginManager.LoadPluginsAsync();
                    }
                    else if (Path.GetExtension(safeFileName) == ".pkg")
                    {
                        var package = await packageManager.GetPackageFromByteArray(await File.ReadAllBytesAsync(tempFilePath));
                        if (package != null)
                            await packageManager.InstallPackage(package);
                        else
                            return Results.BadRequest(new { success = false, message = "Invalid package" });
                    }
                    else
                    {
                        return Results.BadRequest(new { success = false, message = "Unsupported file type." });
                    }

                    logger.Log("✅ Plugin upload and reload complete.");
                    return Results.Ok(new { success = true, message = "Plugin uploaded and reloaded successfully." });
                }
                catch (Exception ex)
                {
                    logger.LogError($"Error uploading plugin: {ex.Message}");
                    return Results.StatusCode(500);
                }
                finally
                {
                    if (tempFilePath != null && File.Exists(tempFilePath))
                    {
                        try { File.Delete(tempFilePath); }
                        catch { }
                    }
                }
            });

            app.MapPost("/api/plugins/reload", async (
                HttpRequest request,
                [FromServices] AuthenticationService authService) =>
            {
                if (!ValidateAdmin(request, authService)) return Results.Unauthorized();

                await pluginManager.ReloadAllPluginsAsync();
                return Results.Ok(new { success = true, message = "Plugins reloaded successfully." });
            });

            app.MapPost("/api/marketplace/download", async (
                HttpRequest request,
                [FromBody] MarketPlugin downloadRequest,
                [FromServices] AuthenticationService authService) =>
            {
                if (!ValidateAdmin(request, authService)) return Results.Unauthorized();

                if (downloadRequest == null || string.IsNullOrWhiteSpace(downloadRequest.DownloadLink) || string.IsNullOrWhiteSpace(downloadRequest.Name))
                {
                    return Results.BadRequest(new { success = false, message = "Request body must contain a valid 'DownloadLink' and 'Name' property." });
                }

                if (!IsSafeUrl(downloadRequest.DownloadLink))
                {
                    return Results.BadRequest(new { success = false, message = "Invalid or forbidden download URL." });
                }

                var downloadJobProcessor = request.HttpContext.RequestServices.GetRequiredService<DownloadJobProcessor>();
                downloadJobProcessor.EnqueueJob(downloadRequest);

                return Results.Accepted(null, new { success = true, message = $"Download request for '{downloadRequest.Name}.dll' has been queued and will be processed." });
            });

            app.MapGet("/videos/{filename}", async (HttpRequest request, string filename, [FromServices] VideoStreamingService videoService, [FromServices] AuthenticationService authService) =>
            {
                if (!ValidateAdmin(request, authService)) return Results.Unauthorized();

                filename = Path.GetFileName(filename);
                if (string.IsNullOrEmpty(filename)) return Results.BadRequest("Invalid filename.");

                string filePath = videoService.GetVideoFilePath(filename);

                if (filePath == null || !File.Exists(filePath)) return Results.NotFound("Video file not found");

                string contentType = videoService.GetContentType(filePath);
                return Results.File(filePath, contentType, enableRangeProcessing: true);
            });

            app.MapGet("/api/stats", async (HttpRequest request, HttpResponse response, UserService userService, [FromServices] AuthenticationService authService) =>
            {
                if (!ValidateAdmin(request, authService)) return Results.Unauthorized();
                try
                {
                    var proc = Process.GetCurrentProcess();
                    double cpuUse = _lastCpuUsage;

                    double memUsage = proc.WorkingSet64 / 1024.0 / 1024.0;
                    int pluginsCount = pluginManager.GetLoadedPlugins().Count;

                    double diskUsedGB = 0;
                    double diskTotalGB = 0;
                    long totalBytesSent = 0;
                    long totalBytesReceived = 0;

                    foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                    {
                        if (nic.OperationalStatus == OperationalStatus.Up &&
                            nic.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                            nic.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                        {
                            try
                            {
                                var nicStats = nic.GetIPv4Statistics();
                                totalBytesSent += nicStats.BytesSent;
                                totalBytesReceived += nicStats.BytesReceived;
                            }
                            catch { }
                        }
                    }

                    if (OperatingSystem.IsLinux())
                    {
                        try
                        {
                            string memInfo = File.ReadAllText("/proc/meminfo");
                            string totalLine = memInfo.Split('\n').FirstOrDefault(l => l.StartsWith("MemTotal:"));
                            string freeLine = memInfo.Split('\n').FirstOrDefault(l => l.StartsWith("MemAvailable:"));

                            double totalMem = totalLine != null ? double.Parse(new string(totalLine.Where(char.IsDigit).ToArray())) / 1024.0 : memUsage;
                            double freeMem = freeLine != null ? double.Parse(new string(freeLine.Where(char.IsDigit).ToArray())) / 1024.0 : 0;
                            memUsage = totalMem - freeMem;

                            DriveInfo drive = new DriveInfo("/");
                            long totalSpace = drive.TotalSize;
                            long usedSpace = totalSpace - drive.AvailableFreeSpace;

                            diskUsedGB = usedSpace / (1024.0 * 1024 * 1024);
                            diskTotalGB = totalSpace / (1024.0 * 1024 * 1024);
                        }
                        catch
                        {
                            diskUsedGB = 0; diskTotalGB = 0;
                        }
                    }
                    else if (OperatingSystem.IsWindows())
                    {
                        try
                        {
                            string rootPath = Path.GetPathRoot(AppContext.BaseDirectory);
                            if (!string.IsNullOrEmpty(rootPath))
                            {
                                DriveInfo drive = new DriveInfo(rootPath);
                                long totalSpace = drive.TotalSize;
                                long usedSpace = totalSpace - drive.AvailableFreeSpace;

                                diskUsedGB = usedSpace / (1024.0 * 1024 * 1024);
                                diskTotalGB = totalSpace / (1024.0 * 1024 * 1024);
                            }
                        }
                        catch
                        {
                            diskUsedGB = 0; diskTotalGB = 0;
                        }
                    }

                    object stats = new
                    {
                        cpuUsage = cpuUse,
                        memoryMB = memUsage,
                        diskUsedGB = diskUsedGB,
                        diskTotalGB = diskTotalGB,
                        netSentMB = totalBytesSent / (1024.0 * 1024),
                        netReceivedMB = totalBytesReceived / (1024.0 * 1024),
                        activePlugins = pluginsCount,
                        uptime = (DateTime.Now - Process.GetCurrentProcess().StartTime).ToString(@"hh\:mm\:ss")
                    };

                    return Results.Ok(stats);
                }
                catch (Exception ex)
                {
                    return Results.Problem("An error occurred while fetching stats.");
                }
            });

            app.MapGet("/api/cache/stats", (
                HttpRequest request,
                [FromServices] AuthenticationService authService) =>
            {
                if (!ValidateAdmin(request, authService)) return Results.Unauthorized();

                var stats = GetCacheStats();
                return Results.Ok(stats);
            });

            app.MapPost("/api/cache/clear", (
                HttpRequest request,
                [FromServices] AuthenticationService authService,
                Logger logger) =>
            {
                if (!ValidateAdmin(request, authService)) return Results.Unauthorized();

                ClearCache();
                logger.Log("🗑️ Cache cleared by admin.");
                return Results.Ok(new { success = true, message = "Cache cleared successfully." });
            });

            app.MapGet("/api/settings", async (
                HttpRequest request,
                [FromServices] AuthenticationService authService,
                [FromServices] ConfigManager configManager) =>
            {
                if (!ValidateAdmin(request, authService)) return Results.Unauthorized();

                var defaultSettings = new SiteSettings
                {
                    General = new GeneralSettings
                    {
                        SiteName = "SharpPress Site",
                        SiteDescription = "Welcome to my site",
                        AdminEmail = "admin@example.com",
                        Timezone = "UTC",
                        FooterText = "2023 © My Company"
                    },
                    Security = new SecuritySettings
                    {
                        ForceHttps = false,
                        AllowRegistration = true,
                        Require2FA = false,
                        SessionTimeout = 60
                    },
                    Advanced = new AdvancedSettings
                    {
                        EnableCache = true,
                        MaintenanceMode = false,
                        CustomCss = ""
                    }
                };

                if (configManager.Config.SiteSettings != null)
                    defaultSettings = configManager.Config.SiteSettings;

                return Results.Ok(defaultSettings);
            });

            app.MapPost("/api/settings", async (
                HttpRequest request,
                [FromBody] SiteSettings settings,
                [FromServices] AuthenticationService authService,
                [FromServices] ConfigManager configManager,
                Logger logger) =>
            {
                if (!ValidateAdmin(request, authService)) return Results.Unauthorized();

                if (settings == null) return Results.BadRequest(new { success = false, message = "Invalid settings data" });

                try
                {
                    configManager.Config.SiteSettings = settings;
                    if (configManager.Config.SiteSettings.Advanced != null)
                        SetCacheEnabled(configManager.Config.SiteSettings.Advanced.EnableCache);

                    await configManager.SaveConfig();

                    logger.Log($"⚙️ Settings updated by admin.");
                    return Results.Ok(new { success = true, message = "Settings saved successfully." });
                }
                catch (Exception ex)
                {
                    logger.LogError($"Error saving settings: {ex.Message}");
                    return Results.Problem("An error occurred while saving settings.");
                }
            });

            app.MapFallback("{*path}", async (HttpContext context, Logger logger) =>
            {
                var rootPath = Path.Combine(AppContext.BaseDirectory, "public_html");
                if (!Directory.Exists(rootPath))
                {
                    Directory.CreateDirectory(rootPath);
                }

                var requestPath = context.Request.Path.Value?.TrimStart('/');
                if (string.IsNullOrEmpty(requestPath))
                {
                    requestPath = "index.php";
                    var phpIndexPath = Path.Combine(rootPath, "index.php");
                    if (!File.Exists(phpIndexPath))
                    {
                        requestPath = "index.html";
                    }
                }

                requestPath = requestPath.TrimEnd('/');

                var filePath = Path.Combine(rootPath, requestPath);

                if (await ServeFile(context, filePath, requestPath))
                {
                    return;
                }

                if (!Path.HasExtension(requestPath))
                {
                    var phpPath = filePath + ".php";
                    if (await ServeFile(context, phpPath, requestPath + ".php"))
                    {
                        return;
                    }

                    var htmlPath = filePath + ".html";
                    if (await ServeFile(context, htmlPath, requestPath + ".html"))
                    {
                        return;
                    }
                }

                if (!Path.HasExtension(requestPath))
                {
                    var indexPhpPath = Path.Combine(filePath, "index.php");
                    if (await ServeFile(context, indexPhpPath, requestPath + "/index.php"))
                    {
                        return;
                    }

                    var indexPath = Path.Combine(filePath, "index.html");
                    if (await ServeFile(context, indexPath, requestPath + "/index.html"))
                    {
                        return;
                    }
                }

                if (!Path.HasExtension(requestPath) && !requestPath.StartsWith("api/"))
                {
                    var spaIndexPath = Path.Combine(rootPath, "index.php");
                    if (File.Exists(spaIndexPath))
                    {
                        if (await ServeFile(context, spaIndexPath, "index.php"))
                        {
                            return;
                        }
                    }

                    spaIndexPath = Path.Combine(rootPath, "index.html");
                    if (File.Exists(spaIndexPath))
                    {
                        if (await ServeFile(context, spaIndexPath, "index.html"))
                        {
                            return;
                        }
                    }
                }

                logger.LogWarning($"[StaticHandler] 404 Not Found: {requestPath}");
                await Serve404Page(context, rootPath);
            });
        }

        private static bool IsSafeUrl(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                return false;

            if (uri.Scheme != "http" && uri.Scheme != "https")
                return false;

            var host = uri.Host;

            if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) || host == "127.0.0.1" || host == "::1")
                return false;

            try
            {
                var ipAddresses = Dns.GetHostAddresses(host);
                foreach (var ip in ipAddresses)
                {
                    if (IPAddress.IsLoopback(ip)) return false;
                    if (ip.IsIPv6LinkLocal) return false;

                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        var bytes = ip.GetAddressBytes();
                        if (bytes[0] == 10) return false;
                        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return false;
                        if (bytes[0] == 192 && bytes[1] == 168) return false;
                    }
                }
            }
            catch
            {
                return false;
            }

            return true;
        }

        private static async Task Serve404Page(HttpContext context, string rootPath)
        {
            context.Response.StatusCode = 404;
            context.Response.ContentType = "text/html; charset=utf-8";

            var custom404Path = Path.Combine(rootPath, "404.html");
            if (File.Exists(custom404Path))
            {
                var content = await File.ReadAllTextAsync(custom404Path);
                await context.Response.WriteAsync(content);
                return;
            }

            var custom404PhpPath = Path.Combine(rootPath, "404.php");
            if (File.Exists(custom404PhpPath))
            {
                await ExecutePhpFile(context, custom404PhpPath);
                return;
            }

            await context.Response.WriteAsync(@"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>404 - Page Not Found</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
        }
        .container {
            text-align: center;
            padding: 2rem;
        }
        h1 {
            font-size: 8rem;
            font-weight: 700;
            margin-bottom: 1rem;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        h2 {
            font-size: 2rem;
            font-weight: 400;
            margin-bottom: 1rem;
        }
        p {
            font-size: 1.2rem;
            opacity: 0.9;
            margin-bottom: 2rem;
        }
        a {
            display: inline-block;
            padding: 1rem 2rem;
            background: white;
            color: #667eea;
            text-decoration: none;
            border-radius: 50px;
            font-weight: 600;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        a:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.3);
        }
        .footer {
            margin-top: 3rem;
            opacity: 0.7;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class='container'>
        <h1>404</h1>
        <h2>Page Not Found</h2>
        <p>The page you're looking for doesn't exist or has been moved.</p>
        <a href='/'>Go Home</a>
        <div class='footer'>
            <p>SharpPress</p>
        </div>
    </div>
</body>
</html>");
        }

        private static async Task<bool> ServeFile(HttpContext context, string filePath, string relativePath)
        {
            if (!File.Exists(filePath))
                return false;

            var fileInfo = new FileInfo(filePath);
            string resolvedPath = filePath;

            try
            {
                if (fileInfo.Exists)
                {
                    var linkTarget = fileInfo.ResolveLinkTarget(true);
                    if (linkTarget != null)
                    {
                        resolvedPath = linkTarget.FullName;
                    }
                }
            }
            catch
            {
                context.Response.StatusCode = 403;
                return true;
            }

            var fullPath = Path.GetFullPath(resolvedPath);
            var rootPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "public_html"));

            if (!fullPath.StartsWith(rootPath, StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = 403;
                return true;
            }

            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            if (extension == ".php")
            {
                return await ExecutePhpFile(context, filePath);
            }

            var lastModified = fileInfo.LastWriteTimeUtc;
            var fileSize = fileInfo.Length;

            if (!_contentTypeProvider.TryGetContentType(filePath, out var contentType))
                contentType = "application/octet-stream";

            context.Response.ContentType = contentType;

            var etag = GenerateETag(filePath, lastModified, fileSize);
            context.Response.Headers["ETag"] = etag;

            var requestETag = context.Request.Headers["If-None-Match"].ToString();
            if (!string.IsNullOrEmpty(requestETag) && requestETag == etag)
            {
                context.Response.StatusCode = 304;
                return true;
            }

            var ifModifiedSince = context.Request.Headers["If-Modified-Since"].ToString();
            if (!string.IsNullOrEmpty(ifModifiedSince) &&
                DateTime.TryParse(ifModifiedSince, out var modifiedSince))
            {
                if (lastModified <= modifiedSince.ToUniversalTime())
                {
                    context.Response.StatusCode = 304;
                    return true;
                }
            }

            SetCacheHeaders(context, Path.GetExtension(filePath));

            context.Response.Headers["Last-Modified"] = lastModified.ToString("R");

            var acceptEncoding = context.Request.Headers["Accept-Encoding"].ToString();
            var supportsGzip = acceptEncoding.Contains("gzip", StringComparison.OrdinalIgnoreCase);
            var supportsBrotli = acceptEncoding.Contains("br", StringComparison.OrdinalIgnoreCase);

            if (_cacheEnabled && _fileCache.TryGetValue(relativePath, out var cachedFile))
            {
                if (cachedFile.LastModified == lastModified)
                {
                    return await ServeCachedFile(context, cachedFile, supportsBrotli, supportsGzip);
                }
                else
                {
                    RemoveFromCache(relativePath, cachedFile.OriginalSize);
                }
            }

            var readCount = _readCounts.AddOrUpdate(relativePath, 1, (k, v) => v + 1);

            return await ServeAndCacheFile(context, filePath, relativePath, fileSize, lastModified,
                contentType, readCount, supportsBrotli, supportsGzip);
        }

        private static async Task<bool> ExecutePhpFile(HttpContext context, string filePath)
        {
            try
            {
                var request = context.Request;
                var response = context.Response;

                if (request.ContentLength > MAX_REQUEST_BODY_SIZE)
                {
                    response.StatusCode = 413;
                    response.ContentType = "text/html; charset=utf-8";
                    await response.WriteAsync("<html><body><h1>Payload Too Large</h1></body></html>");
                    return true;
                }

                var envVars = new Dictionary<string, string>
                {
                    { "REQUEST_METHOD", request.Method },
                    { "REQUEST_URI", request.Path.Value ?? "/" },
                    { "SCRIPT_NAME", request.Path.Value ?? "/" },
                    { "SCRIPT_FILENAME", filePath },
                    { "DOCUMENT_ROOT", Path.Combine(AppContext.BaseDirectory, "public_html") },
                    { "SERVER_PROTOCOL", "HTTP/1.1" },
                    { "SERVER_SOFTWARE", "SharpPress" },
                    { "SERVER_NAME", request.Host.Host },
                    { "SERVER_PORT", request.Host.Port?.ToString() ?? "80" },
                    { "QUERY_STRING", request.QueryString.Value?.TrimStart('?') ?? "" },
                    { "REMOTE_ADDR", context.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1" },
                    { "CONTENT_TYPE", request.ContentType ?? "" },
                    { "CONTENT_LENGTH", request.ContentLength?.ToString() ?? "0" },
                    { "HTTPS", request.IsHttps ? "on" : "off" },
                    { "HTTP_HOST", request.Host.Value },
                    { "HTTP_USER_AGENT", request.Headers["User-Agent"].ToString() },
                    { "HTTP_ACCEPT", request.Headers["Accept"].ToString() },
                    { "HTTP_ACCEPT_LANGUAGE", request.Headers["Accept-Language"].ToString() },
                    { "HTTP_ACCEPT_ENCODING", request.Headers["Accept-Encoding"].ToString() },
                    { "HTTP_COOKIE", request.Headers["Cookie"].ToString() },
                    { "HTTP_REFERER", request.Headers["Referer"].ToString() },
                    { "HTTP_X_REQUESTED_WITH", request.Headers["X-Requested-With"].ToString() },
                    { "HTTP_AUTHORIZATION", request.Headers["Authorization"].ToString() }
                };

                foreach (var header in request.Headers)
                {
                    var key = $"HTTP_{header.Key.ToUpperInvariant().Replace("-", "_")}";
                    if (!envVars.ContainsKey(key))
                    {
                        envVars[key] = header.Value.ToString();
                    }
                }

                string requestBody = null;
                if (request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase) ||
                    request.Method.Equals("PUT", StringComparison.OrdinalIgnoreCase) ||
                    request.Method.Equals("PATCH", StringComparison.OrdinalIgnoreCase))
                {
                    request.EnableBuffering();
                    using (var reader = new StreamReader(request.Body, Encoding.UTF8, true, 1024, true))
                    {
                        requestBody = await reader.ReadToEndAsync();
                    }
                    request.Body.Position = 0;
                }

                var startInfo = new ProcessStartInfo
                {
                    FileName = _phpExecutablePath,
                    Arguments = $"\"{filePath}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    RedirectStandardInput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = Path.GetDirectoryName(filePath)
                };

                foreach (var env in envVars)
                {
                    startInfo.Environment[env.Key] = env.Value;
                }

                using var process = new Process { StartInfo = startInfo };
                var outputBuilder = new StringBuilder();
                var errorBuilder = new StringBuilder();

                process.OutputDataReceived += (sender, e) =>
                {
                    if (e.Data != null)
                        outputBuilder.AppendLine(e.Data);
                };

                process.ErrorDataReceived += (sender, e) =>
                {
                    if (e.Data != null)
                        errorBuilder.AppendLine(e.Data);
                };

                process.Start();

                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                if (!string.IsNullOrEmpty(requestBody))
                {
                    await process.StandardInput.WriteAsync(requestBody);
                    process.StandardInput.Close();
                }

                var timeoutTask = Task.Delay(TimeSpan.FromSeconds(30));
                var processTask = process.WaitForExitAsync();

                if (await Task.WhenAny(processTask, timeoutTask) == timeoutTask)
                {
                    try { process.Kill(); } catch { }
                    response.StatusCode = 504;
                    response.ContentType = "text/html; charset=utf-8";
                    await response.WriteAsync("<html><body><h1>Gateway Timeout</h1><p>Script execution timed out.</p></body></html>");
                    return true;
                }

                var output = outputBuilder.ToString();
                var error = errorBuilder.ToString();

                if (process.ExitCode != 0 && !string.IsNullOrEmpty(error))
                {
                    response.StatusCode = 500;
                    response.ContentType = "text/html; charset=utf-8";
                    await response.WriteAsync($"<html><body><h1>Internal Server Error</h1><p>Script error.</p></body></html>");
                    return true;
                }

                var (headers, body) = ParsePhpOutput(output);

                foreach (var header in headers)
                {
                    if (header.StartsWith("Content-Type:", StringComparison.OrdinalIgnoreCase))
                    {
                        response.ContentType = header.Substring("Content-Type:".Length).Trim();
                    }
                    else if (header.StartsWith("Status:", StringComparison.OrdinalIgnoreCase))
                    {
                        var statusPart = header.Substring("Status:".Length).Trim();
                        if (int.TryParse(statusPart.Split(' ')[0], out var statusCode))
                        {
                            response.StatusCode = statusCode;
                        }
                    }
                    else if (header.StartsWith("Location:", StringComparison.OrdinalIgnoreCase))
                    {
                        response.StatusCode = 302;
                        response.Headers["Location"] = header.Substring("Location:".Length).Trim();
                    }
                    else if (header.StartsWith("Set-Cookie:", StringComparison.OrdinalIgnoreCase))
                    {
                        response.Headers.Append("Set-Cookie", header.Substring("Set-Cookie:".Length).Trim());
                    }
                    else if (!string.IsNullOrWhiteSpace(header))
                    {
                        var colonIndex = header.IndexOf(':');
                        if (colonIndex > 0)
                        {
                            var headerName = header.Substring(0, colonIndex).Trim();
                            var headerValue = header.Substring(colonIndex + 1).Trim();
                            response.Headers[headerName] = headerValue;
                        }
                    }
                }

                if (!headers.Any(h => h.StartsWith("Content-Type:", StringComparison.OrdinalIgnoreCase)))
                {
                    response.ContentType = "text/html; charset=utf-8";
                }

                response.Headers["Cache-Control"] = "no-cache, must-revalidate";

                await response.WriteAsync(body);
                return true;
            }
            catch (Exception)
            {
                context.Response.StatusCode = 500;
                context.Response.ContentType = "text/html; charset=utf-8";
                await context.Response.WriteAsync("<html><body><h1>Internal Server Error</h1><p>Failed to execute PHP script.</p></body></html>");
                return true;
            }
        }

        private static (List<string> headers, string body) ParsePhpOutput(string output)
        {
            var headers = new List<string>();
            var bodyStartIndex = output.IndexOf("\r\n\r\n");

            if (bodyStartIndex == -1)
            {
                bodyStartIndex = output.IndexOf("\n\n");
                if (bodyStartIndex == -1)
                {
                    return (headers, output);
                }
                var headerPart = output.Substring(0, bodyStartIndex);
                var body = output.Substring(bodyStartIndex + 2);
                headers = headerPart.Split('\n')
                    .Select(h => h.TrimEnd('\r'))
                    .Where(h => !string.IsNullOrWhiteSpace(h))
                    .ToList();
                return (headers, body);
            }

            var headersPart = output.Substring(0, bodyStartIndex);
            var bodyContent = output.Substring(bodyStartIndex + 4);

            headers = headersPart.Split(new[] { "\r\n" }, StringSplitOptions.None)
                .Where(h => !string.IsNullOrWhiteSpace(h))
                .ToList();

            return (headers, bodyContent);
        }

        private static async Task<bool> ServeCachedFile(HttpContext context, CachedFile cachedFile,
            bool supportsBrotli, bool supportsGzip)
        {
            byte[] dataToSend = cachedFile.OriginalData;
            string encoding = null;

            if (supportsBrotli && cachedFile.BrotliData != null)
            {
                dataToSend = cachedFile.BrotliData;
                encoding = "br";
            }
            else if (supportsGzip && cachedFile.GzipData != null)
            {
                dataToSend = cachedFile.GzipData;
                encoding = "gzip";
            }

            if (encoding != null)
            {
                context.Response.Headers["Content-Encoding"] = encoding;
            }

            context.Response.ContentLength = dataToSend.Length;
            await context.Response.Body.WriteAsync(dataToSend);
            return true;
        }

        private static async Task<bool> ServeAndCacheFile(HttpContext context, string filePath,
            string relativePath, long fileSize, DateTime lastModified, string contentType,
            int readCount, bool supportsBrotli, bool supportsGzip)
        {
            var shouldCompress = _compressibleTypes.Contains(contentType) && fileSize > 1024;
            var shouldCache = _cacheEnabled &&
                              _cacheableExtensions.Contains(Path.GetExtension(filePath)) &&
                              fileSize <= MAX_FILE_SIZE_FOR_CACHE &&
                              readCount >= CACHE_THRESHOLD_READS &&
                              _currentCacheSize < (MAX_CACHE_SIZE_MB * 1024 * 1024);

            if (!shouldCache && !shouldCompress)
            {
                await context.Response.SendFileAsync(filePath);
                return true;
            }

            byte[] fileContent;

            var fileLock = _fileLocks.GetOrAdd(relativePath, _ => new SemaphoreSlim(1, 1));
            await fileLock.WaitAsync();
            try
            {
                if (_cacheEnabled && _fileCache.TryGetValue(relativePath, out var cachedFile) && cachedFile.LastModified == lastModified)
                {
                    return await ServeCachedFile(context, cachedFile, supportsBrotli, supportsGzip);
                }

                fileContent = await File.ReadAllBytesAsync(filePath);

                byte[] dataToSend = fileContent;
                string encoding = null;

                if (shouldCompress)
                {
                    if (supportsBrotli)
                    {
                        var compressed = await CompressBrotli(fileContent);
                        if (compressed.Length < fileContent.Length * 0.9)
                        {
                            dataToSend = compressed;
                            encoding = "br";
                        }
                    }
                    else if (supportsGzip)
                    {
                        var compressed = await CompressGzip(fileContent);
                        if (compressed.Length < fileContent.Length * 0.9)
                        {
                            dataToSend = compressed;
                            encoding = "gzip";
                        }
                    }
                }

                if (encoding != null)
                {
                    context.Response.Headers["Content-Encoding"] = encoding;
                }

                context.Response.ContentLength = dataToSend.Length;
                await context.Response.Body.WriteAsync(dataToSend);

                if (shouldCache)
                {
                    await CacheFile(relativePath, fileContent, lastModified, contentType);
                }
            }
            finally
            {
                fileLock.Release();
            }

            return true;
        }

        private static string ResolveClientIp(HttpRequest request)
        {
            var remote = request.HttpContext.Connection.RemoteIpAddress;
            if (remote != null)
            {
                if (remote.IsIPv4MappedToIPv6)
                    remote = remote.MapToIPv4();

                if (TrustedProxies.Any(p => p.Equals(remote)))
                {
                    var xff = request.Headers["X-Forwarded-For"].FirstOrDefault();
                    if (!string.IsNullOrWhiteSpace(xff))
                        return xff.Split(',')[0].Trim();
                }
                return remote.ToString();
            }
            return "unknown";
        }

        private static async Task CacheFile(string relativePath, byte[] originalData,
            DateTime lastModified, string contentType)
        {
            var cachedFile = new CachedFile
            {
                OriginalData = originalData,
                LastModified = lastModified,
                ContentType = contentType,
                OriginalSize = originalData.Length
            };

            if (_compressibleTypes.Contains(contentType) && originalData.Length > 1024)
            {
                cachedFile.GzipData = await CompressGzip(originalData);
                cachedFile.BrotliData = await CompressBrotli(originalData);
            }

            var totalSize = cachedFile.OriginalSize +
                           (cachedFile.GzipData?.Length ?? 0) +
                           (cachedFile.BrotliData?.Length ?? 0);

            lock (_cacheLock)
            {
                if (_currentCacheSize + totalSize <= (MAX_CACHE_SIZE_MB * 1024 * 1024))
                {
                    if (_fileCache.TryAdd(relativePath, cachedFile))
                    {
                        _currentCacheSize += totalSize;
                    }
                }
            }
        }

        private static void RemoveFromCache(string relativePath, long size)
        {
            if (_fileCache.TryRemove(relativePath, out var removed))
            {
                var totalSize = removed.OriginalSize +
                               (removed.GzipData?.Length ?? 0) +
                               (removed.BrotliData?.Length ?? 0);

                lock (_cacheLock)
                {
                    _currentCacheSize -= totalSize;
                }
            }
        }

        private static async Task<byte[]> CompressGzip(byte[] data)
        {
            using var output = new MemoryStream();
            using (var gzip = new GZipStream(output, CompressionLevel.Optimal))
            {
                await gzip.WriteAsync(data);
            }
            return output.ToArray();
        }

        private static async Task<byte[]> CompressBrotli(byte[] data)
        {
            using var output = new MemoryStream();
            using (var brotli = new BrotliStream(output, CompressionLevel.Optimal))
            {
                await brotli.WriteAsync(data);
            }
            return output.ToArray();
        }

        private static string GenerateETag(string filePath, DateTime lastModified, long fileSize)
        {
            var input = $"{filePath}:{lastModified.Ticks}:{fileSize}";
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
            return $"\"{Convert.ToBase64String(hash).Substring(0, 16)}\"";
        }

        private static void SetCacheHeaders(HttpContext context, string extension)
        {
            var response = context.Response;

            switch (extension.ToLowerInvariant())
            {
                case ".woff":
                case ".woff2":
                case ".ttf":
                case ".eot":
                    response.Headers["Cache-Control"] = "public, max-age=31536000, immutable";
                    break;

                case ".jpg":
                case ".jpeg":
                case ".png":
                case ".gif":
                case ".webp":
                case ".svg":
                case ".ico":
                    response.Headers["Cache-Control"] = "public, max-age=86400";
                    break;

                case ".css":
                case ".js":
                    response.Headers["Cache-Control"] = "public, max-age=3600";
                    break;

                case ".html":
                case ".htm":
                    response.Headers["Cache-Control"] = "no-cache, must-revalidate";
                    break;

                default:
                    response.Headers["Cache-Control"] = "public, max-age=3600";
                    break;
            }
        }

        public static Dictionary<string, object> GetCacheStats()
        {
            return new Dictionary<string, object>
            {
                { "cachedFiles", _fileCache.Count },
                { "cacheSizeMB", Math.Round(_currentCacheSize / (1024.0 * 1024.0), 2) },
                { "maxCacheSizeMB", MAX_CACHE_SIZE_MB },
                { "trackedFiles", _readCounts.Count },
                { "cacheEnabled", _cacheEnabled }
            };
        }

        private class CachedFile
        {
            public byte[] OriginalData { get; set; }
            public byte[]? GzipData { get; set; }
            public byte[]? BrotliData { get; set; }
            public DateTime LastModified { get; set; }
            public string ContentType { get; set; }
            public long OriginalSize { get; set; }
        }

        public static void SignalShutdown() => _isShuttingDown = true;
        public static async Task RegisterServices(ServerConfig serverConfig)
        {
            if (serverConfig.SiteSettings != null && serverConfig.SiteSettings.Security != null)
            {
                allowRegisters = serverConfig.SiteSettings.Security.AllowRegistration;
            }
        }

        public static void SetPhpExecutablePath(string path)
        {
            if (!string.IsNullOrEmpty(path) && File.Exists(path))
            {
                _phpExecutablePath = path;
            }
        }

        public static void SetCacheEnabled(bool enabled)
        {
            _cacheEnabled = enabled;
            if (!enabled)
                ClearCache();
        }

        public static void ClearCache()
        {
            _fileCache.Clear();
            _readCounts.Clear();
            lock (_cacheLock)
            {
                _currentCacheSize = 0;
            }
        }

        private static void AddSecurityHeaders(HttpContext context)
        {
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["X-Frame-Options"] = "DENY";
            context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
        }
    }
}