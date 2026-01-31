using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.StaticFiles;
using Newtonsoft.Json;
using SharpPress.Helpers;
using SharpPress.Models;
using SharpPress.Services;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text;
using System.IO.Compression;
using System.Security.Cryptography;

namespace SharpPress
{
    public static class Endpoints
    {
        private static readonly ConcurrentDictionary<string, CachedFile> _fileCache = new();
        private static readonly ConcurrentDictionary<string, int> _readCounts = new();
        private static readonly FileExtensionContentTypeProvider _contentTypeProvider = new();
        private static readonly HashSet<string> _compressibleTypes = new(StringComparer.OrdinalIgnoreCase)
        {
            "text/html", "text/css", "text/javascript", "application/javascript",
            "application/json", "application/xml", "text/xml", "text/plain",
            "image/svg+xml", "application/x-javascript"
        };

        private static readonly HashSet<string> _cacheableExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".html", ".css", ".js", ".json", ".svg", ".xml", ".txt",
            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot"
        };

        private static bool _cacheEnabled = true;
        private const int CACHE_THRESHOLD_READS = 10;
        private const int MAX_CACHE_SIZE_MB = 100;
        private const long MAX_FILE_SIZE_FOR_CACHE = 5 * 1024 * 1024;
        private static long _currentCacheSize = 0;
        private static double _lastCpuUsage = 0;

        static Endpoints()
        {
            _ = Task.Run(async () =>
            {
                var proc = Process.GetCurrentProcess();
                TimeSpan prevCpu = proc.TotalProcessorTime;
                DateTime prevTime = DateTime.UtcNow;

                while (true)
                {
                    await Task.Delay(1000);
                    TimeSpan currCpu = proc.TotalProcessorTime;
                    DateTime currTime = DateTime.UtcNow;

                    double cpuUsedMs = (currCpu - prevCpu).TotalMilliseconds;
                    double elapsedMs = (currTime - prevTime).TotalMilliseconds;
                    int cores = Environment.ProcessorCount;

                    _lastCpuUsage = Math.Round(cpuUsedMs / (elapsedMs * cores) * 100, 2);

                    prevCpu = currCpu;
                    prevTime = currTime;
                }
            });

            _ = Task.Run(async () =>
            {
                while (true)
                {
                    await Task.Delay(TimeSpan.FromSeconds(60));
                    _readCounts.Clear();
                }
            });

            _ = Task.Run(async () =>
            {
                while (true)
                {
                    await Task.Delay(TimeSpan.FromMinutes(30));
                    _fileCache.Clear();
                    _currentCacheSize = 0;
                }
            });
        }

        public static void SetCacheEnabled(bool enabled)
        {
            _cacheEnabled = enabled;
            if (!enabled)
            {
                ClearCache();
            }
        }

        public static void ClearCache()
        {
            _fileCache.Clear();
            _readCounts.Clear();
            _currentCacheSize = 0;
        }

        public static void Map(WebApplication app, PluginManager pluginManager)
        {
            bool ValidateAdmin(HttpRequest request, AuthenticationService authService)
            {
                string authHeader = request.Headers["Authorization"].ToString();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ")) return false;
                string token = authHeader.Substring("Bearer ".Length);
                return authService.ValidateJwtToken(token) && authService.GetRoleFromToken(token).ToLower() == "admin";
            }

            app.MapPost("/api/login", async (
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
                    logger.Log($"✅ User logged in: {user.Username}");
                    return Results.Ok(new
                    {
                        success = true,
                        token,
                        refreshToken = user.RefreshToken,
                        user = new { username = user.Username, role = user.Role, email = user.Email }
                    });
                }
                return Results.Unauthorized();
            });

            app.MapPost("/api/register", async (
                [FromBody] RegisterRequest registerRequest,
                UserService userService,
                AuthenticationService authService,
                Logger logger) =>
            {
                if (registerRequest == null) return Results.BadRequest(new { success = false, message = "Invalid request" });

                var (user, message) = await userService.CreateUserAsync(registerRequest);
                if (user != null && user.Role.ToLower() == "admin")
                {
                    var token = authService.GenerateJwtToken(user);
                    logger.Log($"✅ User registered: {user.Username}");
                    return Results.Ok(new
                    {
                        success = true,
                        token,
                        refreshToken = user.RefreshToken,
                        user = new { username = user.Username, role = user.Role, email = user.Email }
                    });
                }
                return Results.BadRequest(new { success = false, message });
            });

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

                string fileName = file.FileName;
                string tempFilePath = Path.Combine(pluginsDirectory, $"{fileName}.tmp");
                string finalFilePath = Path.Combine(pluginsDirectory, fileName);

                try
                {
                    logger.Log("📤 Receiving plugin file...");
                    using (var stream = new FileStream(tempFilePath, FileMode.Create))
                    {
                        await file.CopyToAsync(stream);
                    }

                    if (Path.GetExtension(fileName) == ".dll")
                    {
                        await pluginManager.UnloadAllPluginsAsync();
                        if (File.Exists(finalFilePath)) File.Delete(finalFilePath);
                        File.Move(tempFilePath, finalFilePath);
                        logger.Log($"✅ Replaced old plugin with '{finalFilePath}'");
                        tempFilePath = null;
                        await pluginManager.LoadPluginsAsync();
                    }
                    else if (Path.GetExtension(fileName) == ".pkg")
                    {
                        var package = await packageManager.GetPackageFromByteArray(await File.ReadAllBytesAsync(tempFilePath));
                        if (package != null)
                            await packageManager.InstallPackage(package);
                        else
                            return Results.BadRequest(new { success = false, message = "Invalid package" });
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

            app.MapGet("/api/market/plugins", async (
                HttpRequest request,
                [FromServices] AuthenticationService authService) =>
            {
                if (!ValidateAdmin(request, authService)) return Results.Unauthorized();

                try
                {
                    using var client = new HttpClient();
                    var marketResponse = await client.GetAsync("https://dashboard.voidgames.ir/api/market/plugins");
                    marketResponse.EnsureSuccessStatusCode();

                    var content = await marketResponse.Content.ReadAsStringAsync();
                    var marketPlugins = JsonConvert.DeserializeObject<List<MarketPlugin>>(content);

                    if (marketPlugins != null)
                    {
                        foreach (var plugin in Directory.GetFiles(Path.Combine(AppContext.BaseDirectory, "plugins")))
                        {
                            var fileName = Path.GetFileNameWithoutExtension(plugin);
                            var existed = marketPlugins.FirstOrDefault(p => p.Name == fileName, new MarketPlugin() { Name = string.Empty });
                            if (string.IsNullOrEmpty(existed.Name))
                                continue;

                            marketPlugins.Remove(existed);
                        }
                    }

                    return Results.Ok(new { success = true, plugins = marketPlugins });
                }
                catch (Exception ex)
                {
                    return Results.Problem("Failed to fetch market plugins.");
                }
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

                var downloadJobProcessor = request.HttpContext.RequestServices.GetRequiredService<DownloadJobProcessor>();
                downloadJobProcessor.EnqueueJob(downloadRequest);

                return Results.Accepted(null, new { success = true, message = $"Download request for '{downloadRequest.Name}.dll' has been queued and will be processed." });
            });

            app.MapGet("/videos/{filename}", (string filename, [FromServices] VideoService videoService) =>
            {
                string filePath = videoService.GetVideoFilePath(filename);
                if (filePath == null || !File.Exists(filePath)) return Results.NotFound("Video file not found");

                string contentType = videoService.GetContentType(filePath);
                return Results.File(filePath, contentType, enableRangeProcessing: true);
            });

            app.MapGet("/api/stats", async (HttpRequest request, HttpResponse response, UserService userService) =>
            {
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
                        uptime = (DateTime.Now - Process.GetCurrentProcess().StartTime).ToString(@"hh\:mm\:ss"),
                        users = userService.Users.Count
                    };

                    return Results.Ok(stats);
                }
                catch (Exception ex)
                {
                    return Results.Problem(ex.Message);
                }
            });

            app.MapGet("/api/cache/stats", (
                HttpRequest request,
                [FromServices] AuthenticationService authService) =>
            {
                if (!ValidateAdmin(request, authService))
                    return Results.Unauthorized();

                var stats = GetCacheStats();
                return Results.Ok(stats);
            });

            app.MapPost("/api/cache/clear", (
                HttpRequest request,
                [FromServices] AuthenticationService authService,
                Logger logger) =>
            {
                if (!ValidateAdmin(request, authService))
                    return Results.Unauthorized();

                ClearCache();
                logger.Log("🗑️ Cache cleared by admin.");
                return Results.Ok(new { success = true, message = "Cache cleared successfully." });
            });

            app.MapFallback("{*path}", async (HttpContext context, ILogger<Program> logger) =>
            {
                var rootPath = Path.Combine(AppContext.BaseDirectory, "public_html");
                if (!Directory.Exists(rootPath))
                {
                    Directory.CreateDirectory(rootPath);
                }

                var requestPath = context.Request.Path.Value?.TrimStart('/');
                if (string.IsNullOrEmpty(requestPath))
                {
                    requestPath = "index.html";
                }

                requestPath = requestPath.TrimEnd('/');
                if (IsSuspiciousPath(requestPath))
                {
                    logger.LogWarning($"[StaticHandler] Suspicious path rejected: {requestPath}");
                    context.Response.StatusCode = 403;
                    await context.Response.WriteAsync("Forbidden");
                    return;
                }

                var filePath = Path.Combine(rootPath, requestPath);

                if (await ServeFile(context, filePath, requestPath))
                {
                    LogFileAccess(logger, requestPath, context.Response.StatusCode);
                    return;
                }

                if (!Path.HasExtension(requestPath))
                {
                    var htmlPath = filePath + ".html";
                    if (await ServeFile(context, htmlPath, requestPath + ".html"))
                    {
                        LogFileAccess(logger, requestPath + ".html", context.Response.StatusCode);
                        return;
                    }
                }

                if (!Path.HasExtension(requestPath))
                {
                    var indexPath = Path.Combine(filePath, "index.html");
                    if (await ServeFile(context, indexPath, requestPath + "/index.html"))
                    {
                        LogFileAccess(logger, requestPath + "/index.html", context.Response.StatusCode);
                        return;
                    }
                }

                if (!Path.HasExtension(requestPath) && !requestPath.StartsWith("api/"))
                {
                    var spaIndexPath = Path.Combine(rootPath, "index.html");
                    if (File.Exists(spaIndexPath))
                    {
                        if (await ServeFile(context, spaIndexPath, "index.html"))
                        {
                            logger.LogInformation($"[StaticHandler] SPA fallback: {requestPath} -> index.html");
                            return;
                        }
                    }
                }

                logger.LogWarning($"[StaticHandler] 404 Not Found: {requestPath}");
                await Serve404Page(context, rootPath);
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
                    return Results.Problem($"Error saving settings: {ex.Message}");
                }
            });
        }

        private static bool IsSuspiciousPath(string path)
        {
            if (string.IsNullOrEmpty(path))
                return false;

            var suspicious = new[]
            {
                "..",          
                "~",           
                "/etc/",    
                "/proc/",    
                "/sys/",   
                "\\\\",         
                ".env",         
                ".git",
                "web.config",   
                "appsettings",  
            };

            var lowerPath = path.ToLowerInvariant();
            return suspicious.Any(s => lowerPath.Contains(s));
        }

        private static void LogFileAccess(ILogger logger, string path, int statusCode)
        {
            if (statusCode == 304)
            {
                logger.LogDebug($"[StaticHandler] 304 Not Modified: {path}");
            }
            else if (statusCode == 200)
            {
                logger.LogDebug($"[StaticHandler] 200 OK: {path}");
            }
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

            var fullPath = Path.GetFullPath(filePath);
            var rootPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "public_html"));

            if (!fullPath.StartsWith(rootPath, StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = 403;
                return true;
            }

            var fileInfo = new FileInfo(filePath);
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

            byte[] fileContent = await File.ReadAllBytesAsync(filePath);
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

            if (shouldCache && !_fileCache.ContainsKey(relativePath))
            {
                await CacheFile(relativePath, fileContent, lastModified, contentType);
            }

            return true;
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

            if (_currentCacheSize + totalSize <= (MAX_CACHE_SIZE_MB * 1024 * 1024))
            {
                if (_fileCache.TryAdd(relativePath, cachedFile))
                {
                    Interlocked.Add(ref _currentCacheSize, totalSize);
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
                Interlocked.Add(ref _currentCacheSize, -totalSize);
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
    }
}