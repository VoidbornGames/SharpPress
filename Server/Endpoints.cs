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

namespace SharpPress
{
    public static class Endpoints
    {
        public static bool cacheStaticFiles = true;

        private static ConcurrentDictionary<string, byte[]> _fileCache = new ConcurrentDictionary<string, byte[]>();
        private static ConcurrentDictionary<string, int> _readCounts = new ConcurrentDictionary<string, int>();
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
                _readCounts.Clear();
                await Task.Delay(TimeSpan.FromSeconds(60));
            });

            _ = Task.Run(async () =>
            {
                _fileCache.Clear();
                await Task.Delay(TimeSpan.FromMinutes(30));
            });
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

            // --- /api/login ---
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

            // --- /api/register ---
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

            // --- /api/plugins ---
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

            // --- /api/plugins/upload ---
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

            // --- /api/plugins/reload ---
            app.MapPost("/api/plugins/reload", async (
                HttpRequest request,
                [FromServices] AuthenticationService authService) =>
            {
                if (!ValidateAdmin(request, authService)) return Results.Unauthorized();

                await pluginManager.ReloadAllPluginsAsync();
                return Results.Ok(new { success = true, message = "Plugins reloaded successfully." });
            });

            // --- /api/market/plugins ---
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

            // --- /api/marketplace/download ---
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

            // --- /videos/{filename} ---
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
                        users = userService.usersCount
                    };

                    return Results.Ok(stats);
                }
                catch (Exception ex)
                {
                    return Results.Problem(ex.Message);
                }
            });

            app.MapFallback("{*path}", async (HttpContext context, ILogger<Program> logger) =>
            {
                var rootPath = Path.Combine(AppContext.BaseDirectory, "public_html");
                if (!Directory.Exists(rootPath)) Directory.CreateDirectory(rootPath);

                var requestPath = context.Request.Path.Value?.TrimStart('/');
                if (string.IsNullOrEmpty(requestPath)) requestPath = "index.html";
                if (requestPath.EndsWith('/')) requestPath = requestPath.TrimEnd('/');

                var filePath = Path.Combine(rootPath, requestPath);
                if (await ServeFile(context, filePath, requestPath)) return;

                if (!Path.HasExtension(requestPath))
                {
                    var indexPath = Path.Combine(rootPath, requestPath, "index.html");
                    if (await ServeFile(context, indexPath, requestPath + "/")) return;
                }

                logger.LogWarning($"[StaticHandler] 404 Not Found: {requestPath}");
                context.Response.StatusCode = 404;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync("<div style='text-align: center; color: #ccc; font-family: sans-serif; padding-top: 50px;'><h1>404</h1><h3>File Not Found</h3><p>SharpPress</p></div>");
            });
        }

        private static async Task<bool> ServeFile(HttpContext context, string filePath, string relativePath)
        {
            if (!File.Exists(filePath)) return false;

            var fullPath = Path.GetFullPath(filePath);
            var rootPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "public_html"));

            if (!fullPath.StartsWith(rootPath))
            {
                return false;
            }

            var contentType = new FileExtensionContentTypeProvider();
            string ct;
            if (!contentType.TryGetContentType(filePath, out ct)) ct = "application/octet-stream";

            context.Response.ContentType = ct;

            var ext = Path.GetExtension(filePath).ToLowerInvariant();

            if (_fileCache.ContainsKey(relativePath))
            {
                await context.Response.Body.WriteAsync(_fileCache[relativePath]);
            }
            else
            {
                if (IsTextFile(filePath))
                {
                    var content = await File.ReadAllTextAsync(filePath);
                    await context.Response.WriteAsync(content);

                    if (cacheStaticFiles && _readCounts.AddOrUpdate(relativePath, 1, (k, v) => v + 1) >= 10)
                    {
                        _fileCache[relativePath] = Encoding.UTF8.GetBytes(content);
                    }
                }
                else
                {
                    await context.Response.SendFileAsync(filePath);
                }
            }

            return true;
        }

        private static bool IsTextFile(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan))
                {
                    byte[] buffer = new byte[1024];
                    int bytesRead = fs.Read(buffer, 0, buffer.Length);

                    for (int i = 0; i < bytesRead; i++)
                    {
                        if (buffer[i] == 0) return false;
                    }
                }
                return true;
            }
            catch
            {
                return false; // Safe fallback if file is locked or unreadable
            }
        }
    }
}