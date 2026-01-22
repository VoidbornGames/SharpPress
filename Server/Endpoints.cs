using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Server.Services;
using SharpPress.Helpers;
using SharpPress.Models;
using SharpPress.Services;
using System.Net;

namespace SharpPress
{
    public static class Endpoints
    {
        public static void Map(WebApplication app)
        {
            // --- Shared Helper for Authentication ---
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
                else
                {
                    return Results.Unauthorized();
                }
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
                PluginManager pluginManager,
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
                PluginManager pluginManager,
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
                PluginManager pluginManager,
                [FromServices] AuthenticationService authService) =>
            {
                if (!ValidateAdmin(request, authService)) return Results.Unauthorized();
                await pluginManager.ReloadAllPluginsAsync();
                return Results.Ok(new { success = true, message = "Plugins reloaded successfully." });
            });

            // --- /api/market/plugins ---
            app.MapGet("/api/market/plugins", async (
                HttpRequest request,
                PluginManager pluginManager,
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
                DownloadJobProcessor downloadJobProcessor,
                [FromServices] AuthenticationService authService) =>
            {
                if (!ValidateAdmin(request, authService)) return Results.Unauthorized();

                if (downloadRequest == null || string.IsNullOrWhiteSpace(downloadRequest.DownloadLink) || string.IsNullOrWhiteSpace(downloadRequest.Name))
                {
                    return Results.BadRequest(new { success = false, message = "Request body must contain a valid 'DownloadLink' and 'Name' property." });
                }

                downloadJobProcessor.EnqueueJob(downloadRequest);

                return Results.Accepted(null, new { success = true, message = $"Download request for '{downloadRequest.Name}.dll' has been queued and will be processed." });
            });

            // --- /videos/{filename} ---
            app.MapGet("/videos/{filename}", (string filename, VideoService videoService) =>
            {
                string filePath = videoService.GetVideoFilePath(filename);
                if (filePath == null || !File.Exists(filePath)) return Results.NotFound("Video file not found");

                string contentType = videoService.GetContentType(filePath);

                return Results.File(filePath, contentType, enableRangeProcessing: true);
            });
        }
    }
}