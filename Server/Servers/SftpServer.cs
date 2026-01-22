using Newtonsoft.Json;
using Server.Services;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Text;
using SharpPress.Models;

namespace SharpPress.Services
{
    public class SftpServer : IManualServer
    {
        private readonly int _port;
        private readonly Logger _logger;
        private HttpListener _httpListener;
        private CancellationTokenSource _cts;
        private UserService _userService;
        private ServerConfig _serverConfig;
        private AuthenticationService _authenticationService;
        private readonly FeatherDatabase _featherDatabase;

        public ConcurrentDictionary<string, string> usersFolders = new();


        public class SftpMapping : FeatherData
        {
            public string Username { get; set; }
            public string FolderPath { get; set; }
        }

        public SftpServer(
            ServerSettings settings,
            Logger logger,
            IServiceProvider serviceProvider,
            UserService userService,
            ConfigManager configManager,
            ServerSettings serverSettings,
            AuthenticationService authenticationService,
            FeatherDatabase featherDatabase)
        {
            _port = serverSettings.sftpPort;
            _logger = logger;
            _authenticationService = authenticationService;
            _cts = new CancellationTokenSource();
            _userService = userService;
            _serverConfig = configManager.Config;
            _featherDatabase = featherDatabase;

            _featherDatabase.CreateTable<SftpMapping>();
        }

        internal static readonly string RootFolder = "/var/www/";
        internal static readonly ConcurrentDictionary<string, (DateTime expiry, string username)> Sessions = new();

        public async Task Start()
        {
            var mappings = _featherDatabase.GetAll<SftpMapping>();

            if (mappings.Any())
            {
                usersFolders = new ConcurrentDictionary<string, string>(
                    mappings.ToDictionary(x => x.Username, x => x.FolderPath)
                );
                _logger.Log($"✅ Loaded {mappings.Count} SFTP mappings from database.");
            }
            else
            {
                usersFolders = new ConcurrentDictionary<string, string>();
            }

            try
            {
                if (!Directory.Exists(RootFolder)) Directory.CreateDirectory(RootFolder);
                _httpListener = new HttpListener();
                string prefix = $"http://*:{_port}/";
                _httpListener.Prefixes.Add(prefix);
                _httpListener.Start();
                _logger.Log($"🗃️ SFTP Panel Running on {prefix}");

                if (!usersFolders.ContainsKey("admin"))
                {
                    var adminMapping = new SftpMapping { Username = "admin", FolderPath = "/" };
                    _featherDatabase.SaveData(adminMapping);
                    usersFolders["admin"] = "/";
                }

                _ = Task.Run(async () =>
                {
                    while (!_cts.Token.IsCancellationRequested)
                    {
                        try
                        {
                            var context = await _httpListener.GetContextAsync();
                            _ = HandleRequestAsync(context).ContinueWith(t =>
                            {
                                if (t.Exception != null)
                                    _logger.LogError($"SFTP request handling error: {t.Exception.InnerException?.Message ?? t.Exception.Message}");
                            });
                        }
                        catch (ObjectDisposedException) when (_cts.Token.IsCancellationRequested)
                        {
                            break;
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"SFTP listener error: {ex.Message}");
                        }
                    }
                }, _cts.Token);
            }
            catch (HttpListenerException ex)
            {
                _logger.LogError($"❌ Failed to start SFTP server: {ex.Message}");
                _logger.LogError($"💡 Tip: Make sure port {_port} is not already in use or run as administrator");
                throw;
            }
        }

        public async Task StopAsync()
        {
            _cts.Cancel();
            _httpListener?.Stop();
            _httpListener?.Close();
            _logger.Log("🗃️ SFTP server stopped.");
            await Task.CompletedTask;
        }


        private async Task HandleRequestAsync(HttpListenerContext context)
        {
            var request = context.Request;
            var response = context.Response;

            response.AddHeader("Access-Control-Allow-Origin", "*");
            if (request.HttpMethod == "OPTIONS")
            {
                response.AddHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE");
                response.AddHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
                response.StatusCode = 200;
                response.Close();
                return;
            }

            try
            {
                switch (request.Url.AbsolutePath)
                {
                    case "/":
                        await ServeDefaultPageAsync(request, response);
                        break;

                    case "/api/login":
                        await HandleLoginAsync(request, response);
                        break;

                    case "/api/logout":
                        await HandleLogoutAsync(request, response);
                        break;

                    case "/api/files/list":
                        if (ValidateAuthentication(request))
                            await HandleFileListAsync(request, response);
                        else
                            await SendUnauthorized(response);
                        break;

                    case "/api/files/upload":
                        if (ValidateAuthentication(request))
                            await HandleFileUploadAsync(request, response);
                        else
                            await SendUnauthorized(response);
                        break;

                    case "/api/files/download":
                        if (ValidateAuthentication(request))
                            await HandleFileDownloadAsync(request, response);
                        else
                            await SendUnauthorized(response);
                        break;

                    case "/api/files/create":
                        if (ValidateAuthentication(request))
                            await HandleFileCreateAsync(request, response);
                        else
                            await SendUnauthorized(response);
                        break;

                    case "/api/files/delete":
                        if (ValidateAuthentication(request))
                            await HandleFileDeleteAsync(request, response);
                        else
                            await SendUnauthorized(response);
                        break;

                    case "/api/files/save":
                        if (ValidateAuthentication(request))
                            await HandleFileSaveAsync(request, response);
                        else
                            await SendUnauthorized(response);
                        break;

                    case "/api/files/rename":
                        if (ValidateAuthentication(request))
                            await HandleFileRenameAsync(request, response);
                        else
                            await SendUnauthorized(response);
                        break;

                    default:
                        response.StatusCode = 404;
                        await WriteJsonResponseAsync(response, new { success = false, message = "Not found" });
                        break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"SFTP server error on {request.Url.AbsolutePath}: {ex.Message}");
                response.StatusCode = 500;
                await WriteJsonResponseAsync(response, new { success = false, message = "Internal server error" });
            }
            finally
            {
                response.Close();
            }
        }

        #region API Endpoint Handlers

        private async Task HandleFileRenameAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (request.HttpMethod != "POST")
            {
                response.StatusCode = 405;
                await WriteJsonResponseAsync(response, new { success = false, message = "Only POST allowed" });
                return;
            }

            try
            {
                using var reader = new StreamReader(request.InputStream);
                string body = await reader.ReadToEndAsync();
                var data = JsonConvert.DeserializeObject<Dictionary<string, object>>(body);

                if (data == null ||
                    !data.TryGetValue("path", out var pathObj) ||
                    !data.TryGetValue("newName", out var newNameObj) ||
                    !data.TryGetValue("isDirectory", out var isDirObj))
                {
                    response.StatusCode = 400;
                    await WriteJsonResponseAsync(response, new { success = false, message = "Path, newName, and isDirectory are required." });
                    return;
                }

                var path = pathObj.ToString();
                var newName = newNameObj.ToString();
                var isDirectory = Convert.ToBoolean(isDirObj);

                var fullPath = ResolvePath(path, GetTokenFromRequest(request));

                if (fullPath == null)
                {
                    response.StatusCode = 401;
                    await WriteJsonResponseAsync(response, new { success = false, message = "Unauthorized" });
                    return;
                }

                var directory = Path.GetDirectoryName(fullPath);
                var newPath = Path.Combine(directory, newName);

                if ((isDirectory && Directory.Exists(newPath)) || (!isDirectory && File.Exists(newPath)))
                {
                    response.StatusCode = 409;
                    await WriteJsonResponseAsync(response, new { success = false, message = "An item with this name already exists." });
                    return;
                }

                if (isDirectory)
                {
                    Directory.Move(fullPath, newPath);
                }
                else
                {
                    File.Move(fullPath, newPath);
                }

                if (_serverConfig.DebugMode) _logger.Log($"✅ Item renamed: {Path.GetFileName(fullPath)} to {newName}");

                await WriteJsonResponseAsync(response, new { success = true, message = "Item renamed successfully." });
            }
            catch (Exception ex)
            {
                _logger.LogError($"SFTP rename error: {ex.Message}");
                response.StatusCode = 500;
                await WriteJsonResponseAsync(response, new { success = false, message = ex.Message });
            }
        }

        private async Task HandleFileCreateAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (request.HttpMethod != "POST")
            {
                response.StatusCode = 405;
                await WriteJsonResponseAsync(response, new { success = false, message = "Only POST allowed" });
                return;
            }

            try
            {
                var queryParams = ParseQueryString(request.Url.Query);
                string pathParam = queryParams.GetValueOrDefault("path");

                if (string.IsNullOrEmpty(pathParam))
                {
                    using var reader = new StreamReader(request.InputStream);
                    string body = await reader.ReadToEndAsync();
                    var data = JsonConvert.DeserializeObject<Dictionary<string, object>>(body);

                    if (data == null || !data.TryGetValue("path", out var pathObj))
                    {
                        response.StatusCode = 400;
                        await WriteJsonResponseAsync(response, new { success = false, message = "Path is required." });
                        return;
                    }

                    pathParam = pathObj.ToString();

                    bool isDirectory = false;
                    if (data.TryGetValue("isDirectory", out var isDirObj))
                    {
                        isDirectory = Convert.ToBoolean(isDirObj);
                    }

                    var fullPath = ResolvePath(pathParam, GetTokenFromRequest(request));

                    if (fullPath == null)
                    {
                        response.StatusCode = 401;
                        await WriteJsonResponseAsync(response, new { success = false, message = "Unauthorized" });
                        return;
                    }

                    if (isDirectory)
                    {
                        Directory.CreateDirectory(fullPath);
                    }
                    else
                    {
                        await File.WriteAllTextAsync(fullPath, string.Empty);
                    }

                    if (_serverConfig.DebugMode) _logger.Log($"✅ {(isDirectory ? "Directory" : "File")} created: {Path.GetFileName(fullPath)}");
                }
                else
                {
                    var fullPath = ResolvePath(pathParam, GetTokenFromRequest(request));

                    if (fullPath == null)
                    {
                        response.StatusCode = 401;
                        await WriteJsonResponseAsync(response, new { success = false, message = "Unauthorized" });
                        return;
                    }

                    Directory.CreateDirectory(fullPath);
                    if (_serverConfig.DebugMode) _logger.Log($"✅ Directory created: {Path.GetFileName(fullPath)}");
                }

                await WriteJsonResponseAsync(response, new { success = true, message = "Item created successfully." });
            }
            catch (Exception ex)
            {
                _logger.LogError($"SFTP create error: {ex.Message}");
                response.StatusCode = 500;
                await WriteJsonResponseAsync(response, new { success = false, message = ex.Message });
            }
        }

        private async Task HandleFileSaveAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (request.HttpMethod != "POST")
            {
                response.StatusCode = 405;
                await WriteJsonResponseAsync(response, new { success = false, message = "Only POST allowed" });
                return;
            }

            try
            {
                using var reader = new StreamReader(request.InputStream);
                string body = await reader.ReadToEndAsync();
                var data = JsonConvert.DeserializeObject<Dictionary<string, string>>(body);

                if (data == null || !data.TryGetValue("path", out var pathParam) || !data.TryGetValue("content", out var content))
                {
                    response.StatusCode = 400;
                    await WriteJsonResponseAsync(response, new { success = false, message = "Path and content are required." });
                    return;
                }

                var fullPath = ResolvePath(pathParam, GetTokenFromRequest(request));

                if (fullPath == null)
                {
                    response.StatusCode = 401;
                    await WriteJsonResponseAsync(response, new { success = false, message = "Unauthorized" });
                    return;
                }

                var directory = Path.GetDirectoryName(fullPath);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                await File.WriteAllTextAsync(fullPath, content);
                if (_serverConfig.DebugMode) _logger.Log($"✅ File saved by user: {Path.GetFileName(fullPath)}");

                await WriteJsonResponseAsync(response, new { success = true, message = "File saved successfully." });
            }
            catch (Exception ex)
            {
                _logger.LogError($"SFTP file save error: {ex.Message}");
                response.StatusCode = 500;
                await WriteJsonResponseAsync(response, new { success = false, message = ex.Message });
            }
        }

        private async Task HandleLoginAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (request.HttpMethod != "POST")
            {
                response.StatusCode = 405;
                await WriteJsonResponseAsync(response, new { success = false, message = "Only POST allowed" });
                return;
            }

            try
            {
                using var reader = new StreamReader(request.InputStream);
                string body = await reader.ReadToEndAsync();
                var loginRequest = JsonConvert.DeserializeObject<Dictionary<string, string>>(body);

                if (loginRequest != null &&
                    loginRequest.TryGetValue("Username", out var username) &&
                    loginRequest.TryGetValue("Password", out var password))
                {
                    var _user = _userService.GetUserByUsername(username);
                    if (_user == null || string.IsNullOrWhiteSpace(_user.Username))
                    {
                        response.StatusCode = 401;
                        await WriteJsonResponseAsync(response, new { success = false, message = "Invalid credentials" });
                        return;
                    }
                    if (await _authenticationService.IsAccountLocked(_user.Username))
                    {
                        _logger.LogSecurity($"[SFTP Login] FAILED for user: '{username}'. Too many tries.");
                        response.StatusCode = 401;
                        await WriteJsonResponseAsync(response, new { success = false, message = "Too many tries" });
                        return;
                    }


                    if (_authenticationService.VerifyPassword(password, _user.Password) && _user.Role == "sftp user" || _authenticationService.VerifyPassword(password, _user.Password) && _user.Role == "admin")
                    {
                        _authenticationService.ResetFailedLoginAttempts(_user.Username);
                        var token = Guid.NewGuid().ToString("N");
                        Sessions[token] = (DateTime.UtcNow.AddHours(2), username);

                        if (!usersFolders.ContainsKey(username))
                        {
                            var newMapping = new SftpMapping { Username = username, FolderPath = username };
                            _featherDatabase.SaveData(newMapping);
                            usersFolders[username] = username;
                        }

                        var userPathSuffix = usersFolders.GetValueOrDefault(username, username);
                        var userRootPath = Path.GetFullPath(Path.Combine(RootFolder, userPathSuffix));
                        Directory.CreateDirectory(userRootPath);

                        if (_serverConfig.DebugMode) _logger.Log($"✅ SFTP User logged in: {username}, folder: {userRootPath}");

                        await WriteJsonResponseAsync(response, new { success = true, token, username });
                    }
                    else
                    {
                        _authenticationService.RecordFailedLoginAttempt(username);
                        _logger.LogSecurity($"[SFTP Login] FAILED for user: '{username}'. Invalid credentials.");
                        response.StatusCode = 401;
                        await WriteJsonResponseAsync(response, new { success = false, message = "Invalid credentials" });
                    }
                }
                else
                {
                    response.StatusCode = 400;
                    await WriteJsonResponseAsync(response, new { success = false, message = "Invalid request format" });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"SFTP login error: {ex.Message}");
                response.StatusCode = 500;
                await WriteJsonResponseAsync(response, new { success = false, message = "Server error" });
            }
        }

        private async Task HandleLogoutAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (request.HttpMethod != "POST")
            {
                response.StatusCode = 405;
                await WriteJsonResponseAsync(response, new { success = false, message = "Only POST allowed" });
                return;
            }

            try
            {
                var token = GetTokenFromRequest(request);
                if (Sessions.TryRemove(token, out var sessionData))
                {
                    if (_serverConfig.DebugMode) _logger.Log($"✅ SFTP User logged out: {sessionData.username}");
                }
                await WriteJsonResponseAsync(response, new { success = true });
            }
            catch (Exception ex)
            {
                _logger.LogError($"SFTP logout error: {ex.Message}");
                response.StatusCode = 500;
                await WriteJsonResponseAsync(response, new { success = false, message = "Server error" });
            }
        }

        private async Task HandleFileListAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            try
            {
                var queryParams = ParseQueryString(request.Url.Query);
                string pathParam = queryParams.GetValueOrDefault("path", "/");
                var dir = ResolvePath(pathParam, GetTokenFromRequest(request));

                if (dir == null)
                {
                    response.StatusCode = 401;
                    await WriteJsonResponseAsync(response, new { success = false, message = "Unauthorized" });
                    return;
                }

                if (!Directory.Exists(dir))
                {
                    await WriteJsonResponseAsync(response, new { success = true, items = new object[0] });
                    return;
                }

                var items = Directory.GetDirectories(dir)
                    .Select(d => new DirectoryInfo(d))
                    .Select(di => new { name = di.Name, isDirectory = true, size = 0L, lastModified = di.LastWriteTime })
                    .Concat(Directory.GetFiles(dir)
                        .Select(f => new FileInfo(f))
                        .Select(fi => new { name = fi.Name, isDirectory = false, size = fi.Length, lastModified = fi.LastWriteTime }))
                    .OrderBy(x => !x.isDirectory)
                    .ThenBy(x => x.name);

                await WriteJsonResponseAsync(response, new { success = true, items });
            }
            catch (Exception ex)
            {
                _logger.LogError($"SFTP file list error: {ex.Message}");
                response.StatusCode = 500;
                await WriteJsonResponseAsync(response, new { success = false, message = ex.Message });
            }
        }

        private async Task HandleFileUploadAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            try
            {
                var queryParams = ParseQueryString(request.Url.Query);
                string pathParam = queryParams.GetValueOrDefault("path", "/");
                var dir = ResolvePath(pathParam, GetTokenFromRequest(request));

                if (dir == null)
                {
                    response.StatusCode = 401;
                    await WriteJsonResponseAsync(response, new { success = false, message = "Unauthorized" });
                    return;
                }

                Directory.CreateDirectory(dir);
                var (filename, fileContent) = await ReadMultipartFileAsync(request);
                if (string.IsNullOrEmpty(filename))
                {
                    response.StatusCode = 400;
                    await WriteJsonResponseAsync(response, new { success = false, message = "No filename found" });
                    return;
                }

                var filePath = Path.Combine(dir, filename);
                await File.WriteAllBytesAsync(filePath, fileContent);

                await WriteJsonResponseAsync(response, new { success = true });
            }
            catch (Exception ex)
            {
                _logger.LogError($"SFTP file upload error: {ex.Message}");
                response.StatusCode = 500;
                await WriteJsonResponseAsync(response, new { success = false, message = ex.Message });
            }
        }

        private async Task HandleFileDownloadAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            try
            {
                var queryParams = ParseQueryString(request.Url.Query);
                string pathParam = queryParams.GetValueOrDefault("path");
                var fullPath = ResolvePath(pathParam, GetTokenFromRequest(request));

                if (fullPath == null)
                {
                    response.StatusCode = 401;
                    await WriteJsonResponseAsync(response, new { success = false, message = "Unauthorized" });
                    return;
                }

                if (!File.Exists(fullPath))
                {
                    response.StatusCode = 404;
                    await WriteJsonResponseAsync(response, new { success = false, message = "File not found" });
                    return;
                }

                var extension = Path.GetExtension(fullPath).ToLowerInvariant();
                response.ContentType = GetMimeType(extension);
                response.AddHeader("Content-Disposition", $"attachment; filename=\"{Path.GetFileName(fullPath)}\"");

                using var fileStream = File.OpenRead(fullPath);
                await fileStream.CopyToAsync(response.OutputStream);
            }
            catch (Exception ex)
            {
                _logger.LogError($"SFTP file download error: {ex.Message}");
                response.StatusCode = 500;
                await WriteJsonResponseAsync(response, new { success = false, message = ex.Message });
            }
        }

        private async Task HandleFileDeleteAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            try
            {
                var queryParams = ParseQueryString(request.Url.Query);
                string pathParam = queryParams.GetValueOrDefault("path");
                bool isDir = bool.Parse(queryParams.GetValueOrDefault("isDir", "false"));
                var fullPath = ResolvePath(pathParam, GetTokenFromRequest(request));

                if (fullPath == null)
                {
                    response.StatusCode = 401;
                    await WriteJsonResponseAsync(response, new { success = false, message = "Unauthorized" });
                    return;
                }

                if (isDir)
                    Directory.Delete(fullPath, true);
                else
                    File.Delete(fullPath);

                await WriteJsonResponseAsync(response, new { success = true });
            }
            catch (Exception ex)
            {
                _logger.LogError($"SFTP file delete error: {ex.Message}");
                response.StatusCode = 500;
                await WriteJsonResponseAsync(response, new { success = false, message = ex.Message });
            }
        }

        #endregion

        #region Helper Methods

        public async Task CreateUser(string username, string password)
        {
            try
            {
                var newUser = new User
                {
                    Username = username,
                    Password = _authenticationService.HashPassword(password),
                    Email = "",
                    uuid = Guid.NewGuid(),
                    Role = "sftp user",
                    RefreshToken = _authenticationService.GenerateRefreshToken(),
                    RefreshTokenExpiry = DateTime.UtcNow.AddDays(7)
                };
                _featherDatabase.SaveData(newUser);

                var mapping = new SftpMapping { Username = username, FolderPath = username };
                _featherDatabase.SaveData(mapping);

                usersFolders[username] = username;

                var path = Path.GetFullPath(Path.Combine(RootFolder, username));
                Directory.CreateDirectory(path);

                _logger.Log($"✅ SFTP User Created: {username}");
            }
            catch (Exception e)
            {
                _logger.LogError($"Error creating SFTP user: {e.Message}");
            }
        }

        public async Task DeleteUser(string username)
        {
            try
            {
                var mapping = _featherDatabase.GetByColumn<SftpMapping>("Username", username);
                if (mapping != null)
                {
                    _featherDatabase.Delete<SftpMapping>(mapping.Id);
                }

                usersFolders.TryRemove(username, out _);

                var path = Path.GetFullPath(Path.Combine(RootFolder, username));
                if (Directory.Exists(path)) Directory.Delete(path, true);

                await _userService.DeleteUserAsync(username);
            }
            catch (Exception e)
            {
                _logger.LogError($"Error deleting SFTP user: {e.Message}");
            }
        }

        private Dictionary<string, string> ParseQueryString(string query)
        {
            var dict = new Dictionary<string, string>();
            if (string.IsNullOrEmpty(query) || !query.StartsWith("?")) return dict;
            var pairs = query.Substring(1).Split('&');
            foreach (var pair in pairs)
            {
                var kv = pair.Split(new[] { '=' }, 2);
                if (kv.Length == 2)
                {
                    var key = Uri.UnescapeDataString(kv[0]);
                    var value = Uri.UnescapeDataString(kv[1]);
                    dict[key] = value;
                }
            }
            return dict;
        }

        private string ResolvePath(string relativePath, string token)
        {
            if (!Sessions.TryGetValue(token, out var sessionData))
                return null;

            if (!usersFolders.TryGetValue(sessionData.username, out var pathSuffix))
            {
                pathSuffix = sessionData.username;
            }

            if (relativePath.Contains(".."))
                return null;

            var userBasePath = Path.GetFullPath(Path.Combine(RootFolder, pathSuffix));
            var cleanRelativePath = (relativePath ?? "/").Trim('/').Replace('\\', '/');
            var fullPath = Path.GetFullPath(Path.Combine(userBasePath, cleanRelativePath));

            if (!fullPath.StartsWith(userBasePath))
                return null;

            return fullPath;
        }

        private string GetTokenFromRequest(HttpListenerRequest request)
        {
            var authHeader = request.Headers["Authorization"];
            if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
                return authHeader.Substring("Bearer ".Length);
            return null;
        }

        private bool ValidateAuthentication(HttpListenerRequest request)
        {
            string token = GetTokenFromRequest(request);
            if (string.IsNullOrEmpty(token))
                return false;

            if (Sessions.TryGetValue(token, out var sessionData))
            {
                if (sessionData.expiry < DateTime.UtcNow)
                {
                    Sessions.TryRemove(token, out _);
                    return false;
                }
                return true;
            }
            return false;
        }

        private async Task SendUnauthorized(HttpListenerResponse response)
        {
            response.StatusCode = 401;
            response.AddHeader("WWW-Authenticate", "Bearer");
        }

        private async Task ServeDefaultPageAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            string htmlPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "sftp.html");
            if (File.Exists(htmlPath))
            {
                string html = await File.ReadAllTextAsync(htmlPath);
                byte[] buffer = Encoding.UTF8.GetBytes(html);
                response.ContentType = "text/html";
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            }
            else
            {
                _logger.LogError($"SFTP frontend file not found at: {htmlPath}");
                response.StatusCode = 404;
                byte[] errorBytes = Encoding.UTF8.GetBytes("<h1>404 - SFTP Frontend Not Found</h1><p>Ensure sftp.html is in the application directory.</p>");
                await response.OutputStream.WriteAsync(errorBytes, 0, errorBytes.Length);
            }
        }

        private async Task WriteJsonResponseAsync(HttpListenerResponse response, object data)
        {
            string json = JsonConvert.SerializeObject(data);
            byte[] buffer = Encoding.UTF8.GetBytes(json);
            response.ContentType = "application/json";
            response.ContentLength64 = buffer.Length;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
        }

        private async Task<(string filename, byte[] data)> ReadMultipartFileAsync(HttpListenerRequest request)
        {
            var contentType = request.ContentType;
            var boundary = contentType.Split(';')[1].Split('=')[1].Trim('"');
            var boundaryBytes = Encoding.ASCII.GetBytes($"--{boundary}");
            var endBoundaryBytes = Encoding.ASCII.GetBytes($"--{boundary}--");

            using var memoryStream = new MemoryStream();
            await request.InputStream.CopyToAsync(memoryStream);
            var requestData = memoryStream.ToArray();

            int startIndex = FindIndexOf(requestData, boundaryBytes);
            if (startIndex == -1) return (null, null);
            startIndex += boundaryBytes.Length;

            int headerEndIndex = FindIndexOf(requestData, new byte[] { 0x0D, 0x0A, 0x0D, 0x0A }, startIndex);
            if (headerEndIndex == -1) return (null, null);
            int fileContentStartIndex = headerEndIndex + 4;

            int endIndex = FindIndexOf(requestData, endBoundaryBytes, fileContentStartIndex);
            if (endIndex == -1) return (null, null);

            var headerBytes = new byte[headerEndIndex - startIndex];
            Array.Copy(requestData, startIndex, headerBytes, 0, headerBytes.Length);
            var headerText = Encoding.UTF8.GetString(headerBytes);
            var filenameMatch = System.Text.RegularExpressions.Regex.Match(headerText, @"filename=""([^""]+)""");
            var filename = filenameMatch.Success ? filenameMatch.Groups[1].Value : null;

            var fileContentLength = endIndex - fileContentStartIndex;
            var fileContent = new byte[fileContentLength];
            Array.Copy(requestData, fileContentStartIndex, fileContent, 0, fileContentLength);

            return (filename, fileContent);
        }

        private int FindIndexOf(byte[] source, byte[] pattern, int startIndex = 0)
        {
            for (int i = startIndex; i <= source.Length - pattern.Length; i++)
            {
                if (source[i] == pattern[0])
                {
                    bool found = true;
                    for (int j = 1; j < pattern.Length; j++)
                    {
                        if (source[i + j] != pattern[j])
                        {
                            found = false;
                            break;
                        }
                    }
                    if (found) return i;
                }
            }
            return -1;
        }

        private string GetMimeType(string extension)
        {
            switch (extension.ToLowerInvariant())
            {
                case ".txt": return "text/plain";
                case ".html":
                case ".htm": return "text/html";
                case ".css": return "text/css";
                case ".js": return "application/javascript";
                case ".json": return "application/json";
                case ".xml": return "application/xml";
                case ".pdf": return "application/pdf";
                case ".doc": return "application/msword";
                case ".docx": return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
                case ".xls": return "application/vnd.ms-excel";
                case ".xlsx": return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
                case ".ppt": return "application/vnd.ms-powerpoint";
                case ".pptx": return "application/vnd.openxmlformats-officedocument.presentationml.presentation";
                case ".jpg":
                case ".jpeg": return "image/jpeg";
                case ".png": return "image/png";
                case ".gif": return "image/gif";
                case ".svg": return "image/svg+xml";
                case ".mp3": return "audio/mpeg";
                case ".wav": return "audio/wav";
                case ".mp4": return "video/mp4";
                case ".avi": return "video/x-msvideo";
                case ".mov": return "video/quicktime";
                case ".zip": return "application/zip";
                case ".rar": return "application/x-rar-compressed";
                case ".tar": return "application/x-tar";
                case ".gz": return "application/gzip";
                default: return "application/octet-stream";
            }
        }

        #endregion
    }
}