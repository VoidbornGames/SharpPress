using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewEngines;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Razor.Language;
using RazorEngineCore;
using SharpPress.Events;
using SharpPress.Plugins;
using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.Loader;
using System.Text.RegularExpressions;

namespace SharpPress.Services
{
    public class PluginManager
    {
        private readonly Logger _logger;
        private readonly IEventBus _eventBus;
        private readonly IServiceProvider _serviceProvider;
        private readonly IServiceScopeFactory _scopeFactory;
        private IEndpointRouteBuilder _routeBuilder;

        private readonly IRazorEngine _razorEngine;
        private readonly ApplicationPartManager _appPartManager;

        private readonly ConcurrentDictionary<string, IPlugin> _loadedPlugins = new();
        private readonly ConcurrentDictionary<string, PluginContext> _pluginContexts = new();
        private readonly ConcurrentDictionary<string, PluginLoadContext> _loadContexts = new();
        private readonly ConcurrentDictionary<string, string> _uniquePaths = new();
        private readonly ConcurrentDictionary<string, Func<HttpContext, Task>> _globalRoutes = new();
        private readonly ConcurrentDictionary<string, IRazorEngineCompiledTemplate> _compiledTemplates = new();
        private readonly ConcurrentDictionary<string, EmbeddedRazorPage> _embeddedPages = new();


        public PluginManager(
            Logger logger,
            IEventBus eventBus,
            IServiceProvider serviceProvider,
            IServiceScopeFactory scopeFactory)
        {
            _logger = logger;
            _eventBus = eventBus;
            _serviceProvider = serviceProvider;
            _scopeFactory = scopeFactory;

            _razorEngine = new RazorEngineCore.RazorEngine();
        }

        public void Initialize(IEndpointRouteBuilder routeBuilder)
        {
            _routeBuilder = routeBuilder;
        }

        public async Task LoadPluginsAsync(string pluginsDirectory = "plugins")
        {
            if (!Directory.Exists(pluginsDirectory)) Directory.CreateDirectory(pluginsDirectory);

            var absDir = Path.GetFullPath(pluginsDirectory);
            var tempDir = Path.Combine(absDir, ".plugin_temp");
            Directory.CreateDirectory(tempDir);

            var dllFiles = Directory.GetFiles(absDir, "*.dll", SearchOption.TopDirectoryOnly)
                                    .Where(f => !IsGeneratedCopy(Path.GetFileNameWithoutExtension(f)))
                                    .ToList();

            if (!dllFiles.Any()) return;
            foreach (var dllFile in dllFiles)
            {
                await LoadPluginFromFileAsync(dllFile, tempDir);
            }

            _logger.Log($"🔌 Plugin loading complete. {_loadedPlugins.Count} plugins loaded.");
        }

        public void RegisterRoute(string path, Func<HttpContext, Task> handler)
        {
            _globalRoutes[path] = handler;
            _routeBuilder?.Map(path, handler);
            _logger.Log($"🔌 Plugin registered route: {path}");
        }

        public Func<HttpContext, Task>? GetRouteHandler(string path)
        {
            _globalRoutes.TryGetValue(path, out var handler);
            return handler;
        }

        public async Task LoadPluginFromFileAsync(string dllFile, string tempDir)
        {
            try
            {
                var absolutePath = Path.GetFullPath(dllFile);
                if (!IsValidNetAssembly(absolutePath)) return;

                Directory.CreateDirectory(tempDir);
                var uniqueFileName = $"{Path.GetFileNameWithoutExtension(absolutePath)}_{Guid.NewGuid()}{Path.GetExtension(absolutePath)}";
                var uniquePath = Path.Combine(tempDir, uniqueFileName);
                File.Copy(absolutePath, uniquePath, true);
                uniquePath = Path.GetFullPath(uniquePath);

                _uniquePaths[absolutePath] = uniquePath;

                var loadContext = new PluginLoadContext(uniquePath);
                var assembly = loadContext.LoadFromAssemblyPath(uniquePath);
                _loadContexts[absolutePath] = loadContext;

                var resourceNames = assembly.GetManifestResourceNames();
                foreach (var resourceName in resourceNames)
                {
                    if (!resourceName.EndsWith(".cshtml")) continue;

                    try
                    {
                        using var stream = assembly.GetManifestResourceStream(resourceName);
                        if (stream == null) continue;

                        using var reader = new StreamReader(stream);
                        var content = await reader.ReadToEndAsync();

                        var match = Regex.Match(content, @"@page\s+""([^""]+)""");
                        if (match.Success)
                        {
                            string route = match.Groups[1].Value;

                            _logger.Log($"🔍 Found embedded Razor page '{resourceName}' for route '{route}'");

                            var embeddedPage = new EmbeddedRazorPage
                            {
                                ResourceName = resourceName,
                                Content = content,
                                Route = route,
                                Assembly = assembly
                            };
                            _embeddedPages[route] = embeddedPage;

                            _routeBuilder.Map(route, async context =>
                            {
                                await RenderEmbeddedRazorPage(context, embeddedPage);
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error scanning razor page {resourceName}: {ex.Message}");
                    }
                }

                var pluginTypes = assembly.GetTypes()
                    .Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract)
                    .ToList();

                if (!pluginTypes.Any()) return;

                foreach (var pluginType in pluginTypes)
                {
                    if (Activator.CreateInstance(pluginType) is not IPlugin plugin) continue;

                    var pluginName = plugin.Name;

                    var context = new PluginContext(_logger, _scopeFactory, _routeBuilder, _serviceProvider);
                    _pluginContexts[plugin.Name] = context;

                    await plugin.OnLoadAsync(context);

                    _loadedPlugins[plugin.Name] = plugin;
                    _logger.Log($"✅ Plugin Loaded: {plugin.Name}");
                    await _eventBus.PublishAsync(new PluginLoadedEvent(plugin));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to load plugin: {ex.Message}");
            }
        }

        private async Task RenderEmbeddedRazorPage(HttpContext context, EmbeddedRazorPage embeddedPage)
        {
            try
            {
                var razorContent = embeddedPage.Content;
                var modelMatch = Regex.Match(razorContent, @"@model\s+([^\r\n]+)");

                Type? modelType = null;
                if (modelMatch.Success)
                {
                    var modelTypeName = modelMatch.Groups[1].Value.Trim();
                    modelType = embeddedPage.Assembly.GetTypes()
                        .FirstOrDefault(t => t.FullName == modelTypeName || t.Name == modelTypeName);
                }

                razorContent = Regex.Replace(razorContent, @"@page\s+""[^""]+""", "");
                var templateKey = $"{embeddedPage.ResourceName}_{embeddedPage.Route}";

                if (!_compiledTemplates.TryGetValue(templateKey, out var compiledTemplate))
                {
                    if (modelType != null)
                    {
                        compiledTemplate = await _razorEngine.CompileAsync(razorContent);
                    }
                    else
                    {
                        compiledTemplate = await _razorEngine.CompileAsync(razorContent);
                    }
                    _compiledTemplates[templateKey] = compiledTemplate;
                }

                string renderedHtml;

                if (modelType != null)
                {
                    var model = Activator.CreateInstance(modelType);
                    await TryPopulateModel(context, model, modelType);

                    renderedHtml = await compiledTemplate.RunAsync(model);
                }
                else
                {
                    var viewBag = new
                    {
                        Request = context.Request,
                        Response = context.Response,
                        User = context.User,
                        Path = context.Request.Path.Value,
                        Method = context.Request.Method
                    };
                    renderedHtml = await compiledTemplate.RunAsync(viewBag);
                }

                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(renderedHtml);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error rendering embedded Razor page '{embeddedPage.Route}': {ex.Message}");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsync($@"
                    <html>
                    <head><title>Error</title></head>
                    <body>
                        <h1>Error Rendering Plugin Page</h1>
                        <p><strong>Route:</strong> {embeddedPage.Route}</p>
                        <p><strong>Resource:</strong> {embeddedPage.ResourceName}</p>
                        <p><strong>Error:</strong> {ex.Message}</p>
                        <pre>{ex.StackTrace}</pre>
                    </body>
                    </html>
                ");
            }
        }

        private async Task TryPopulateModel(HttpContext context, object model, Type modelType)
        {
            try
            {
                var properties = modelType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                    .Where(p => p.CanWrite);

                foreach (var prop in properties)
                {
                    string? value = null;

                    if (context.Request.Query.ContainsKey(prop.Name))
                    {
                        value = context.Request.Query[prop.Name].ToString();
                    }
                    else if (context.Request.HasFormContentType && context.Request.Form.ContainsKey(prop.Name))
                    {
                        value = context.Request.Form[prop.Name].ToString();
                    }

                    if (value != null)
                    {
                        try
                        {
                            var convertedValue = Convert.ChangeType(value, prop.PropertyType);
                            prop.SetValue(model, convertedValue);
                        }
                        catch
                        {
                            if (prop.PropertyType == typeof(string))
                            {
                                prop.SetValue(model, value);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error populating model: {ex.Message}");
            }
        }

        public async Task ReloadAllPluginsAsync()
        {
            _logger.Log("🔄 Reloading plugins...");
            await UnloadAllPluginsAsync();
            await Task.Delay(1000);
            await LoadPluginsAsync();
        }

        private static bool IsGeneratedCopy(string fileNameWithoutExtension)
        {
            if (string.IsNullOrEmpty(fileNameWithoutExtension)) return false;
            var parts = fileNameWithoutExtension.Split('_');
            return parts.Length >= 2 && Guid.TryParse(parts.Last(), out _);
        }

        private bool IsValidNetAssembly(string absolutePath)
        {
            try
            {
                AssemblyName.GetAssemblyName(absolutePath);
                return true;
            }
            catch (BadImageFormatException) { return false; }
            catch (FileNotFoundException) { return false; }
            catch { return false; }
        }

        public IReadOnlyDictionary<string, IPlugin> GetLoadedPlugins() => _loadedPlugins;
        public PluginContext? GetPluginContext(string pluginName)
            => _pluginContexts.TryGetValue(pluginName, out var ctx) ? ctx : null;

        public async Task UnloadAllPluginsAsync()
        {
            _logger.Log("🔌 Unloading all plugins...");
            foreach (var plugin in _loadedPlugins.Values.ToList())
            {
                try { await plugin.OnUnloadAsync(); } catch { }
            }
            _loadedPlugins.Clear();
            _pluginContexts.Clear();
            _embeddedPages.Clear();
            _compiledTemplates.Clear();

            foreach (var kv in _loadContexts.ToList())
            {
                try { kv.Value.Unload(); } catch { }
            }
            _loadContexts.Clear();

            for (int i = 0; i < 3; i++) { GC.Collect(); GC.WaitForPendingFinalizers(); await Task.Delay(100); }
            foreach (var temp in _uniquePaths.Values.ToList()) { try { if (File.Exists(temp)) File.Delete(temp); } catch { } }
            _uniquePaths.Clear();
        }

        public async Task UpdateLoadedPluginsAsync(CancellationToken cancellationToken = default)
        {
            foreach (var pluginEntry in _loadedPlugins)
            {
                if (cancellationToken.IsCancellationRequested) break;
                try { var plugin = pluginEntry.Value; var context = _pluginContexts[plugin.Name]; _ = Task.Run(async () => { try { await plugin.OnUpdateAsync(context); } catch { } }, cancellationToken); } catch { }
            }
        }

        private class EmbeddedRazorPage
        {
            public string ResourceName { get; set; } = string.Empty;
            public string Content { get; set; } = string.Empty;
            public string Route { get; set; } = string.Empty;
            public Assembly Assembly { get; set; } = null!;
        }
    }

    public class PluginLoadContext : AssemblyLoadContext
    {
        private readonly string _pluginPath;
        public PluginLoadContext(string pluginPath) : base(isCollectible: true) => _pluginPath = Path.GetFullPath(pluginPath);

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            var dir = Path.GetDirectoryName(_pluginPath)!;
            var assemblyPath = Path.Combine(dir, $"{assemblyName.Name}.dll");
            return File.Exists(assemblyPath) ? LoadFromAssemblyPath(Path.GetFullPath(assemblyPath)) : null;
        }
    }
}