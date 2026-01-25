using System.Collections.Concurrent;
using System.IO;
using System.Reflection;
using System.Runtime.Loader;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using SharpPress.Events;
using SharpPress.Plugins;

namespace SharpPress.Services
{
    public class PluginManager
    {
        private readonly Logger _logger;
        private readonly IEventBus _eventBus;
        private readonly IServiceProvider _serviceProvider;
        private readonly IServiceScopeFactory _scopeFactory;
        private IEndpointRouteBuilder _routeBuilder;

        private readonly ConcurrentDictionary<string, IPlugin> _loadedPlugins = new();
        private readonly ConcurrentDictionary<string, PluginContext> _pluginContexts = new();
        private readonly ConcurrentDictionary<string, PluginLoadContext> _loadContexts = new();
        private readonly ConcurrentDictionary<string, string> _uniquePaths = new();
        private readonly ConcurrentDictionary<string, Func<HttpContext, Task>> _globalRoutes = new();


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
        }

        public async Task Initialize(IEndpointRouteBuilder routeBuilder)
        {
            _routeBuilder = routeBuilder;
        }

        public async Task LoadPluginsAsync(string pluginsDirectory = "plugins")
        {
            if (!Directory.Exists(pluginsDirectory))
            {
                Directory.CreateDirectory(pluginsDirectory);
                return;
            }

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

        /// <summary>
        /// Registers a route to the central routing table.
        /// </summary>
        public void RegisterRoute(string path, Func<HttpContext, Task> handler)
        {
            _globalRoutes[path] = handler;
            _logger.Log($"🔌 Plugin registered route: {path}");
        }

        /// <summary>
        /// Gets a handler for a specific route.
        /// </summary>
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

                var pluginTypes = assembly.GetTypes()
                    .Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract)
                    .ToList();

                if (!pluginTypes.Any()) return;

                foreach (var pluginType in pluginTypes)
                {
                    if (Activator.CreateInstance(pluginType) is not IPlugin plugin) continue;

                    var pluginName = plugin.Name;

                    var context = new PluginContext(_logger, _scopeFactory, _routeBuilder);
                    _pluginContexts[plugin.Name] = context;

                    await plugin.OnLoadAsync(context);
                    _loadedPlugins[plugin.Name] = plugin;
                    await _eventBus.PublishAsync(new PluginLoadedEvent(plugin));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to load plugin: {ex.Message}");
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