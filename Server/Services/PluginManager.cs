using Microsoft.Extensions.DependencyInjection;
using System.Reflection;
using System.Runtime.Loader;
using SharpPress.Events;
using SharpPress.Plugins;

namespace SharpPress.Services
{
    /// <summary>
    /// Manages the loading, unloading, and lifecycle of plugins in the application.
    /// </summary>
    public class PluginManager
    {
        private readonly Logger _logger;
        private readonly IEventBus _eventBus;
        public IServiceProvider _serviceProvider;

        private readonly Dictionary<string, IPlugin> _loadedPlugins = new();
        private readonly Dictionary<string, PluginContext> _pluginContexts = new();
        private readonly Dictionary<string, PluginLoadContext> _loadContexts = new();
        private readonly Dictionary<string, string> _uniquePaths = new();

        /// <summary>
        /// Initializes a new instance of the PluginManager class.
        /// </summary>
        public PluginManager(Logger logger, IEventBus eventBus, IServiceProvider serviceProvider)
        {
            _logger = logger;
            _eventBus = eventBus;
            _serviceProvider = serviceProvider;
        }

        /// <summary>
        /// Scans the specified directory for plugin DLLs and loads them.
        /// </summary>
        public async Task LoadPluginsAsync(string pluginsDirectory = "plugins")
        {
            if (!Directory.Exists(pluginsDirectory))
            {
                _logger.Log($"🔌 Plugins directory not found at '{pluginsDirectory}'. Creating it.");
                Directory.CreateDirectory(pluginsDirectory);
                return;
            }

            var absDir = Path.GetFullPath(pluginsDirectory);
            _logger.Log($"🔌 Scanning for plugins in '{absDir}'...");

            var tempDir = Path.Combine(absDir, ".plugin_temp");
            Directory.CreateDirectory(tempDir);

            var dllFiles = Directory.GetFiles(absDir, "*.dll", SearchOption.TopDirectoryOnly)
                                    .Where(f => !IsGeneratedCopy(Path.GetFileNameWithoutExtension(f)))
                                    .ToList();

            if (!dllFiles.Any())
            {
                _logger.Log($"🔎 No plugin DLLs found in {absDir} (after skipping generated copies).");
                return;
            }

            foreach (var dllFile in dllFiles)
            {
                await LoadPluginFromFileAsync(dllFile, tempDir);
            }

            _logger.Log($"🔌 Plugin loading complete. {_loadedPlugins.Count} plugins loaded.");
        }

        /// <summary>
        /// Loads a plugin from a specific DLL file.
        /// </summary>
        public async Task LoadPluginFromFileAsync(string dllFile, string tempDir)
        {
            try
            {
                var absolutePath = Path.GetFullPath(dllFile);

                if (!IsValidNetAssembly(absolutePath))
                    return;

                Directory.CreateDirectory(tempDir);

                var uniqueFileName = $"{Path.GetFileNameWithoutExtension(absolutePath)}_{Guid.NewGuid()}{Path.GetExtension(absolutePath)}";
                var uniquePath = Path.Combine(tempDir, uniqueFileName);
                File.Copy(absolutePath, uniquePath, true);
                uniquePath = Path.GetFullPath(uniquePath);

                _uniquePaths[absolutePath] = uniquePath;

                //_logger.Log($"🧩 Loading plugin from path: {uniquePath}");

                var loadContext = new PluginLoadContext(uniquePath);
                var assembly = loadContext.LoadFromAssemblyPath(uniquePath);
                _loadContexts[absolutePath] = loadContext;

                var pluginTypes = assembly.GetTypes()
                    .Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract)
                    .ToList();

                if (!pluginTypes.Any())
                {
                    _logger.LogWarning($"⚠️ No plugin types found in '{absolutePath}'");
                    SafeDelete(uniquePath);
                    _uniquePaths.Remove(absolutePath);
                    return;
                }

                foreach (var pluginType in pluginTypes)
                {
                    try
                    {
                        if (Activator.CreateInstance(pluginType) is not IPlugin plugin)
                        {
                            _logger.LogError($"❌ Failed to instantiate plugin type {pluginType.Name}.");
                            continue;
                        }

                        var context = new PluginContext(_logger, _eventBus, _serviceProvider);
                        _pluginContexts[plugin.Name] = context;

                        await plugin.OnLoadAsync(context);

                        _loadedPlugins[plugin.Name] = plugin;
                        _logger.Log($"✅ Loaded plugin: {plugin.Name} v{plugin.Version}");
                        await _eventBus.PublishAsync(new PluginLoadedEvent(plugin));
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"❌ Failed to instantiate or load plugin type {pluginType.Name}: {ex.Message}");
                    }
                }
            }
            catch (ReflectionTypeLoadException ex)
            {
                var loaderMessages = ex.LoaderExceptions?.Where(e => e != null)
                    .Select(e => e.Message)
                    .ToArray() ?? Array.Empty<string>();
                _logger.LogError($"❌ Reflection error loading '{dllFile}': {ex.Message}. Loader Exceptions: {string.Join(", ", loaderMessages)}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Failed to load plugin from '{dllFile}': {ex.Message}");
                _logger.LogError($"💡 This can happen if the file is locked, corrupted, or unsigned properly.");
            }
        }

        /// <summary>
        /// Calls the OnUpdateAsync method for all loaded plugins.
        /// </summary>
        public async Task UpdateLoadedPluginsAsync(CancellationToken cancellationToken = default)
        {
            foreach (var pluginEntry in _loadedPlugins)
            {
                try
                {
                    var plugin = pluginEntry.Value;
                    var context = _pluginContexts[plugin.Name];
                    _ = Task.Run(async () => plugin.OnUpdateAsync(context));
                }
                catch (Exception ex)
                {
                    _logger.LogError($"❌ Error updating plugin {pluginEntry.Key}: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Gets a read-only dictionary of all loaded plugins.
        /// </summary>
        public IReadOnlyDictionary<string, IPlugin> GetLoadedPlugins() => _loadedPlugins;

        /// <summary>
        /// Gets the context associated with a specific plugin.
        /// </summary>
        public PluginContext? GetPluginContext(string pluginName)
            => _pluginContexts.TryGetValue(pluginName, out var context) ? context : null;

        /// <summary>
        /// Unloads all loaded plugins and cleans up resources.
        /// </summary>
        public async Task UnloadAllPluginsAsync()
        {
            _logger.Log("🔌 Unloading all plugins...");

            foreach (var plugin in _loadedPlugins.Values.ToList())
            {
                try
                {
                    await plugin.OnUnloadAsync();
                }
                catch (Exception ex)
                {
                    _logger.LogError($"❌ Error during OnUnloadAsync for plugin {plugin.Name}: {ex.Message}");
                }
            }

            _loadedPlugins.Clear();
            _pluginContexts.Clear();

            foreach (var kv in _loadContexts.ToList())
            {
                try
                {
                    kv.Value.Unload();
                }
                catch (Exception ex)
                {
                    _logger.LogError($"❌ Failed to unload PluginLoadContext for '{kv.Key}': {ex.Message}");
                }
            }
            _loadContexts.Clear();

            for (int i = 0; i < 3; i++)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
                await Task.Delay(100);
            }

            foreach (var temp in _uniquePaths.Values.ToList())
                SafeDelete(temp);
            _uniquePaths.Clear();

            try
            {
                var anyTemp = _uniquePaths.Values.FirstOrDefault();
            }
            catch { }

            _logger.Log("🔌 All plugins unloaded.");
        }

        /// <summary>
        /// Unloads all loaded plugins and loads them again.
        /// </summary>
        public async Task ReloadAllPluginsAsync()
        {
            _logger.Log("🔄 Reloading plugins via Plugin Manger request...");
            await UnloadAllPluginsAsync();

            _logger.Log("⏳ Waiting for file locks to be released...");
            await Task.Delay(1000);

            await LoadPluginsAsync();
            _logger.Log("✅ Plugin reload complete.");
        }

        /// <summary>
        /// Determines if a file name represents a generated copy based on naming convention.
        /// </summary>
        private static bool IsGeneratedCopy(string fileNameWithoutExtension)
        {
            if (string.IsNullOrEmpty(fileNameWithoutExtension))
                return false;

            var parts = fileNameWithoutExtension.Split('_');
            if (parts.Length < 2)
                return false;

            var last = parts.Last();
            return Guid.TryParse(last, out _);
        }

        /// <summary>
        /// Safely attempts to delete a file, ignoring any exceptions.
        /// </summary>
        private static void SafeDelete(string path)
        {
            try
            {
                if (File.Exists(path))
                    File.Delete(path);
            }
            catch { }
        }

        /// <summary>
        /// Validates that a file is a valid .NET assembly.
        /// </summary>
        private bool IsValidNetAssembly(string absolutePath)
        {
            try
            {
                AssemblyName.GetAssemblyName(absolutePath);
                return true;
            }
            catch (BadImageFormatException)
            {
                _logger.LogError($"❌ '{Path.GetFileName(absolutePath)}' is not a valid .NET assembly.");
                return false;
            }
            catch (FileNotFoundException ex)
            {
                _logger.LogError($"❌ File not found: {ex.FileName}");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Assembly validation failed for '{absolutePath}': {ex.Message}");
                return false;
            }
        }
    }

    /// <summary>
    /// Custom assembly load context for plugins that enables isolation and unloading.
    /// </summary>
    public class PluginLoadContext : AssemblyLoadContext
    {
        private readonly string _pluginPath;

        public PluginLoadContext(string pluginPath) : base(isCollectible: true)
        {
            _pluginPath = Path.GetFullPath(pluginPath);
        }

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            var dir = Path.GetDirectoryName(_pluginPath)!;
            var assemblyPath = Path.Combine(dir, $"{assemblyName.Name}.dll");
            if (File.Exists(assemblyPath))
                return LoadFromAssemblyPath(Path.GetFullPath(assemblyPath));
            return null;
        }
    }


    public class PluginMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly PluginManager _pluginManager;
        private readonly Logger _logger;

        public PluginMiddleware(RequestDelegate next, PluginManager pluginManager, Logger logger)
        {
            _next = next;
            _pluginManager = pluginManager;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            bool handled = false;
            foreach (var pluginEntry in _pluginManager.GetLoadedPlugins())
            {
                var plugin = pluginEntry.Value;
                var pluginCtx = _pluginManager.GetPluginContext(plugin.Name);

                var handler = pluginCtx.GetRouteHandler(context.Request.Path);
                if (handler != null)
                {
                    try
                    {
                        await handler(context.Request);
                        handled = true;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Plugin error: {ex.Message}");
                        handled = true;
                    }
                    break;
                }
            }

            if (!handled)
            {
                await _next(context);
            }
        }
    }
}