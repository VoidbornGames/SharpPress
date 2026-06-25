using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;
using SharpPress.Events;
using SharpPress.Plugins;
using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.Loader;

namespace SharpPress.Services
{
    public class PluginManager
    {
        private readonly Logger _logger;
        private readonly IEventBus _eventBus;
        private readonly IServiceProvider _serviceProvider;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly IAdminMenuService _adminMenuService;
        private readonly IActionDescriptorCollectionProvider _actionDescriptorProvider;
        private readonly PluginActionDescriptorChangeProvider _changeProvider;
        private readonly PluginStateService _pluginStateService;

        private readonly HashSet<string> _loadedAssemblyPaths = new();
        private readonly ConcurrentDictionary<string, IPlugin> _loadedPlugins = new();
        private readonly ConcurrentDictionary<string, PluginLoadContext> _loadContexts = new();
        private readonly ConcurrentDictionary<string, Assembly> _assemblies = new();
        private readonly ConcurrentDictionary<string, RequestDelegate> _legacyRoutes = new();
        private readonly ConcurrentDictionary<string, bool> _pluginEnabledState = new();
        private readonly ConcurrentDictionary<string, string> _legacyRoutesToPluginMap = new();
        private readonly ConcurrentDictionary<string, Assembly> _pluginAssemblies = new();
        private readonly ConcurrentDictionary<Type, string> _typeToPluginMap = new();
        private readonly ConcurrentDictionary<string, string> _pluginToAssemblyPath = new();

        public IReadOnlyDictionary<string, string> PluginToAssemblyPath => _pluginToAssemblyPath;

        private ApplicationPartManager? _partManager;
        private IWebHostEnvironment? _env;
        private IRazorViewEngine? _razorEngine;

        public PluginManager(
            Logger logger,
            IEventBus eventBus,
            IServiceProvider serviceProvider,
            IServiceScopeFactory scopeFactory,
            IAdminMenuService adminMenuService,
            PluginActionDescriptorChangeProvider changeProvider,
            PluginStateService pluginStateService)
        {
            _logger = logger;
            _eventBus = eventBus;
            _serviceProvider = serviceProvider;
            _scopeFactory = scopeFactory;
            _adminMenuService = adminMenuService;
            _actionDescriptorProvider = serviceProvider.GetRequiredService<IActionDescriptorCollectionProvider>();
            _changeProvider = changeProvider;
            _pluginStateService = pluginStateService;
        }

        public void Initialize(
            ApplicationPartManager partManager,
            IWebHostEnvironment env)
        {
            _partManager = partManager;
            _env = env;
            _razorEngine = _serviceProvider.GetService<IRazorViewEngine>();

            _logger.Log("✅ PluginManager initialized");
        }

        public async Task LoadPluginsAsync(string pluginsDirectory = "plugins")
        {
            if (!Directory.Exists(pluginsDirectory))
                Directory.CreateDirectory(pluginsDirectory);

            var pluginFiles = Directory.GetFiles(
                pluginsDirectory,
                "*.dll",
                SearchOption.TopDirectoryOnly);

            foreach (var dll in pluginFiles)
            {
                await LoadPluginAsync(dll);
            }

            _logger.Log($"✅ Loaded {_loadedPlugins.Count} plugins");
        }

        public void RegisterRoute(string path, string pluginName, RequestDelegate handler)
        {
            _legacyRoutes[path] = handler;
            _legacyRoutesToPluginMap[path] = pluginName;
            _logger.Log($"🔗 Legacy route registered: {path} (Plugin: {pluginName})");
        }

        public RequestDelegate? GetRouteHandler(string path)
        {
            if (_legacyRoutes.TryGetValue(path, out var handler))
            {
                var pluginName = _legacyRoutesToPluginMap.TryGetValue(path, out var name) ? name : null;

                if (pluginName == null || IsPluginEnabled(pluginName))
                    return handler;
            }
            return null;
        }

        public async Task LoadPluginFromFileAsync(
            string dllFile,
            string? unusedTempDir = null)
        {
            await LoadPluginAsync(dllFile);
        }

        public async Task LoadPluginAsync(string dllPath)
        {
            try
            {
                dllPath = Path.GetFullPath(dllPath);

                if (!File.Exists(dllPath))
                {
                    _logger.LogError($"Plugin not found: {dllPath}");
                    return;
                }

                _logger.Log($"📦 Loading plugin: {Path.GetFileName(dllPath)}");

                var loadContext = new PluginLoadContext(dllPath);
                var assembly = loadContext.LoadFromAssemblyPath(dllPath);

                _loadContexts[dllPath] = loadContext;
                _assemblies[dllPath] = assembly;

                var pluginTypes = assembly.GetTypes().Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsAbstract && !t.IsInterface);
                foreach (var type in pluginTypes)
                {
                    if (Activator.CreateInstance(type) is not IPlugin plugin)
                        continue;

                    foreach (var assemblyType in assembly.GetTypes())
                        _typeToPluginMap[assemblyType] = plugin.Name;

                    _loadedPlugins[plugin.Name] = plugin;
                    _pluginToAssemblyPath[plugin.Name] = dllPath;
                    _pluginAssemblies[plugin.Name] = assembly;

                    var savedState = _pluginStateService.IsEnabled(plugin.Name);
                    _pluginEnabledState[plugin.Name] = savedState;

                    if (savedState)
                    {
                        RegisterApplicationPart(assembly);
                        _changeProvider.NotifyChange();
                        InvalidateActionDescriptorCache();
                        await plugin.OnLoadAsync(new PluginContext(_logger, _scopeFactory, _serviceProvider, _adminMenuService, plugin.Name));
                    }

                    _logger.Log($"✅ Plugin initialized: {plugin.Name}");
                    await _eventBus.PublishAsync(new PluginLoadedEvent(plugin));
                }

                _loadedAssemblyPaths.Add(dllPath);
                _logger.Log($"📚 Plugin assembly loaded: {assembly.GetName().Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Plugin load failed: {ex.Message}\n{ex.StackTrace}");
            }
        }

        private void RegisterApplicationPart(Assembly assembly)
        {
            if (_partManager == null)
                throw new InvalidOperationException("PluginManager.Initialize() not called");

            bool alreadyRegistered = _partManager.ApplicationParts
                .OfType<AssemblyPart>()
                .Any(a => a.Assembly == assembly);

            if (alreadyRegistered)
            {
                _logger.Log($"⚠️  ApplicationPart already registered: {assembly.GetName().Name}");
                return;
            }

            _partManager.ApplicationParts.Add(new AssemblyPart(assembly));
            _partManager.ApplicationParts.Add(new CompiledRazorAssemblyPart(assembly));

            _logger.Log($"🧩 Registered ApplicationPart: {assembly.GetName().Name}");
        }

        private void RemoveApplicationPart(Assembly assembly)
        {
            if (_partManager == null)
                throw new InvalidOperationException("PluginManager.Initialize() not called");

            var assemblyParts = _partManager.ApplicationParts
                .OfType<AssemblyPart>()
                .Where(a => a.Assembly == assembly)
                .ToList();

            foreach (var part in assemblyParts)
            {
                _partManager.ApplicationParts.Remove(part);
                _logger.Log($"🧩 Removed ApplicationPart: {assembly.GetName().Name}");
            }

            var razorParts = _partManager.ApplicationParts
                .OfType<CompiledRazorAssemblyPart>()
                .Where(a => a.Assembly == assembly)
                .ToList();

            foreach (var part in razorParts)
            {
                _partManager.ApplicationParts.Remove(part);
                _logger.Log($"📄 Removed RazorPart: {assembly.GetName().Name}");
            }
        }

        public IReadOnlyDictionary<string, IPlugin> GetLoadedPlugins() => _loadedPlugins;
        private const int ReloadStabilizationDelayMs = 1000;

        public async Task ReloadAllPluginsAsync()
        {
            await UnloadAllPluginsAsync();
            await Task.Delay(ReloadStabilizationDelayMs);
            await LoadPluginsAsync();
        }

        public async Task UnloadPluginAsync(string pluginName)
        {
            if (!_loadedPlugins.TryGetValue(pluginName, out var plugin))
                return;

            try
            {
                await plugin.OnUnloadAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Plugin unload error: {ex}");
            }

            _loadedPlugins.TryRemove(pluginName, out _);
            _pluginEnabledState.TryRemove(pluginName, out _);

            foreach (var kvp in _typeToPluginMap.Where(x => x.Value == pluginName).ToList())
                _typeToPluginMap.TryRemove(kvp.Key, out _);

            var pluginMenuItems = _adminMenuService.GetItems()
                .Where(x => x.ResponsiblePlugin == pluginName)
                .ToList();
            foreach (var item in pluginMenuItems)
                _adminMenuService.UnRegister(item);

            if (_pluginAssemblies.TryRemove(pluginName, out var assembly))
                RemoveApplicationPart(assembly);

            if (_pluginToAssemblyPath.TryRemove(pluginName, out var dllPath))
            {
                _assemblies.TryRemove(dllPath, out _);
                _loadedAssemblyPaths.Remove(dllPath);

                if (_loadContexts.TryRemove(dllPath, out var context))
                    context.Unload();
            }

            _changeProvider.NotifyChange();

            GC.Collect();
            GC.WaitForPendingFinalizers();

            _logger.Log($"🧹 Plugin unloaded: {pluginName}");
        }

        public async Task UnloadAllPluginsAsync()
        {
            foreach (var plugin in _loadedPlugins.Values)
            {
                try
                {
                    await plugin.OnUnloadAsync();
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Plugin unload error: {ex}");
                }
            }

            _loadedPlugins.Clear();
            _typeToPluginMap.Clear();

            foreach (var context in _loadContexts.Values)
            {
                try
                {
                    context.Unload();
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Plugin context unload error: {ex}");
                }
            }

            _loadContexts.Clear();
            _assemblies.Clear();
            _pluginAssemblies.Clear();
            _pluginToAssemblyPath.Clear();

            GC.Collect();
            GC.WaitForPendingFinalizers();

            _logger.Log("🧹 Plugins unloaded");
        }

        public async Task<bool> EnablePluginAsync(string pluginName)
        {
            if (!_loadedPlugins.ContainsKey(pluginName))
            {
                _logger.LogError($"Plugin not found: {pluginName}");
                return false;
            }

            if (_pluginEnabledState.TryGetValue(pluginName, out var isEnabled) && isEnabled)
            {
                _logger.Log($"⚠️ Plugin already enabled: {pluginName}");
                return true;
            }

            if (_pluginAssemblies.TryGetValue(pluginName, out var assembly))
            {
                RegisterApplicationPart(assembly);
                _changeProvider.NotifyChange();
            }

            _pluginEnabledState[pluginName] = true;
            _pluginStateService.SetEnabled(pluginName, true);
            var plugin = _loadedPlugins[pluginName];

            try
            {
                await plugin.OnLoadAsync(new PluginContext(_logger, _scopeFactory, _serviceProvider, _adminMenuService, plugin.Name));
            }
            catch (Exception ex)
            {
                _logger.LogError($"Plugin onload error: {ex}");
            }

            InvalidateActionDescriptorCache();
            _logger.Log($"✅ Plugin enabled and routes added: {pluginName}");
            return true;
        }

        public async Task<bool> DisablePluginAsync(string pluginName)
        {
            if (!_loadedPlugins.ContainsKey(pluginName))
            {
                _logger.LogError($"Plugin not found: {pluginName}");
                return false;
            }

            if (_pluginEnabledState.TryGetValue(pluginName, out var isEnabled) && !isEnabled)
            {
                _logger.Log($"⚠️ Plugin already disabled: {pluginName}");
                return true;
            }


            var plugin = _loadedPlugins[pluginName];

            try
            {
                await plugin.OnUnloadAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Plugin onunload error: {ex}");
            }

            _pluginEnabledState[pluginName] = false;
            _pluginStateService.SetEnabled(pluginName, false);

            var pluginMenuItems = _adminMenuService.GetItems().Where(item => item.ResponsiblePlugin == pluginName).ToList();
            if (pluginMenuItems.Count > 0)
                foreach (var menuItem in pluginMenuItems)
                    _adminMenuService.UnRegister(menuItem);

            if (_pluginToAssemblyPath.TryGetValue(pluginName, out var dllPath))
            {
                if (_pluginAssemblies.TryGetValue(pluginName, out var assembly))
                {
                    RemoveApplicationPart(assembly);
                    _changeProvider.NotifyChange();
                }

                if (_loadContexts.TryGetValue(dllPath, out var context))
                {
                    context.Unload();
                    _loadContexts.TryRemove(dllPath, out _);
                    _assemblies.TryRemove(dllPath, out _);
                }
            }

            InvalidateActionDescriptorCache();
            _logger.Log($"🔇 Plugin disabled and unloaded: {pluginName}");
            return true;
        }

        public bool IsPluginEnabled(string pluginName)
        {
            return _pluginEnabledState.TryGetValue(pluginName, out var enabled) && enabled;
        }

        public bool IsTypeFromDisabledPlugin(Type type)
        {
            if (_typeToPluginMap.TryGetValue(type, out var pluginName))
            {
                return !IsPluginEnabled(pluginName);
            }
            return false;
        }

        public IReadOnlyDictionary<string, IPlugin> GetEnabledPlugins()
        {
            return _loadedPlugins
                .Where(x => IsPluginEnabled(x.Key))
                .ToDictionary(x => x.Key, x => x.Value);
        }

        public async Task UpdateLoadedPluginsAsync(CancellationToken cancellationToken = default)
        {
            foreach (var plugin in _loadedPlugins.Values)
            {
                if (!IsPluginEnabled(plugin.Name))
                    continue;

                if (cancellationToken.IsCancellationRequested)
                    break;

                try
                {
                    await plugin.OnUpdateAsync(new PluginContext(_logger, _scopeFactory, _serviceProvider, _adminMenuService, plugin.Name));
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Plugin update failed: {ex}");
                }
            }
        }

        private void InvalidateActionDescriptorCache()
        {
            if (_actionDescriptorProvider is ActionDescriptorCollectionProvider provider)
            {
                var field = typeof(ActionDescriptorCollectionProvider)
                    .GetField("_actionDescriptors", BindingFlags.NonPublic | BindingFlags.Instance);
                field?.SetValue(provider, null);
            }
        }
    }

    public class PluginLoadContext : AssemblyLoadContext
    {
        private readonly AssemblyDependencyResolver _resolver;

        public PluginLoadContext(string pluginPath)
            : base(isCollectible: true)
        {
            _resolver = new AssemblyDependencyResolver(pluginPath);
        }

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            var path = _resolver.ResolveAssemblyToPath(assemblyName);
            return path != null ? LoadFromAssemblyPath(path) : null;
        }

        protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
        {
            var path = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
            return path != null ? LoadUnmanagedDllFromPath(path) : IntPtr.Zero;
        }
    }

    public interface IAdminMenuService
    {
        void Register(AdminMenuItem item);
        void UnRegister(AdminMenuItem item);
        IReadOnlyList<AdminMenuItem> GetItems();
    }

    public class AdminMenuService : IAdminMenuService
    {
        private readonly List<AdminMenuItem> _items = new();

        public void Register(AdminMenuItem item)
        {
            if (_items.Any(x => x.Url == item.Url))
                return;

            _items.Add(item);
        }

        public void UnRegister(AdminMenuItem item)
        {
            if (!_items.Contains(item))
                return;

            _items.Remove(item);
        }


        public IReadOnlyList<AdminMenuItem> GetItems() => _items.AsReadOnly();
    }

    public class AdminMenuItem
    {
        public string ResponsiblePlugin { get; set; } = "";
        public string Name { get; set; } = "";
        public string IconSvg { get; set; } = "";
        public string Url { get; set; } = "";
        public int Order { get; set; }
    }

    public class PluginActionDescriptorChangeProvider : IActionDescriptorChangeProvider
    {
        private CancellationTokenSource _cts = new();

        public IChangeToken GetChangeToken()
            => new CancellationChangeToken(_cts.Token);

        public void NotifyChange()
        {
            using var newCts = new CancellationTokenSource();
            var old = Interlocked.Exchange(ref _cts, newCts);
            old.Cancel();
            old.Dispose();
        }
    }
}