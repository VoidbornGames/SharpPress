using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SharpPress.Services;
using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.Loader;

namespace SharpPress.Modules
{
    /// <summary>
    /// A module runs BEFORE and AFTER app.Build() — giving it direct access to
    /// service registration and middleware pipeline. NOT hot-pluggable.
    /// Changes to enabled state require application restart.
    /// </summary>
    public interface IModule
    {
        string Name { get; }
        string Description { get; }
        string Version { get; }
        string Author { get; }

        /// <summary>Lower runs first. Use for ordering when modules depend on each other.</summary>
        int Order { get; }

        /// <summary>Called before builder.Build(). Register services here.</summary>
        void BeforeBuild(ModuleBuilderContext context);

        /// <summary>Called after builder.Build(). Add middleware, map endpoints, etc.</summary>
        void AfterBuild(ModuleAppContext context);
    }

    public sealed class ModuleBuilderContext
    {
        public WebApplicationBuilder Builder { get; }
        public IConfiguration Configuration => Builder.Configuration;
        public IWebHostEnvironment Environment => Builder.Environment;
        public IServiceCollection Services => Builder.Services;
        public Logger Logger { get; }
        public string ModulePath { get; }
        public Assembly ModuleAssembly { get; }

        public ModuleBuilderContext(
            WebApplicationBuilder builder,
            Logger logger,
            string modulePath,
            Assembly moduleAssembly)
        {
            Builder = builder;
            Logger = logger;
            ModulePath = modulePath;
            ModuleAssembly = moduleAssembly;
        }
    }

    public sealed class ModuleAppContext
    {
        public WebApplication App { get; }
        public IServiceProvider Services => App.Services;
        public IWebHostEnvironment Environment => App.Environment;
        public IConfiguration Configuration => App.Configuration;
        public IHostApplicationLifetime Lifetime => App.Lifetime;
        public Logger Logger { get; }
        public string ModulePath { get; }
        public Assembly ModuleAssembly { get; }

        public ModuleAppContext(
            WebApplication app,
            Logger logger,
            string modulePath,
            Assembly moduleAssembly)
        {
            App = app;
            Logger = logger;
            ModulePath = modulePath;
            ModuleAssembly = moduleAssembly;
        }
    }

    /// <summary>
    /// Persists module enabled-state to a simple text file.
    /// Read at startup — changes apply on next restart.
    /// </summary>
    public class ModuleStateService
    {
        private readonly ConcurrentDictionary<string, bool> _state = new();
        private readonly string _stateFile;

        public ModuleStateService(string stateFile = "modules/state.txt")
        {
            _stateFile = stateFile;
            Load();
        }

        public bool IsEnabled(string moduleName)
            => _state.TryGetValue(moduleName, out var enabled) && enabled;

        public void SetEnabled(string moduleName, bool enabled)
        {
            _state[moduleName] = enabled;
            Save();
        }

        public IReadOnlyDictionary<string, bool> GetAll() => _state;

        private void Load()
        {
            try
            {
                if (!File.Exists(_stateFile)) return;
                foreach (var line in File.ReadAllLines(_stateFile))
                {
                    var idx = line.IndexOf('|');
                    if (idx <= 0) continue;

                    var name = line[..idx];
                    if (bool.TryParse(line[(idx + 1)..], out var enabled))
                        _state[name] = enabled;
                }
            }
            catch { }
        }

        private void Save()
        {
            try
            {
                var dir = Path.GetDirectoryName(_stateFile);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                File.WriteAllLines(_stateFile, _state.Select(kv => $"{kv.Key}|{kv.Value}"));
            }
            catch { }
        }
    }

    /// <summary>
    /// Non-collectible load context — modules stay loaded for app lifetime.
    /// </summary>
    public class ModuleLoadContext : AssemblyLoadContext
    {
        private readonly AssemblyDependencyResolver _resolver;
        private static readonly HashSet<string> _sharedPrefixes = new()
        {
            "SharpPress",
            "Microsoft.AspNetCore",
            "Microsoft.Extensions",
            "Microsoft.Net.Http",
            "System"
        };

        public ModuleLoadContext(string modulePath) : base(isCollectible: false)
        {
            _resolver = new AssemblyDependencyResolver(modulePath);
        }

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            var name = assemblyName.Name ?? "";
            if (_sharedPrefixes.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                return null;

            var path = _resolver.ResolveAssemblyToPath(assemblyName);
            return path != null ? LoadFromAssemblyPath(path) : null;
        }

        protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
        {
            var path = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
            return path != null ? LoadUnmanagedDllFromPath(path) : IntPtr.Zero;
        }
    }

    public class ModuleManager
    {
        private readonly Logger _logger;
        private readonly ModuleStateService _stateService;

        private readonly List<IModule> _orderedModules = new();
        private readonly ConcurrentDictionary<string, ModuleEntry> _entries = new();

        public IReadOnlyList<IModule> Modules => _orderedModules;

        public ModuleManager(Logger logger, ModuleStateService stateService)
        {
            _logger = logger;
            _stateService = stateService;
        }

        public Task LoadModulesAsync(string modulesDirectory = "modules")
        {
            if (!Directory.Exists(modulesDirectory))
                Directory.CreateDirectory(modulesDirectory);

            var dllFiles = Directory.GetFiles(modulesDirectory, "*.dll", SearchOption.TopDirectoryOnly);

            foreach (var dll in dllFiles)
            {
                try { LoadModuleFile(dll); }
                catch (Exception ex)
                {
                    _logger.LogError($"Failed to load module from {dll}: {ex.Message}");
                }
            }
            _orderedModules.Sort((a, b) => a.Order.CompareTo(b.Order));

            _logger.Log($"✅ Loaded {_orderedModules.Count} modules " + $"({_orderedModules.Count(m => IsEnabled(m.Name))} enabled)");
            return Task.CompletedTask;
        }

        private void LoadModuleFile(string dllPath)
        {
            dllPath = Path.GetFullPath(dllPath);
            if (!File.Exists(dllPath))
            {
                _logger.LogError($"Module not found: {dllPath}");
                return;
            }

            _logger.Log($"📦 Loading module: {Path.GetFileName(dllPath)}");

            var loadContext = new ModuleLoadContext(dllPath);
            var assembly = loadContext.LoadFromAssemblyPath(dllPath);

            var moduleTypes = assembly.GetTypes()
                .Where(t => typeof(IModule).IsAssignableFrom(t) && !t.IsAbstract && !t.IsInterface);

            foreach (var type in moduleTypes)
            {
                if (Activator.CreateInstance(type) is not IModule module)
                    continue;

                if (_entries.ContainsKey(module.Name))
                {
                    _logger.Log($"⚠️  Module already loaded, skipping: {module.Name}");
                    continue;
                }

                var entry = new ModuleEntry
                {
                    Module = module,
                    Assembly = assembly,
                    LoadContext = loadContext,
                    Path = dllPath
                };
                _entries[module.Name] = entry;
                _orderedModules.Add(module);

                _logger.Log($"   • Discovered: {module.Name} v{module.Version} " + $"(order={module.Order}, enabled={IsEnabled(module.Name)})");
            }
        }

        public void RunBeforeBuild(WebApplicationBuilder builder)
        {
            foreach (var module in _orderedModules)
            {
                if (!IsEnabled(module.Name))
                {
                    _logger.Log($"⏭️  Skipping disabled module (BeforeBuild): {module.Name}");
                    continue;
                }

                var entry = _entries[module.Name];
                var ctx = new ModuleBuilderContext(
                    builder, _logger, entry.Path, entry.Assembly);

                try
                {
                    module.BeforeBuild(ctx);
                    _logger.Log($"🔧 BeforeBuild → {module.Name}");
                }
                catch (Exception ex)
                {
                    _logger.LogError($"BeforeBuild failed for {module.Name}: {ex}");
                }
            }
        }

        public Task RunAfterBuildAsync(WebApplication app)
        {
            foreach (var module in _orderedModules)
            {
                if (!IsEnabled(module.Name))
                {
                    _logger.Log($"⏭️  Skipping disabled module (AfterBuild): {module.Name}");
                    continue;
                }

                var entry = _entries[module.Name];
                var ctx = new ModuleAppContext(
                    app, _logger, entry.Path, entry.Assembly);

                try
                {
                    module.AfterBuild(ctx);
                    _logger.Log($"🚀 AfterBuild  → {module.Name}");
                }
                catch (Exception ex)
                {
                    _logger.LogError($"AfterBuild failed for {module.Name}: {ex}");
                }
            }
            return Task.CompletedTask;
        }

        public bool IsEnabled(string moduleName) => _stateService.IsEnabled(moduleName);

        public bool TryGetModule(string name, out IModule module)
        {
            module = null!;
            if (_entries.TryGetValue(name, out var entry))
            {
                module = entry.Module;
                return true;
            }
            return false;
        }

        public void SetEnabled(string moduleName, bool enabled)
        {
            _stateService.SetEnabled(moduleName, enabled);
            _logger.Log($"📌 Module '{moduleName}' will be {(enabled ? "enabled" : "disabled")} on next restart");
        }

        private sealed class ModuleEntry
        {
            public IModule Module { get; set; } = null!;
            public Assembly Assembly { get; set; } = null!;
            public ModuleLoadContext LoadContext { get; set; } = null!;
            public string Path { get; set; } = "";
        }
    }
}