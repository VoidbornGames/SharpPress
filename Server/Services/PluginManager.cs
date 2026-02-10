using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewEngines;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using RazorEngineCore;
using SharpPress.Events;
using SharpPress.Plugins;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
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

        private readonly IRazorViewEngine _razorViewEngine;
        private readonly ITempDataProvider _tempDataProvider;
        private readonly IModelMetadataProvider _modelMetadataProvider;

        private readonly ApplicationPartManager _appPartManager;

        private readonly ConcurrentDictionary<string, IPlugin> _loadedPlugins = new();
        private readonly ConcurrentDictionary<string, PluginContext> _pluginContexts = new();
        private readonly ConcurrentDictionary<string, PluginLoadContext> _loadContexts = new();
        private readonly ConcurrentDictionary<string, string> _uniquePaths = new();
        private readonly ConcurrentDictionary<string, Func<HttpContext, Task>> _globalRoutes = new();

        // Store embedded razor pages
        private readonly ConcurrentDictionary<string, EmbeddedRazorPage> _embeddedPages = new();

        // RazorEngineCore for compiling embedded templates
        private readonly IRazorEngine _razorEngine;

        // Cache compiled templates
        private readonly ConcurrentDictionary<string, IRazorEngineCompiledTemplate> _compiledTemplates = new();

        public PluginManager(
            Logger logger,
            IEventBus eventBus,
            IServiceProvider serviceProvider,
            IServiceScopeFactory scopeFactory,
            IRazorViewEngine razorViewEngine,
            ITempDataProvider tempDataProvider,
            IModelMetadataProvider modelMetadataProvider,
            ApplicationPartManager appPartManager)
        {
            _logger = logger;
            _eventBus = eventBus;
            _serviceProvider = serviceProvider;
            _scopeFactory = scopeFactory;
            _razorViewEngine = razorViewEngine;
            _tempDataProvider = tempDataProvider;
            _modelMetadataProvider = modelMetadataProvider;
            _appPartManager = appPartManager;

            CustomRazorTemplateBase.SetStaticLogger(logger);

            _razorEngine = new RazorEngine();
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

                // Load embedded Razor pages
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

                            // Store the embedded page
                            var embeddedPage = new EmbeddedRazorPage
                            {
                                ResourceName = resourceName,
                                Content = content,
                                Route = route,
                                Assembly = assembly
                            };
                            _embeddedPages[route] = embeddedPage;

                            // Register the route
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

                // Load plugin types
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

        private void CollectReferencedAssemblies(Type type, HashSet<Assembly> assemblies)
        {
            if (type == null || assemblies.Contains(type.Assembly, new AssemblyComparer()))
                return;

            try
            {
                assemblies.Add(type.Assembly);

                if (type.BaseType != null)
                    CollectReferencedAssemblies(type.BaseType, assemblies);

                foreach (var interfaceType in type.GetInterfaces())
                    CollectReferencedAssemblies(interfaceType, assemblies);

                foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
                {
                    CollectReferencedAssemblies(property.PropertyType, assemblies);
                }

                foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
                {
                    if (method.ReturnType != typeof(void))
                        CollectReferencedAssemblies(method.ReturnType, assemblies);

                    foreach (var param in method.GetParameters())
                        CollectReferencedAssemblies(param.ParameterType, assemblies);
                }

                if (type.IsGenericType)
                {
                    foreach (var genericArg in type.GetGenericArguments())
                        CollectReferencedAssemblies(genericArg, assemblies);
                }
            }
            catch { }
        }

        private async Task RenderEmbeddedRazorPage(HttpContext context, EmbeddedRazorPage embeddedPage)
        {
            try
            {
                var razorContent = embeddedPage.Content;
                var parseResult = ParseRazorDirectives(razorContent);
                
                _logger.Log($"🔌 Parsed directives - Usings: {parseResult.Usings.Count}, InjectDirectives: {parseResult.InjectDirectives.Count}, Model: {parseResult.ModelTypeName ?? "none"}");
                foreach (var inj in parseResult.InjectDirectives)
                {
                    _logger.Log($"   - @inject {inj.ServiceTypeName} {inj.PropertyName}");
                }
                
                var templateKey = $"{embeddedPage.ResourceName}_{embeddedPage.Route}";

                if (!_compiledTemplates.TryGetValue(templateKey, out var compiledTemplate))
                {
                    var modifiedContent = BuildModifiedRazorContent(parseResult, embeddedPage.Assembly);
                    
                    _logger.Log($"🔌 After BuildModifiedRazorContent - Injects: {parseResult.Injects.Count}");
                    foreach (var inj in parseResult.Injects)
                    {
                        _logger.Log($"   - Resolved: {inj.PropertyName} -> {inj.ServiceType.FullName}");
                    }

                    compiledTemplate = await _razorEngine.CompileAsync(modifiedContent, builder =>
                    {
                        builder.Inherits(typeof(CustomRazorTemplateBase));

                        var referencedAssemblies = new HashSet<Assembly>(new AssemblyComparer());
                        referencedAssemblies.Add(typeof(object).Assembly);
                        referencedAssemblies.Add(typeof(Console).Assembly);
                        referencedAssemblies.Add(typeof(IEnumerable<>).Assembly);
                        referencedAssemblies.Add(typeof(HttpContext).Assembly);
                        referencedAssemblies.Add(typeof(List<>).Assembly);
                        referencedAssemblies.Add(Assembly.GetExecutingAssembly());
                        referencedAssemblies.Add(embeddedPage.Assembly);

                        try
                        {
                            var systemCollectionsAsm = Assembly.Load("System.Collections");
                            referencedAssemblies.Add(systemCollectionsAsm);
                        }
                        catch { }

                        try
                        {
                            var systemLinqAsm = Assembly.Load("System.Linq");
                            referencedAssemblies.Add(systemLinqAsm);
                        }
                        catch { }

                        try
                        {
                            var systemRuntimeAsm = Assembly.Load("System.Runtime");
                            referencedAssemblies.Add(systemRuntimeAsm);
                        }
                        catch { }

                        try
                        {
                            var systemTextAsm = Assembly.Load("System.Text.RegularExpressions");
                            referencedAssemblies.Add(systemTextAsm);
                        }
                        catch { }

                        var currentDomainAssemblies = AppDomain.CurrentDomain.GetAssemblies();
                        foreach (var asm in currentDomainAssemblies)
                        {
                            if (asm.FullName != null && (asm.FullName.StartsWith("System.") || asm.FullName.StartsWith("Microsoft.")))
                            {
                                referencedAssemblies.Add(asm);
                            }
                        }

                        foreach (var inject in parseResult.Injects)
                        {
                            CollectReferencedAssemblies(inject.ServiceType, referencedAssemblies);
                        }

                        if (parseResult.ModelType != null)
                        {
                            CollectReferencedAssemblies(parseResult.ModelType, referencedAssemblies);
                        }

                        foreach (var assembly in referencedAssemblies)
                        {
                            try
                            {
                                builder.AddAssemblyReference(assembly);
                            }
                            catch { }
                        }

                        foreach (var usingDirective in parseResult.Usings)
                        {
                            builder.AddUsing(usingDirective);
                        }
                    });

                    _compiledTemplates[templateKey] = compiledTemplate;
                }
                else
                {
                    _logger.Log($"🔌 Template cached, resolving inject types for this request...");
                    ResolveInjectTypes(parseResult, embeddedPage.Assembly);
                    _logger.Log($"🔌 Injects resolved: {parseResult.Injects.Count}");
                }

                // Create model instance if needed
                object? model = null;
                if (parseResult.ModelType != null)
                {
                    model = Activator.CreateInstance(parseResult.ModelType);
                    await TryPopulateModel(context, model!, parseResult.ModelType);
                }

                // Resolve injected services
                var injectedServices = new Dictionary<string, object>();
                _logger.Log($"🔌 Resolving {parseResult.Injects.Count} injected services...");
                
                foreach (var inject in parseResult.Injects)
                {
                    try
                    {
                        object? service = null;
                        _logger.Log($"   - Looking for {inject.PropertyName} ({inject.ServiceType.FullName})");
                        
                        service = _serviceProvider.GetService(inject.ServiceType);
                        _logger.Log($"     Result: {(service != null ? "Found" : "Not found")}");
                        
                        if (service == null && _serviceProvider is ServiceProvider sp)
                        {
                            var serviceDescriptors = sp.GetType().GetProperty("Root", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?.GetValue(sp);
                            if (serviceDescriptors != null)
                            {
                                foreach (var serviceProperty in serviceDescriptors.GetType().GetProperties())
                                {
                                    if (serviceProperty.PropertyType.FullName == inject.ServiceType.FullName)
                                    {
                                        service = serviceProperty.GetValue(serviceDescriptors);
                                        _logger.Log($"     Found in Root (via reflection)");
                                        break;
                                    }
                                }
                            }
                        }
                        
                        if (service == null)
                        {
                            using (var scope = _serviceProvider.CreateScope())
                            {
                                service = scope.ServiceProvider.GetService(inject.ServiceType);
                                if (service != null)
                                {
                                    _logger.Log($"     Found in scoped provider");
                                }
                            }
                        }
                        
                        if (service != null)
                        {
                            injectedServices[inject.PropertyName] = service;
                            _logger.Log($"     ✓ Registered: {inject.PropertyName}");
                        }
                        else
                        {
                            _logger.LogError($"   ✗ Could not resolve injected service: {inject.ServiceType.FullName} for property {inject.PropertyName}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"   ✗ Exception resolving {inject.PropertyName}: {ex.Message}");
                    }
                }

                var renderContext = new TemplateRenderContext
                {
                    Model = model,
                    HttpContext = context,
                    ServiceProvider = _serviceProvider,
                    InjectedServices = injectedServices
                };
                renderContext.ViewBag["Request"] = context.Request;
                renderContext.ViewBag["Response"] = context.Response;
                renderContext.ViewBag["User"] = context.User;
                renderContext.ViewBag["Path"] = context.Request.Path.Value;
                renderContext.ViewBag["Method"] = context.Request.Method;

                renderContext.ViewData["Request"] = context.Request;
                renderContext.ViewData["Response"] = context.Response;
                renderContext.ViewData["User"] = context.User;
                renderContext.ViewData["Path"] = context.Request.Path.Value;
                renderContext.ViewData["Method"] = context.Request.Method;

                CustomRazorTemplateBase.SetRenderContext(renderContext);
                
                _logger.Log($"🔌 Set render context with {renderContext.InjectedServices.Count} services");

                string renderedHtml = await compiledTemplate.RunAsync((Action<object?>)(instance =>
                {
                    _logger.Log($"🔌 RunAsync - Type: {instance?.GetType().Name ?? "null"}");
                    
                    if (instance == null)
                    {
                        _logger.LogError("🔌 ERROR: RunAsync called with null instance!");
                        return;
                    }

                    var instanceType = instance.GetType();
                    _logger.Log($"🔌 Instance type: {instanceType.FullName}");

                    var isCustomBase = instance is CustomRazorTemplateBase;
                    _logger.Log($"🔌 Is CustomRazorTemplateBase: {isCustomBase}");
                    
                    if (instance is CustomRazorTemplateBase customBase)
                    {
                        _logger.Log($"🔌 Setting instance properties as fallback");
                        customBase.Model = model;
                        customBase.Context = context;
                        customBase.ServiceProvider = _serviceProvider;

                        customBase.InjectedServices.Clear();
                        foreach (var kvp in injectedServices)
                        {
                            customBase.InjectedServices[kvp.Key] = kvp.Value;
                        }
                        
                        customBase.ViewBag["Request"] = context.Request;
                        customBase.ViewBag["Response"] = context.Response;
                        customBase.ViewBag["User"] = context.User;
                        customBase.ViewBag["Path"] = context.Request.Path.Value;
                        customBase.ViewBag["Method"] = context.Request.Method;

                        customBase.ViewData["Request"] = context.Request;
                        customBase.ViewData["Response"] = context.Response;
                        customBase.ViewData["User"] = context.User;
                        customBase.ViewData["Path"] = context.Request.Path.Value;
                        customBase.ViewData["Method"] = context.Request.Method;
                    }
                    else
                    {
                        _logger.LogError($"🔌 WARNING: Instance is {instanceType.FullName}, not CustomRazorTemplateBase");
                    }
                }));

                CustomRazorTemplateBase.SetRenderContext(null);

                if (!string.IsNullOrEmpty(parseResult.Layout))
                {
                    _logger.Log($"🔌 Layout specified: {parseResult.Layout}");
                    var layoutContent = await TryLoadLayoutAsync(parseResult.Layout, renderContext, renderedHtml);
                    if (layoutContent != null)
                    {
                        renderedHtml = layoutContent;
                    }
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

        private RazorParseResult ParseRazorDirectives(string razorContent)
        {
            var result = new RazorParseResult
            {
                OriginalContent = razorContent
            };

            // Extract @using directives
            var usingMatches = Regex.Matches(razorContent, @"@using\s+([^\r\n]+)");
            foreach (Match match in usingMatches)
            {
                result.Usings.Add(match.Groups[1].Value.Trim());
            }

            // Extract @model directive
            var modelMatch = Regex.Match(razorContent, @"@model\s+([^\r\n]+)");
            if (modelMatch.Success)
            {
                result.ModelTypeName = modelMatch.Groups[1].Value.Trim();
            }

            // Extract @inject directives
            var injectMatches = Regex.Matches(razorContent, @"@inject\s+([^\s]+)\s+([^\r\n]+)");
            _logger.Log($"🔌 ParseRazorDirectives found {injectMatches.Count} @inject directives");
            
            foreach (Match match in injectMatches)
            {
                var serviceTypeName = match.Groups[1].Value.Trim();
                var propertyName = match.Groups[2].Value.Trim();
                result.InjectDirectives.Add((serviceTypeName, propertyName));
                _logger.Log($"   - {serviceTypeName} -> {propertyName}");
            }

            // Extract Layout
            var layoutMatch = Regex.Match(razorContent, @"Layout\s*=\s*[""']([^""']+)[""']");
            if (layoutMatch.Success)
            {
                result.Layout = layoutMatch.Groups[1].Value;
                _logger.Log($"🔌 Found Layout: {result.Layout}");
            }
            else
            {
                var layoutMatch2 = Regex.Match(razorContent, @"Layout\s*=\s*([^\r\n;]+)");
                if (layoutMatch2.Success)
                {
                    result.Layout = layoutMatch2.Groups[1].Value.Trim();
                    _logger.Log($"🔌 Found Layout: {result.Layout}");
                }
            }

            return result;
        }

        private void ResolveInjectTypes(RazorParseResult parseResult, Assembly pluginAssembly)
        {
            foreach (var (serviceTypeName, propertyName) in parseResult.InjectDirectives)
            {
                _logger.Log($"🔌 Resolving service type: {serviceTypeName} for property: {propertyName}");
                
                var serviceType = pluginAssembly.GetTypes()
                    .FirstOrDefault(t => t.FullName == serviceTypeName || t.Name == serviceTypeName);
                
                if (serviceType == null)
                {
                    _logger.Log($"   Not found in plugin assembly, checking SharpPress...");
                    serviceType = Assembly.GetExecutingAssembly().GetTypes()
                        .FirstOrDefault(t => t.FullName == serviceTypeName || t.Name == serviceTypeName);
                }

                if (serviceType == null)
                {
                    _logger.Log($"   Not found in SharpPress, checking all loaded assemblies...");
                    var allLoadedAssemblies = AppDomain.CurrentDomain.GetAssemblies();
                    serviceType = allLoadedAssemblies
                        .SelectMany(a => 
                        {
                            try { return a.GetTypes(); }
                            catch { return new Type[0]; }
                        })
                        .FirstOrDefault(t => t.FullName == serviceTypeName || t.Name == serviceTypeName);
                }

                if (serviceType != null)
                {
                    parseResult.Injects.Add((serviceType, propertyName));
                    _logger.Log($"   ✓ Resolved to {serviceType.FullName}");
                    
                    if (!string.IsNullOrEmpty(serviceType.Namespace) && !parseResult.Usings.Contains(serviceType.Namespace))
                    {
                        parseResult.Usings.Add(serviceType.Namespace);
                    }
                }
                else
                {
                    _logger.LogError($"✗ Could not resolve injected service type: {serviceTypeName}");
                }
            }
        }

        private void ReplaceInjectDirectivesInContent(ref string content)
        {
            var injectMatches = Regex.Matches(content, @"@inject\s+([^\s]+)\s+([^\r\n]+)");
            var injectReplacements = new Dictionary<string, string>();
            
            foreach (Match match in injectMatches)
            {
                var typeName = match.Groups[1].Value.Trim();
                var propertyName = match.Groups[2].Value.Trim();
                injectReplacements[propertyName] = typeName;
            }
            
            content = Regex.Replace(content, @"@inject\s+([^\s]+)\s+([^\r\n]+)[\r\n]*", "");
            
            foreach (var kvp in injectReplacements)
            {
                content = Regex.Replace(content, @"\b" + Regex.Escape(kvp.Key) + @"\b", $"GetInjectedService<{kvp.Value}>(\"{kvp.Key}\")");
            }
        }

        private string BuildModifiedRazorContent(RazorParseResult parseResult, Assembly pluginAssembly)
        {
            var content = parseResult.OriginalContent;

            // Remove @page directive
            content = Regex.Replace(content, @"@page\s+""[^""]+""", "");

            // Remove @using directives (we add them via builder)
            content = Regex.Replace(content, @"@using\s+[^\r\n]+[\r\n]*", "");

            // Remove @model directive (we handle it via template base)
            content = Regex.Replace(content, @"@model\s+[^\r\n]+[\r\n]*", "");

            // Replace @inject directives with property access
            ReplaceInjectDirectivesInContent(ref content);

            // Remove Layout directives from content (they're handled separately)
            content = Regex.Replace(content, @"Layout\s*=\s*[""'][^""']+[""'];?\s*[\r\n]*", "");
            content = Regex.Replace(content, @"Layout\s*=\s*[^\r\n;]+;?\s*[\r\n]*", "");
            
            // Remove @using directives that may be on same line as Layout
            content = Regex.Replace(content, @"^\s*Layout\s*=\s*.*$", "", RegexOptions.Multiline);

            // Resolve model type if specified
            if (!string.IsNullOrEmpty(parseResult.ModelTypeName))
            {
                parseResult.ModelType = pluginAssembly.GetTypes()
                    .FirstOrDefault(t => t.FullName == parseResult.ModelTypeName || t.Name == parseResult.ModelTypeName);
            }

            ResolveInjectTypes(parseResult, pluginAssembly);

            return content;
        }

        private async Task<string?> TryLoadLayoutAsync(string layoutName, TemplateRenderContext context, string content)
        {
            try
            {
                var layoutName_clean = layoutName.TrimStart('~', '/');
                if (!layoutName_clean.EndsWith(".cshtml"))
                    layoutName_clean += ".cshtml";

                string? layoutContent = null;

                var layoutResourceName = $"SharpPress.Pages.{layoutName_clean}";
                _logger.Log($"🔌 Looking for layout resource: {layoutResourceName}");

                var mainAssembly = Assembly.GetExecutingAssembly();
                var resourceNames = mainAssembly.GetManifestResourceNames();
                
                _logger.Log($"🔌 Total resources in assembly: {resourceNames.Length}");
                _logger.Log($"🔌 All resources: {string.Join(", ", resourceNames.Take(20))}");
                
                var matchingResource = resourceNames.FirstOrDefault(r => r.EndsWith(layoutName_clean, StringComparison.OrdinalIgnoreCase));
                
                if (matchingResource == null)
                {
                    matchingResource = resourceNames.FirstOrDefault(r => r.Contains("_AdminLayout"));
                    if (matchingResource != null)
                    {
                        _logger.Log($"🔌 Found similar resource by name search: {matchingResource}");
                    }
                }
                
                if (matchingResource != null)
                {
                    _logger.Log($"🔌 Found layout resource: {matchingResource}");
                    using (var stream = mainAssembly.GetManifestResourceStream(matchingResource))
                    {
                        if (stream != null)
                        {
                            using (var reader = new StreamReader(stream))
                            {
                                layoutContent = await reader.ReadToEndAsync();
                            }
                        }
                    }
                }

                if (layoutContent == null)
                {
                    _logger.LogError($"Layout resource not found: {layoutName_clean}");
                    var pageResources = resourceNames.Where(r => r.Contains("Pages") || r.Contains("cshtml")).ToList();
                    _logger.Log($"🔌 Resources containing 'Pages' or 'cshtml': {string.Join(", ", pageResources)}");
                    return null;
                }

                _logger.Log($"🔌 Loaded layout from embedded resource");

                var compiledLayout = await _razorEngine.CompileAsync(layoutContent, builder =>
                {
                    builder.Inherits(typeof(CustomRazorTemplateBase));
                    
                    var referencedAssemblies = new HashSet<Assembly>(new AssemblyComparer());
                    referencedAssemblies.Add(typeof(object).Assembly);
                    referencedAssemblies.Add(typeof(HttpContext).Assembly);
                    referencedAssemblies.Add(mainAssembly);
                    
                    var currentDomainAssemblies = AppDomain.CurrentDomain.GetAssemblies();
                    foreach (var asm in currentDomainAssemblies)
                    {
                        if (asm.FullName != null && (asm.FullName.StartsWith("System.") || asm.FullName.StartsWith("Microsoft.")))
                        {
                            referencedAssemblies.Add(asm);
                        }
                    }

                    foreach (var assembly in referencedAssemblies)
                    {
                        try { builder.AddAssemblyReference(assembly); }
                        catch { }
                    }

                    builder.AddUsing("System.Collections.Generic");
                });

                CustomRazorTemplateBase.SetBodyContent(content);
                CustomRazorTemplateBase.SetSections(new Dictionary<string, string>());

                string renderedLayout = await compiledLayout.RunAsync((Action<object?>)(instance =>
                {
                    if (instance is CustomRazorTemplateBase layoutBase)
                    {
                        layoutBase.ViewData = context.ViewData;
                        layoutBase.ViewBag = context.ViewBag;
                    }
                }));

                CustomRazorTemplateBase.SetBodyContent(null);
                CustomRazorTemplateBase.SetSections(null);

                _logger.Log($"🔌 Layout rendered successfully");
                
                return renderedLayout;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error loading layout {layoutName}: {ex.Message}");
                return null;
            }
        }

        private async Task TryPopulateModel(HttpContext context, object model, Type modelType)
        {
            try
            {
                // Simple model binding from query string and form data
                var properties = modelType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                    .Where(p => p.CanWrite);

                foreach (var prop in properties)
                {
                    string? value = null;

                    // Check query string first
                    if (context.Request.Query.ContainsKey(prop.Name))
                    {
                        value = context.Request.Query[prop.Name].ToString();
                    }
                    // Then check form data
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
                            // If conversion fails, try setting as string if property is string
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

        // Helper classes
        public class SafeDictionary : IDictionary<string, object>
        {
            private readonly Dictionary<string, object> _inner = new();

            public object? this[string key]
            {
                get => _inner.TryGetValue(key, out var value) ? value : null;
                set => _inner[key] = value!;
            }

            public ICollection<string> Keys => _inner.Keys;
            public ICollection<object> Values => _inner.Values;
            public int Count => _inner.Count;
            public bool IsReadOnly => false;

            public void Add(string key, object value) => _inner.Add(key, value);
            public void Add(KeyValuePair<string, object> item) => _inner.Add(item.Key, item.Value);
            public void Clear() => _inner.Clear();
            public bool Contains(KeyValuePair<string, object> item) => _inner.Contains(item);
            public bool ContainsKey(string key) => _inner.ContainsKey(key);
            public void CopyTo(KeyValuePair<string, object>[] array, int arrayIndex) => ((ICollection<KeyValuePair<string, object>>)_inner).CopyTo(array, arrayIndex);
            public IEnumerator<KeyValuePair<string, object>> GetEnumerator() => _inner.GetEnumerator();
            public bool Remove(string key) => _inner.Remove(key);
            public bool Remove(KeyValuePair<string, object> item) => _inner.Remove(item.Key);
            public bool TryGetValue(string key, out object value) => _inner.TryGetValue(key, out value!);
            IEnumerator IEnumerable.GetEnumerator() => _inner.GetEnumerator();
        }

        public class TemplateRenderContext
        {
            public object? Model { get; set; }
            public HttpContext? HttpContext { get; set; }
            public Dictionary<string, object> InjectedServices { get; set; } = new();
            public IServiceProvider? ServiceProvider { get; set; }
            public SafeDictionary ViewBag { get; set; } = new();
            public SafeDictionary ViewData { get; set; } = new();
        }

        private class EmbeddedRazorPage
        {
            public string ResourceName { get; set; } = string.Empty;
            public string Content { get; set; } = string.Empty;
            public string Route { get; set; } = string.Empty;
            public Assembly Assembly { get; set; } = null!;
        }

        private class AssemblyComparer : IEqualityComparer<Assembly>
        {
            public bool Equals(Assembly? x, Assembly? y)
            {
                if (x == null && y == null) return true;
                if (x == null || y == null) return false;
                return x.FullName == y.FullName;
            }

            public int GetHashCode(Assembly obj)
            {
                return obj?.FullName?.GetHashCode() ?? 0;
            }
        }

        private class RazorParseResult
        {
            public string OriginalContent { get; set; } = string.Empty;
            public List<string> Usings { get; set; } = new();
            public string? ModelTypeName { get; set; }
            public Type? ModelType { get; set; }
            public List<(string ServiceTypeName, string PropertyName)> InjectDirectives { get; set; } = new();
            public List<(Type ServiceType, string PropertyName)> Injects { get; set; } = new();
            public string? Layout { get; set; }
        }


        public class CustomRazorTemplateBase : RazorEngineTemplateBase
        {
            private static Logger? _staticLogger;
            private static readonly AsyncLocal<TemplateRenderContext?> _currentContext = new();
            private static readonly AsyncLocal<string?> _bodyContent = new();
            private static readonly AsyncLocal<Dictionary<string, string>> _sections = new();
            
            public static void SetStaticLogger(Logger logger)
            {
                _staticLogger = logger;
            }

            public static void SetRenderContext(TemplateRenderContext? context)
            {
                _currentContext.Value = context;
            }

            public static void SetBodyContent(string? body)
            {
                _bodyContent.Value = body;
            }

            public static void SetSections(Dictionary<string, string>? sections)
            {
                _sections.Value = sections ?? new Dictionary<string, string>();
            }
            
            public HttpContext? Context { get; set; }
            public IServiceProvider? ServiceProvider { get; set; }
            public new SafeDictionary ViewBag { get; set; } = new SafeDictionary();
            public SafeDictionary ViewData { get; set; } = new SafeDictionary();
            public Dictionary<string, object> InjectedServices { get; set; } = new Dictionary<string, object>();

            public TService GetInjectedService<TService>(string propertyName) where TService : class
            {
                _staticLogger?.Log($"[GetInjectedService<{typeof(TService).Name}>] propertyName='{propertyName}'");
                
                var context = _currentContext.Value;
                if (context != null)
                {
                    _staticLogger?.Log($"   Using AsyncLocal context - has {context.InjectedServices.Count} services");
                    if (context.InjectedServices.TryGetValue(propertyName, out var service))
                    {
                        if (service is TService typedService)
                        {
                            _staticLogger?.Log($"   ✓ Found in context");
                            return typedService;
                        }
                        _staticLogger?.LogError($"   ✗ Type mismatch in context");
                        throw new InvalidOperationException($"Service {propertyName} is of type {service.GetType().FullName}, not {typeof(TService).FullName}");
                    }
                    _staticLogger?.Log($"   Not found in context");
                    
                    if (context.ViewData.TryGetValue(propertyName, out var vdService))
                    {
                        if (vdService is TService vdTypedService)
                        {
                            _staticLogger?.Log($"   ✓ Found in context.ViewData");
                            return vdTypedService;
                        }
                    }
                }
                else
                {
                    _staticLogger?.Log($"   No AsyncLocal context, trying instance property");
                }
                
                if (InjectedServices.TryGetValue(propertyName, out var instanceService))
                {
                    if (instanceService is TService typedService)
                    {
                        _staticLogger?.Log($"   ✓ Found in instance property");
                        return typedService;
                    }
                    _staticLogger?.LogError($"   ✗ Type mismatch in instance property");
                    throw new InvalidOperationException($"Service {propertyName} is of type {instanceService.GetType().FullName}, not {typeof(TService).FullName}");
                }
                
                if (ViewData.TryGetValue(propertyName, out var vdInstanceService))
                {
                    if (vdInstanceService is TService vdTypedService)
                    {
                        _staticLogger?.Log($"   ✓ Found in instance.ViewData");
                        return vdTypedService;
                    }
                }
                
                _staticLogger?.LogError($"   ✗ Not found anywhere");
                var availableInContext = context != null ? string.Join(", ", context.InjectedServices.Keys) : "N/A";
                var availableInInstance = string.Join(", ", InjectedServices.Keys);
                throw new InvalidOperationException($"Service '{propertyName}' of type {typeof(TService).FullName} was not injected. Context: [{availableInContext}], Instance: [{availableInInstance}]");
            }

            public IHtmlContent RenderBody()
            {
                var body = _bodyContent.Value ?? string.Empty;
                return new HtmlString(body);
            }

            public async Task<IHtmlContent> RenderSectionAsync(string name, bool required = true)
            {
                var sections = _sections.Value ?? new Dictionary<string, string>();
                if (sections.TryGetValue(name, out var section))
                {
                    return new HtmlString(section);
                }
                if (required)
                {
                    throw new InvalidOperationException($"Section '{name}' not found");
                }
                return new HtmlString(string.Empty);
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