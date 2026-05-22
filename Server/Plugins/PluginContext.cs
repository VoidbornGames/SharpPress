using SharpPress.Plugins;

namespace SharpPress.Services
{
    public class PluginContext : IPluginContext
    {
        public Logger Logger { get; }
        public IServiceScopeFactory ScopeFactory { get; }
        public IServiceProvider ServiceProvider { get; }

        private readonly IAdminMenuService _adminMenuService;
        private readonly PluginManager _pluginManager;
        private readonly string _pluginName;

        public PluginContext(Logger logger, IServiceScopeFactory scopeFactory, IServiceProvider serviceProvider, IAdminMenuService adminMenuService, string pluginName)
        {
            Logger = logger;
            ScopeFactory = scopeFactory;
            ServiceProvider = serviceProvider;
            _adminMenuService = adminMenuService;
            _pluginManager = serviceProvider.GetRequiredService<PluginManager>();
            _pluginName = pluginName;
        }

        public void RegisterAdminMenuItem(string name, string iconSvg, string url, int order = 0)
            => _adminMenuService.Register(new AdminMenuItem { ResponsiblePlugin = _pluginName, Name = name, IconSvg = iconSvg, Url = url, Order = order });

        public void MapGet(string pattern, Delegate handler) => MapRoute(pattern, handler);
        public void MapPost(string pattern, Delegate handler) => MapRoute(pattern, handler);
        public void Map(string pattern, Delegate handler) => MapRoute(pattern, handler);

        private void MapRoute(string pattern, Delegate handler)
        {
            RequestDelegate secureWrapper = async (httpContext) =>
            {
                try
                {
                    var result = handler.DynamicInvoke(httpContext);
                    if (result is Task task)
                    {
                        await task;
                        if (task.GetType().IsGenericType && task.GetType().GetGenericTypeDefinition() == typeof(Task<>))
                        {
                            var innerResult = task.GetType().GetProperty("Result")?.GetValue(task);
                            if (innerResult is IResult iResult) await iResult.ExecuteAsync(httpContext);
                        }
                    }
                    else if (result is IResult iResult) await iResult.ExecuteAsync(httpContext);
                }
                catch (Exception ex) { httpContext.Response.StatusCode = 500; await httpContext.Response.WriteAsync($"Plugin Error: {ex.Message}"); }
            };

            _pluginManager.RegisterRoute(pattern, _pluginName, secureWrapper);
        }
    }
}