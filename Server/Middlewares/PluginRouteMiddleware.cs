using SharpPress.Services;

namespace SharpPress.Middlewares
{
    public class PluginRouteMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly PluginManager _pluginManager;
        private readonly Logger _logger;

        public PluginRouteMiddleware(RequestDelegate next, PluginManager pluginManager, Logger logger)
        {
            _next = next;
            _pluginManager = pluginManager;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var path = context.Request.Path.Value ?? "";

            if (IsDisabledPluginPath(path))
            {
                _logger.Log($"🚫 Blocked access to disabled plugin path: {path}");
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                await context.Response.WriteAsync("Plugin is disabled");
                return;
            }

            await _next(context);
        }

        private bool IsDisabledPluginPath(string path)
        {
            var loadedPlugins = _pluginManager.GetLoadedPlugins();

            foreach (var plugin in loadedPlugins.Values)
            {
                var pluginName = plugin.Name.ToLower();
                if (path.StartsWith($"/{pluginName}", StringComparison.OrdinalIgnoreCase) ||
                    path.Contains($"/{pluginName}/", StringComparison.OrdinalIgnoreCase))
                {
                    if (!_pluginManager.IsPluginEnabled(plugin.Name))
                        return true;
                }
            }

            return false;
        }
    }
}
