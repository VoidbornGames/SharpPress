using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using SharpPress.Plugins;

namespace SharpPress.Services
{
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
            var handler = _pluginManager.GetRouteHandler(context.Request.Path);

            if (handler != null)
            {
                try
                {
                    await handler(context);
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Plugin execution error: {ex.Message}");
                    if (!context.Response.HasStarted)
                    {
                        context.Response.StatusCode = 500;
                        await context.Response.WriteAsync("Internal Plugin Error");
                    }
                }
                return;
            }

            await _next(context);
        }
    }
}