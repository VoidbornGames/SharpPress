using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using SharpPress.Services;

namespace SharpPress.Plugins
{
    public class PluginEnabledFilter : IAsyncActionFilter, IAsyncPageFilter
    {
        private readonly PluginManager _pluginManager;
        private readonly Logger _logger;

        public PluginEnabledFilter(PluginManager pluginManager, Logger logger)
        {
            _pluginManager = pluginManager;
            _logger = logger;
        }

        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var controllerType = context.Controller.GetType();

            if (_pluginManager.IsTypeFromDisabledPlugin(controllerType))
            {
                _logger.Log($"🚫 Access denied to disabled plugin controller: {controllerType.Name}");
                context.Result = new NotFoundResult();
                return;
            }

            await next();
        }

        public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
        {
            var pageType = context.HandlerInstance?.GetType();

            if (pageType != null && _pluginManager.IsTypeFromDisabledPlugin(pageType))
            {
                _logger.Log($"🚫 Access denied to disabled plugin page: {pageType.Name}");
                context.Result = new NotFoundResult();
                return;
            }

            await next();
        }

        public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context)
        {
            return Task.CompletedTask;
        }
    }
}