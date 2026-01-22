using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using SharpPress.Plugins;
using SharpPress.Services;

namespace SharpPress.Services
{
    /// <summary>
    /// Implementation of IPluginContext
    /// </summary>
    public class PluginContext : IPluginContext
    {
        public Logger Logger { get; }
        public IEventBus EventBus { get; }
        public IServiceProvider ServiceProvider { get; }

        private readonly Dictionary<string, Func<HttpRequest, Task>> _routes = new();

        public PluginContext(Logger serverLogger, IEventBus eventBus, IServiceProvider serviceProvider)
        {
            Logger = serverLogger;
            EventBus = eventBus;
            ServiceProvider = serviceProvider;
        }

        public void RegisterApiRoute(string path, Func<HttpRequest, Task> handler)
        {
            _routes[path] = handler;
            Logger.Log($"🔌 Plugin registered route: {path}");
        }

        public Func<HttpRequest, Task> GetRouteHandler(string path)
        {
            return _routes.TryGetValue(path, out var handler) ? handler : null;
        }
    }
}