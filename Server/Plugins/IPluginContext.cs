using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using SharpPress.Services;

namespace SharpPress.Plugins
{
    /// <summary>
    /// Provides a safe API for plugins to interact with the core application.
    /// </summary>
    public interface IPluginContext
    {
        Logger Logger { get; }
        IEventBus EventBus { get; }
        IServiceProvider ServiceProvider { get; }
        void RegisterApiRoute(string path, Func<HttpRequest, Task> handler);
        Func<HttpRequest, Task> GetRouteHandler(string path);
    }
}