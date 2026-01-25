using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using SharpPress.Plugins;
using System;
using System.Threading.Tasks;

namespace SharpPress.Services
{
    public class PluginContext : IPluginContext
    {
        public Logger Logger { get; }
        public IServiceScopeFactory ScopeFactory { get; }

        private readonly IEndpointRouteBuilder _routes;

        public PluginContext(
            Logger logger,
            IServiceScopeFactory scopeFactory,
            IEndpointRouteBuilder routes)
        {
            Logger = logger;
            ScopeFactory = scopeFactory;
            _routes = routes;
        }

        public void MapGet(string pattern, Delegate handler) => MapRoute(pattern, handler);
        public void MapPost(string pattern, Delegate handler) => MapRoute(pattern, handler);
        public void Map(string pattern, Delegate handler) => MapRoute(pattern, handler);

        private void MapRoute(string pattern, Delegate handler)
        {
            RequestDelegate secureWrapper = async (httpContext) =>
            {
                httpContext.RequestServices = httpContext.RequestServices;
                try
                {
                    var result = handler.DynamicInvoke(httpContext);

                    if (result is Task task)
                    {
                        await task;
                        if (task.GetType().IsGenericType && task.GetType().GetGenericTypeDefinition() == typeof(Task<>))
                        {
                            var resultProperty = task.GetType().GetProperty("Result");
                            var innerResult = resultProperty?.GetValue(task);
                            if (innerResult is IResult iResult)
                            {
                                await iResult.ExecuteAsync(httpContext);
                            }
                        }
                    }
                    else if (result is IResult iResult)
                    {
                        await iResult.ExecuteAsync(httpContext);
                    }
                }
                catch (Exception ex)
                {
                    httpContext.Response.StatusCode = 500;
                    await httpContext.Response.WriteAsync($"Plugin Error: {ex.Message}");
                }
                finally
                {
                    httpContext.RequestServices = httpContext.RequestServices;
                }
            };

            _routes.Map(pattern, secureWrapper);
        }
    }
}