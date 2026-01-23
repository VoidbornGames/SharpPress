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
        private readonly PluginPermissions _grantedPermissions;
        private readonly ServiceSecurityPolicy _securityPolicy;

        public PluginContext(
            Logger logger,
            IServiceScopeFactory scopeFactory,
            IEndpointRouteBuilder routes,
            PluginPermissions grantedPermissions,
            ServiceSecurityPolicy securityPolicy)
        {
            Logger = logger;
            ScopeFactory = scopeFactory;
            _routes = routes;
            _grantedPermissions = grantedPermissions;
            _securityPolicy = securityPolicy;
        }

        public void MapGet(string pattern, Delegate handler) => MapRoute(pattern, handler);
        public void MapPost(string pattern, Delegate handler) => MapRoute(pattern, handler);
        public void Map(string pattern, Delegate handler) => MapRoute(pattern, handler);

        private void MapRoute(string pattern, Delegate handler)
        {
            RequestDelegate secureWrapper = async (httpContext) =>
            {
                var originalProvider = httpContext.RequestServices;
                var restrictedProvider = new RestrictedServiceProvider(originalProvider, _grantedPermissions, _securityPolicy);

                httpContext.RequestServices = restrictedProvider;

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
                    httpContext.RequestServices = originalProvider;
                }
            };

            _routes.Map(pattern, secureWrapper);
        }

        public T GetService<T>()
        {
            var scope = ScopeFactory.CreateScope();
            var restrictedProvider = new RestrictedServiceProvider(scope.ServiceProvider, _grantedPermissions, _securityPolicy);
            var service = restrictedProvider.GetService(typeof(T));
            if (service == null) throw new InvalidOperationException($"Service {typeof(T).Name} not found.");
            return (T)service;
        }
    }
}