using Microsoft.Extensions.DependencyInjection;
using SharpPress.Plugins;
using System;

namespace SharpPress.Services
{
    public class RestrictedServiceProvider : IServiceProvider, IServiceProviderIsService
    {
        private readonly IServiceProvider _innerProvider;
        private readonly PluginPermissions _grantedPermissions;
        private readonly ServiceSecurityPolicy _securityPolicy;

        public RestrictedServiceProvider(
            IServiceProvider innerProvider,
            PluginPermissions grantedPermissions,
            ServiceSecurityPolicy securityPolicy)
        {
            _innerProvider = innerProvider;
            _grantedPermissions = grantedPermissions;
            _securityPolicy = securityPolicy;
        }

        public object? GetService(Type serviceType)
        {
            if (!_securityPolicy.HasAccess(serviceType, _grantedPermissions))
            {
                throw new UnauthorizedAccessException(
                    $"Plugin attempted to access {serviceType.Name} without permission. Granted: {_grantedPermissions}."
                );
            }
            return _innerProvider.GetService(serviceType);
        }

        public bool IsService(Type serviceType)
        {
            return _securityPolicy.HasAccess(serviceType, _grantedPermissions)
                   && (_innerProvider as IServiceProviderIsService)?.IsService(serviceType) == true;
        }
    }
}