using SharpPress.Models;
using System.Diagnostics;

namespace SharpPress.Helpers
{
    public class GenericHostedServiceWrapper<T> : BackgroundService where T : class, IManualServer
    {
        private readonly T _server;

        public GenericHostedServiceWrapper(T server)
        {
            _server = server;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await _server.Start();
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            await _server.StopAsync();
            await base.StopAsync(cancellationToken);
        }
    }
}
