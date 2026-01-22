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

    public class HtmlCache
    {
        public string Html { get; set; }
    }

    public class HtmlRefresherBackgroundService : BackgroundService
    {
        private readonly HtmlCache _cache;

        public HtmlRefresherBackgroundService(HtmlCache cache)
        {
            _cache = cache;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    string htmlPath = Path.Combine(AppContext.BaseDirectory, "index.html");
                    string cssPath = Path.Combine(AppContext.BaseDirectory, "style.css");
                    string jsPath = Path.Combine(AppContext.BaseDirectory, "script.js");

                    if (File.Exists(htmlPath))
                    {
                        string webPage = await File.ReadAllTextAsync(htmlPath, stoppingToken);

                        if (File.Exists(cssPath))
                        {
                            string css = await File.ReadAllTextAsync(cssPath, stoppingToken);
                            webPage = webPage.Replace("</head>", $"<style>\n{css}\n</style>\n</head>");
                        }
                        if (File.Exists(jsPath))
                        {
                            string js = await File.ReadAllTextAsync(jsPath, stoppingToken);
                            webPage = webPage.Replace("</body>", $"<script>\n{js}\n</script>\n</body>");
                        }
                        _cache.Html = webPage;
                    }
                }
                catch { }

                await Task.Delay(5000, stoppingToken);
            }
        }
    }
}
