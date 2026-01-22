using Server.Services;
using SharpPress.Events;
using SharpPress.Helpers;
using SharpPress.Models;
using SharpPress.Servers;
using SharpPress.Services;
using System.Diagnostics;

namespace SharpPress
{
    class Program
    {
        private static int httpPort = 12001;
        private static int sftpPort = 12002;

        static async Task Main(string[] args)
        {
            if (args.Length > 1 && int.TryParse(args[1], out int parsedPortWeb))
                httpPort = parsedPortWeb;
            if (args.Length > 3 && int.TryParse(args[3], out int parsedSftpPort))
                sftpPort = parsedSftpPort;

            var builder = WebApplication.CreateBuilder(args);
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.ListenAnyIP(httpPort);
            });

            // Singletons
            builder.Services.AddSingleton<Logger>();
            builder.Services.AddSingleton(provider => new ConfigManager(logger: provider.GetRequiredService<Logger>()));
            builder.Services.AddSingleton(provider => new EmailService(config: provider.GetRequiredService<ConfigManager>().Config));
            builder.Services.AddSingleton(provider => provider.GetRequiredService<ConfigManager>().Config);
            builder.Services.AddSingleton<FilePaths>();
            builder.Services.AddSingleton(provider => new ServerSettings { httpPort = httpPort, sftpPort = sftpPort });
            builder.Services.AddSingleton<FeatherDatabase>();
            builder.Services.AddSingleton<CacheService>();
            builder.Services.AddSingleton<IEventBus, InMemoryEventBus>();
            builder.Services.AddSingleton<Services.EventHandler>();
            builder.Services.AddSingleton<PluginManager>();
            builder.Services.AddSingleton<DownloadJobProcessor>();
            builder.Services.AddSingleton<UserService>();

            // Scoped
            builder.Services.AddScoped<AuthenticationService>();
            builder.Services.AddScoped<ValidationService>();
            builder.Services.AddScoped<PackageManager>();
            builder.Services.AddScoped<VideoService>();
            builder.Services.AddScoped<Nginx>();

            builder.Services.AddHostedService<GenericHostedServiceWrapper<SftpServer>>();
            builder.Services.AddHostedService<GenericHostedServiceWrapper<WebSocketServer>>();

            builder.Services.AddHostedService<HtmlRefresherBackgroundService>();

            var app = builder.Build();
            var serviceProvider = app.Services;
            var logger = serviceProvider.GetRequiredService<Logger>();
            var configManager = serviceProvider.GetRequiredService<ConfigManager>();

            logger.PrepareLogs();

            var eventBus = serviceProvider.GetRequiredService<IEventBus>();
            var eventHandler = serviceProvider.GetRequiredService<Services.EventHandler>();
            var pluginManager = serviceProvider.GetRequiredService<PluginManager>();

            eventBus.Subscribe<PluginLoadedEvent>(eventHandler);
            eventBus.Subscribe<VideoUploadedEvent>(eventHandler);
            eventBus.Subscribe<UserRegisteredEvent>(eventHandler);

            pluginManager._serviceProvider = serviceProvider;
            if (Directory.Exists(Path.Combine("plugins", ".plugin_temp")))
                Directory.Delete(Path.Combine("plugins", ".plugin_temp"), true);

            await pluginManager.LoadPluginsAsync();

            app.UseMiddleware<PluginMiddleware>();
            app.Use(async (context, next) =>
            {
                context.Response.Headers.Append("Access-Control-Allow-Origin", "*");
                context.Response.Headers.Append("Access-Control-Allow-Headers", "Content-Type, Authorization");
                context.Response.Headers.Append("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
                if (context.Request.Method == "OPTIONS")
                {
                    context.Response.StatusCode = 200;
                    return;
                }
                await next();
            });

            Endpoints.Map(app);
            app.MapFallback(async context =>
            {
                var cache = serviceProvider.GetRequiredService<HtmlCache>();
                if (!string.IsNullOrEmpty(cache.Html))
                {
                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync(cache.Html);
                }
                else
                {
                    context.Response.StatusCode = 404;
                    await context.Response.WriteAsync("Not Found");
                }
            });

            var lifetime = app.Lifetime;
            lifetime.ApplicationStopping.Register(() =>
            {
                logger.Log("🛑 Shutdown requested...");
                pluginManager.UnloadAllPluginsAsync().GetAwaiter().GetResult();
                logger.Log("✅ Shutdown complete.");
            });

            logger.Log($"🚀 Server started successfully on HTTP port {httpPort}!");
            app.Run();
        }
    }
}