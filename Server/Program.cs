using Newtonsoft.Json;
using SharpPress.Events;
using SharpPress.Helpers;
using SharpPress.Models;
using SharpPress.Servers;
using SharpPress.Services;
using System.Text;

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
            builder.Services.AddRazorPages();

            // Singletons 
            builder.Services.AddSingleton<Logger>();
            builder.Services.AddSingleton(provider => new ConfigManager(logger: provider.GetRequiredService<Logger>()));
            builder.Services.AddSingleton(provider => new EmailService(config: provider.GetRequiredService<ConfigManager>().Config));
            builder.Services.AddSingleton(provider => provider.GetRequiredService<ConfigManager>().Config);
            builder.Services.AddSingleton<FilePaths>();
            builder.Services.AddSingleton(provider => new ServerSettings { httpPort = httpPort, sftpPort = sftpPort });
            builder.Services.AddSingleton(provider => new MiniDB(new MiniDBOptions(), provider.GetRequiredService<Logger>()));
            builder.Services.AddSingleton<FeatherDatabase>();
            builder.Services.AddSingleton<CacheService>();
            builder.Services.AddSingleton<IEventBus, InMemoryEventBus>();
            builder.Services.AddSingleton<Services.EventHandler>();
            builder.Services.AddSingleton<UserService>();
            builder.Services.AddSingleton<SftpServer>();
            builder.Services.AddSingleton<WebSocketServer>();
            builder.Services.AddSingleton<ValidationService>();
            builder.Services.AddSingleton<PluginManager>();
            builder.Services.AddSingleton<DownloadJobProcessor>();
            builder.Services.AddSingleton<AuthenticationService>();
            builder.Services.AddSingleton<PackageManager>();
            builder.Services.AddSingleton<VideoService>();
            builder.Services.AddSingleton<Nginx>();

            var app = builder.Build();
            var serviceProvider = app.Services;

            var logger = serviceProvider.GetRequiredService<Logger>();
            var configManager = serviceProvider.GetRequiredService<ConfigManager>();
            var miniDB = serviceProvider.GetRequiredService<MiniDB>();

            logger.PrepareLogs();
            await miniDB.StartAsync();

            var eventBus = serviceProvider.GetRequiredService<IEventBus>();
            var eventHandler = serviceProvider.GetRequiredService<Services.EventHandler>();

            eventBus.Subscribe<PluginLoadedEvent>(eventHandler);
            eventBus.Subscribe<VideoUploadedEvent>(eventHandler);
            eventBus.Subscribe<UserRegisteredEvent>(eventHandler);

            if (Directory.Exists(Path.Combine("plugins", ".plugin_temp")))
                Directory.Delete(Path.Combine("plugins", ".plugin_temp"), true);

            var pluginManager = serviceProvider.GetRequiredService<PluginManager>();
            await pluginManager.Initialize(app);
            await pluginManager.LoadPluginsAsync();

            app.UseMiddleware<PluginMiddleware>(pluginManager);

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

            app.MapRazorPages();
            Endpoints.Map(app, pluginManager);

            var lifetime = app.Lifetime;
            lifetime.ApplicationStopping.Register(() =>
            {
                logger.Log("🛑 Shutdown requested...");

                serviceProvider.GetRequiredService<MiniDB>().StopAsync().GetAwaiter().GetResult();
                serviceProvider.GetRequiredService<SftpServer>().StopAsync().GetAwaiter().GetResult();
                serviceProvider.GetRequiredService<DownloadJobProcessor>().StopAsync().GetAwaiter().GetResult();

                pluginManager.UnloadAllPluginsAsync().GetAwaiter().GetResult();
                miniDB.StopAsync().GetAwaiter().GetResult();

                logger.Log("✅ Shutdown complete.");
            });

            logger.Log($"⚠️ Ensure Nginx is configured to proxy port 443 to localhost:{httpPort}");
            logger.Log($"🚀 Server started successfully on HTTP port {httpPort}!");
            app.Run();
        }
    }
}