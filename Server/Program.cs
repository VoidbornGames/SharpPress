using Server.Services;
using SharpPress.Events;
using SharpPress.Helpers;
using SharpPress.Models;
using SharpPress.Servers;
using SharpPress.Services;
using System.Diagnostics;
using System.IO;
using System.Reflection;

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

            var pluginConfigPath = Path.Combine(AppContext.BaseDirectory, "plugin_security.json");
            if (!File.Exists(pluginConfigPath))
            {
                File.WriteAllText(pluginConfigPath, @"
                {
                    ""DefaultMode"": ""Deny"",
                    ""Policies"": 
                     [
                       { ""ServiceType"": ""SharpPress.Services.UserService"", ""RequiredPermission"": 1 },
                       { ""ServiceType"": ""SharpPress.Plugins.IEventBus"", ""RequiredPermission"": 8 }
                     ]
                }");
            }

            builder.Configuration.AddJsonFile("plugin_security.json", optional: false, reloadOnChange: true);

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
            builder.Services.AddSingleton<UserService>();
            builder.Services.AddSingleton<SftpServer>();
            builder.Services.AddSingleton<WebSocketServer>();
            builder.Services.AddSingleton<ValidationService>();
            builder.Services.AddSingleton<ServiceSecurityPolicy>();
            builder.Services.AddSingleton<DownloadJobProcessor>();

            // Scoped
            builder.Services.AddScoped<AuthenticationService>();
            builder.Services.AddScoped<PackageManager>();
            builder.Services.AddScoped<VideoService>();
            builder.Services.AddScoped<Nginx>();

            // Background Services
            builder.Services.AddHostedService<GenericHostedServiceWrapper<SftpServer>>();

            var app = builder.Build();
            var serviceProvider = app.Services;
            var logger = serviceProvider.GetRequiredService<Logger>();
            var configManager = serviceProvider.GetRequiredService<ConfigManager>();

            logger.PrepareLogs();

            var eventBus = serviceProvider.GetRequiredService<IEventBus>();
            var eventHandler = serviceProvider.GetRequiredService<Services.EventHandler>();

            eventBus.Subscribe<PluginLoadedEvent>(eventHandler);
            eventBus.Subscribe<VideoUploadedEvent>(eventHandler);
            eventBus.Subscribe<UserRegisteredEvent>(eventHandler);

            if (Directory.Exists(Path.Combine("plugins", ".plugin_temp")))
                Directory.Delete(Path.Combine("plugins", ".plugin_temp"), true);

            var pluginManager = new PluginManager(
                logger: serviceProvider.GetRequiredService<Logger>(),
                eventBus: serviceProvider.GetRequiredService<IEventBus>(),
                serviceProvider: serviceProvider,
                scopeFactory: serviceProvider.GetRequiredService<IServiceScopeFactory>(),
                routeBuilder: app,
                securityPolicy: serviceProvider.GetRequiredService<ServiceSecurityPolicy>()
            );

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

            Endpoints.Map(app, pluginManager);

            app.MapPost("/api/plugins/reload", async (HttpRequest req, PluginManager pm) =>
            {
                await pm.ReloadAllPluginsAsync();
                return Results.Ok("Plugins Reloaded");
            });

            app.MapFallback(async context =>
            {
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(@"<p>404 Not Found</p>");
            });

            var lifetime = app.Lifetime;
            lifetime.ApplicationStopping.Register(() =>
            {
                logger.Log("🛑 Shutdown requested...");
                pluginManager.UnloadAllPluginsAsync().GetAwaiter().GetResult();
                logger.Log("✅ Shutdown complete.");
            });

            logger.Log($"⚠️ Ensure Nginx is configured to proxy port 443 to localhost:{httpPort}");
            logger.Log($"🚀 Server started successfully on HTTP port {httpPort}!");
            app.Run();
        }
    }
}