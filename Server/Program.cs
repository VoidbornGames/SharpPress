using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.IdentityModel.Tokens;
using SharpPress.Helpers;
using SharpPress.Middlewares;
using SharpPress.Models;
using SharpPress.Modules;
using SharpPress.Plugins;
using SharpPress.Servers;
using SharpPress.Services;
using System.Text;

namespace SharpPress
{
    public class Program
    {
        private static int httpPort = 12001;

        public static async Task Main(string[] args)
        {
            var httpPortEnv = Environment.GetEnvironmentVariable("HTTP_PORT");
            if (!string.IsNullOrEmpty(httpPortEnv) && int.TryParse(httpPortEnv, out int envHttpPort))
            {
                httpPort = envHttpPort;
            }
            else if (args.Length >= 1 && int.TryParse(args[0], out int argHttpPort))
            {
                httpPort = argHttpPort;
            }

            var builder = WebApplication.CreateBuilder(args);

            builder.WebHost.ConfigureKestrel(options =>
            {
                options.ListenAnyIP(httpPort);
            });

            builder.Services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders =
                    ForwardedHeaders.XForwardedFor |
                    ForwardedHeaders.XForwardedProto;

                options.KnownNetworks.Clear();
                options.KnownProxies.Clear();
            });

            var logger = new Logger();
            var loggerAdapter = new LoggerAdapter(logger);
            var configManager = new ConfigManager(logger: logger);

            var moduleStateService = new ModuleStateService();
            var moduleManager = new ModuleManager(logger, moduleStateService);

            await moduleManager.LoadModulesAsync();
            moduleManager.RunBeforeBuild(builder);

            builder.Services.AddSingleton(logger);
            builder.Services.AddSingleton(configManager);
            builder.Services.AddSingleton(provider => provider.GetRequiredService<ConfigManager>().Config);
            builder.Services.AddSingleton(moduleManager);
            builder.Services.AddSingleton(moduleStateService);

            builder.Services.AddControllersWithViews(options =>
            {
                options.Filters.Add<PluginEnabledFilter>();
            });

            builder.Services.AddRazorPages();
            builder.Services.AddCors(options =>
            {
                options.AddPolicy("DynamicPolicy", policyBuilder =>
                {
                    policyBuilder
                        .WithOrigins($"https://{configManager.Config.PanelDomain}")
                        .AllowAnyMethod()
                        .AllowAnyHeader()
                        .AllowCredentials();
                });
            });

            builder.Services.AddMemoryCache();
            builder.Services.AddHealthChecks();
            builder.Services.Configure<HostOptions>(options =>
            {
                options.ShutdownTimeout = TimeSpan.FromSeconds(30);
            });
            builder.Services.AddHttpClient();
            builder.Services.AddHttpContextAccessor();

            builder.Services.AddSingleton(provider => new EmailService(config: provider.GetRequiredService<ConfigManager>().Config));
            builder.Services.AddSingleton<FilePaths>();
            builder.Services.AddSingleton(provider => new ServerSettings { httpPort = httpPort });
            builder.Services.AddSingleton<CacheService>();
            builder.Services.AddSingleton<IEventBus, InMemoryEventBus>();
            builder.Services.AddSingleton<PluginStateService>();
            builder.Services.AddSingleton<PluginActionDescriptorChangeProvider>();
            builder.Services.AddSingleton<IActionDescriptorChangeProvider>(sp => sp.GetRequiredService<PluginActionDescriptorChangeProvider>());
            builder.Services.AddSingleton<Services.EventHandler>();
            builder.Services.AddSingleton(provider => new FeatherDatabase(loggerAdapter, provider.GetRequiredService<ConfigManager>().Config.MySQL_Config));
            builder.Services.AddSingleton<UserService>();
            builder.Services.AddSingleton<WebSocketServer>();
            builder.Services.AddSingleton<ValidationService>();
            builder.Services.AddSingleton<PluginManager>();
            builder.Services.AddSingleton<DownloadJobProcessor>();
            builder.Services.AddSingleton<AuthenticationService>();
            builder.Services.AddSingleton<PackageManager>();
            builder.Services.AddSingleton<VideoStreamingService>();
            builder.Services.AddSingleton<IAdminMenuService, AdminMenuService>();
            builder.Services.AddSingleton<PostService>();
            builder.Services.AddSingleton<TaxonomyService>();
            builder.Services.AddSingleton<MediaService>();

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Bearer";
                options.DefaultChallengeScheme = "Cookies";
            })
            .AddCookie(options =>
            {
                options.LoginPath = "/Login";
                options.LogoutPath = "/Login";
                options.AccessDeniedPath = "/Login";
            })
            .AddJwtBearer("Bearer", options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(configManager.Config.JwtSecret))
                };

                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = context =>
                    {
                        if (context.Request.Cookies.TryGetValue("X-Access-Token", out var token))
                            context.Token = token;

                        return Task.CompletedTask;
                    },
                    OnAuthenticationFailed = context =>
                    {
                        if (context.Exception is SecurityTokenExpiredException)
                            context.Response.Cookies.Delete("X-Access-Token");

                        return Task.CompletedTask;
                    }
                };
            });

            builder.Services.AddAuthorization();

            logger.PrepareLogs();

            var app = builder.Build();
            var serviceProvider = app.Services;

            await moduleManager.RunAfterBuildAsync(app);

            app.UseForwardedHeaders();
            app.UseMiddleware<UserControlMiddleware>();
            app.UseMiddleware<SlugRoutingMiddleware>();
            app.UseRouting();

            app.UseCors("DynamicPolicy");

            app.UseAuthentication();
            app.UseAuthorization();

            var applicationPartManager = serviceProvider.GetRequiredService<ApplicationPartManager>();
            var pluginManager = serviceProvider.GetRequiredService<PluginManager>();
            var env = serviceProvider.GetRequiredService<IWebHostEnvironment>();

            pluginManager.Initialize(applicationPartManager, env);

            var tempPluginPath = Path.Combine(AppContext.BaseDirectory, "plugins", ".plugin_temp");
            if (Directory.Exists(tempPluginPath))
            {
                try
                {
                    Directory.Delete(tempPluginPath, true);
                }
                catch (Exception ex)
                {
                    logger.LogError($"Failed to clean temp plugin dir: {ex.Message}");
                }
            }

            await pluginManager.LoadPluginsAsync();
            await Endpoints.RegisterServices(serviceProvider.GetRequiredService<ServerConfig>());

            app.MapControllers();
            app.MapRazorPages();
            app.MapHealthChecks("/health");

            Endpoints.Map(app, pluginManager);

            var lifetime = serviceProvider.GetRequiredService<IHostApplicationLifetime>();
            lifetime.ApplicationStopping.Register(() =>
            {
                Endpoints.SignalShutdown();

                logger.Log("🛑 Shutdown signal received. Stopping services...");
                ShutdownApplication(serviceProvider, logger).GetAwaiter().GetResult();
            });

            logger.Log($"⚠️ Ensure Nginx is configured to proxy port 443 to localhost:{httpPort}");
            logger.Log($"🚀 Server started successfully on HTTP port {httpPort}!");

            _ = Task.Run(async () =>
            {
                while (!app.Lifetime.ApplicationStopping.IsCancellationRequested)
                {
                    if (app.Lifetime.ApplicationStopping.IsCancellationRequested)
                        break;

                    await Task.Delay(50, app.Lifetime.ApplicationStopping);
                    await pluginManager.UpdateLoadedPluginsAsync();
                }
            });

            await PrepareDatabase(serviceProvider.GetRequiredService<FeatherDatabase>());
            await app.RunAsync();
        }

        private static async Task PrepareDatabase(FeatherDatabase database)
        {
            await database.CreateTable<User>();
            await database.CreateIndex<User>("Username");
            await database.CreateIndex<User>("UUID");
            await database.CreateTable<Post>();
            await database.CreateIndex<Post>("Slug");
            await database.CreateTable<Category>();
            await database.CreateIndex<Category>("Slug");
            await database.CreateTable<Tag>();
            await database.CreateIndex<Tag>("Slug");
            await database.CreateTable<PostCategory>();
            await database.CreateIndex<PostCategory>("PostId");
            await database.CreateIndex<PostCategory>("CategoryId");
            await database.CreateTable<PostTag>();
            await database.CreateIndex<PostTag>("PostId");
            await database.CreateIndex<PostTag>("TagId");
            await database.CreateTable<MediaItem>();
            await database.CreateIndex<MediaItem>("MediaType");
        }

        private static async Task ShutdownApplication(IServiceProvider serviceProvider, Logger logger)
        {
            try
            {
                var downloadProcessor = serviceProvider.GetService<DownloadJobProcessor>();
                if (downloadProcessor != null)
                {
                    logger.Log("🛑 Stopping Download Processor...");
                    await downloadProcessor.StopAsync();
                }

                var plugins = serviceProvider.GetService<PluginManager>();
                if (plugins != null)
                {
                    logger.Log("🛑 Unloading Plugins...");
                    await plugins.UnloadAllPluginsAsync();
                }

                logger.Log("✅ All services stopped gracefully.");
            }
            catch (Exception ex)
            {
                logger.LogError($"Error during shutdown: {ex.Message}");
            }
        }
    }
}