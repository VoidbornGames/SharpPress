# SharpPress

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![.NET](https://img.shields.io/badge/.NET-8.0-purple.svg)
![MySQL](https://img.shields.io/badge/MySQL-8.0-blue.svg)
![Plugin Architecture](https://img.shields.io/badge/Architecture-Plugin--First-green.svg)

**SharpPress** is a modern, plugin-first hybrid headless CMS and web platform built with C# and .NET 8. It is designed around a modular architecture where a lightweight core provides essential CMS primitives — content management, user authentication, media handling, and real-time communication — while nearly every feature can be extended, replaced, or augmented through a hot-loadable plugin system. Whether you need a simple blog, a content-rich editorial site, or a complex web application with custom business logic, SharpPress gives you a production-ready foundation that stays out of your way.

---

## Overview

SharpPress combines the convenience of a traditional CMS admin panel with the flexibility of a headless API backend. The server renders Razor Pages for the built-in admin interface while simultaneously exposing RESTful API endpoints that frontend applications can consume. Content is stored in MySQL through a custom lightweight ORM (FeatherDatabase) that automatically creates and migrates tables based on your C# model classes — no manual schema management or EF Core migration files required.

At its core, the platform revolves around three pillars:

- **Content Engine** — Manage posts (articles, pages, blog posts), categories, tags, and media with full CRUD operations, slug-based URL routing, scheduled publishing, and featured image support.
- **Plugin Runtime** — Drop a compiled DLL into the `plugins/` folder and SharpPress loads it into an isolated `AssemblyLoadContext`, registers its controllers and Razor views into the ASP.NET Core pipeline, and calls your plugin's lifecycle hooks. Plugins can be enabled, disabled, and reloaded at runtime without restarting the server.
- **Real-Time Infrastructure** — A built-in WebSocket server and an in-memory event bus with 30+ domain events enable live notifications, collaborative features, and plugin-driven reactions to every meaningful state change in the system.

## Key Features

### Content Management
| Feature | Description |
|---------|-------------|
| **Multi-Type Posts** | Articles, Pages, and Blog Posts with distinct type semantics |
| **Slug-Based Routing** | Clean URLs like `/blog/my-post`, `/category/tech`, `/tag/tutorial` resolved via middleware |
| **Scheduled Publishing** | Set a future date and posts automatically transition to Published when due |
| **Rich Taxonomy** | Hierarchical categories with parent/child relationships and flat tag system |
| **Post Excerpts** | Optional hand-crafted excerpts with automatic fallback support |
| **Featured Images** | Per-post featured image with thumbnail generation |

### Authentication & User Management
| Feature | Description |
|---------|-------------|
| **Dual-Auth Strategy** | JWT Bearer tokens for API consumers + Cookie authentication for browser sessions |
| **Two-Factor Authentication** | TOTP-based 2FA with per-user enable/disable support |
| **Role-Based Access Control** | Bitmask roles: User, Moderator, Support, Admin with hierarchical permission checks |
| **Account Lockout** | Configurable failed-login threshold with automatic temporary lockout |
| **Password Reset Flow** | Token-based email reset with expiration and one-time validation |
| **Token Renewal** | Automatic JWT renewal when the token is nearing expiry (transparent to the user) |
| **User States** | Active, Banned, Locked, Verified — each with dedicated UI pages and event hooks |

### Media & File Handling
| Feature | Description |
|---------|-------------|
| **Multi-Type Uploads** | Images, videos, audio, and documents with automatic type detection |
| **Image Processing** | Automatic thumbnail generation using SixLabors.ImageSharp with dimension tracking |
| **Video Streaming** | Upload videos via URL or direct upload; served with proper MIME types |
| **Safe File Paths** | Path traversal protection on all file lookups |
| **Content Type Mapping** | Comprehensive extension-to-MIME mapping for 30+ file formats |

### Plugin System
| Feature | Description |
|---------|-------------|
| **Hot-Loading** | Drop DLLs into the `plugins/` folder; loaded and initialized at runtime |
| **Isolated Load Contexts** | Each plugin uses a collectible `AssemblyLoadContext` with its own dependency resolver |
| **Runtime Enable/Disable** | Toggle plugins on and off without restarting the server |
| **Dynamic Route Registration** | Plugins register both MVC controllers and legacy request delegates |
| **Admin Menu Integration** | Plugins inject items into the admin sidebar menu dynamically |
| **Plugin Marketplace** | Built-in package manager for browsing and downloading community plugins |
| **Lifecycle Hooks** | `OnLoadAsync`, `OnUpdateAsync`, `OnUnloadAsync` for full control over plugin lifecycle |
| **Event Subscriptions** | Plugins subscribe to any domain event through the event bus |

### Performance & Infrastructure
| Feature | Description |
|---------|-------------|
| **Static File Caching** | In-memory file cache with per-file read counters and semaphore-based locking |
| **Gzip/Deflate Compression** | Automatic response compression for text-based content types |
| **In-Memory Cache** | TTL-based cache service with automatic expired-item cleanup every 5 minutes |
| **WebSocket Server** | Real-time bidirectional communication with broadcast and echo protocols |
| **Health Check Endpoint** | `/health` endpoint for load balancer and monitoring integration |
| **Graceful Shutdown** | Ordered service teardown: download processor → plugins → server |

### Admin Panel
| Feature | Description |
|---------|-------------|
| **Dashboard** | Overview panel with system status and quick actions |
| **Post Editor** | Full post creation and editing with category/tag assignment |
| **Media Library** | Browse, upload, and manage all media assets |
| **User Management** | Create, ban, unban, and assign roles to users |
| **Plugin Store** | Browse, install, enable, and disable plugins from the admin UI |
| **Settings** | Site configuration, security settings, and advanced options |
| **Category & Tag Management** | Full taxonomy CRUD from the admin interface |

### Core Components

- **API Layer**: RESTful endpoints with JSON serialization, mapped via `Endpoints.cs` and ASP.NET Core controllers
- **Plugin Engine**: Dynamic DLL loading via `AssemblyLoadContext` with dependency isolation, hot-reload, and runtime enable/disable
- **Data Access**: FeatherDatabase — a custom lightweight MySQL ORM that auto-creates tables from C# classes, uses `ConcurrentDictionary`-cached reflection, and protects against destructive queries
- **Event System**: In-memory pub/sub event bus with 30+ domain events covering posts, users, media, plugins, and authentication
- **Caching**: Two-layer caching — static file cache with per-file read tracking and a TTL-based in-memory cache for dynamic data
- **Authentication**: Dual JWT + Cookie authentication with automatic token renewal, 2FA, account lockout, and role hierarchy
- **Middleware Pipeline**: User control (ban/maintenance), slug routing, plugin route dispatch, and forwarded headers

### Request Pipeline

```
HTTP Request
    │
    ├── CORS (DynamicPolicy)
    ├── Authentication (JWT + Cookie)
    ├── Authorization
    ├── Forwarded Headers
    ├── UserControlMiddleware (ban check / maintenance mode)
    ├── Plugin Routes (plugin-registered legacy routes)
    ├── SlugRoutingMiddleware (/blog/*, /category/*, /tag/*)
    ├── MVC / Razor Pages / API Controllers
    └── Static File Serving (with cache + compression)
```

## Getting Started

### Prerequisites

- **.NET 8.0 SDK** or later
- **MySQL 8.0** (or compatible) running and accessible
- **Nginx** (recommended for production, with SSL termination)

### Quick Start

1. **Clone and build:**
   ```bash
   git clone https://github.com/your-username/SharpPress.git
   cd SharpPress/Server
   dotnet restore
   dotnet build
   ```

2. **Configure MySQL:**
   Edit `config.json` (auto-generated on first run) with your MySQL credentials:
   ```json
   {
     "MySQL_Config": {
       "host": "localhost",
       "port": 3306,
       "database_name": "sharppress",
       "database_username": "root",
       "database_password": "your_password"
     }
   }
   ```

3. **Run the server:**
   ```bash
   dotnet run
   # Or specify a custom port:
   dotnet run -- 8080
   # Or use the environment variable:
   HTTP_PORT=8080 dotnet run
   ```

   The server starts on `http://localhost:12001` by default.

4. **Access the admin panel:**
   Navigate to `/Admin` in your browser. The default admin password is configured in `config.json`.

### First Run

On first launch, SharpPress:
- Generates a default `config.json` if one does not exist
- Creates the MySQL database tables automatically (Users, Posts, Categories, Tags, MediaItems, and join tables)
- Creates indexes on frequently queried columns (Slug, Username, UUID, MediaType)
- Prepares the `media/`, `media/thumbnails/`, `videos/`, and `logs/` directories

## Configuration

All configuration is managed through `config.json` in the application root. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `DebugMode` | `false` | Enables verbose logging |
| `JwtSecret` | (generated) | HMAC-SHA256 key for JWT signing — **change in production** |
| `JwtExpiryHours` | `24` | JWT token lifetime |
| `PanelDomain` | `example.com` | Your domain, used for CORS and email links |
| `MaxFailedLoginAttempts` | `5` | Lockout threshold |
| `LockoutDurationMinutes` | `3` | Temporary lockout duration |
| `EnableCompression` | `true` | Gzip/Deflate response compression |
| `EnableStaticFileCache` | `true` | In-memory static file caching |
| `CacheExpiryMinutes` | `15` | TTL for the in-memory cache |
| `email_host` | `smtp.gmail.com` | SMTP server hostname |
| `email_port` | `587` | SMTP server port |
| `email_useSsl` | `false` | Enable STARTTLS for SMTP |

### Site Settings

Site settings are configurable from the admin panel and include:

- **General**: Site name, description, admin email, timezone, footer text
- **Security**: Force HTTPS, allow registration, require 2FA, session timeout
- **Advanced**: Enable cache, maintenance mode, custom CSS injection

## Plugin Development

SharpPress's plugin architecture allows you to extend functionality without modifying core code. Plugins are compiled C# class libraries that implement the `IPlugin` interface. They are loaded into isolated `AssemblyLoadContext` instances, meaning each plugin has its own dependency resolution — no version conflicts with the host or other plugins.

### Plugin Interface

```csharp
using SharpPress.Plugins;

public class MyPlugin : IPlugin
{
    public string Name => "MyPlugin";
    public string Version => "1.0.0";
    public string Author => "Your Name";
    public string? Description => "A brief description of what this plugin does.";

    public async Task OnLoadAsync(IPluginContext context)
    {
        // Called when the plugin is loaded or enabled.
        // Register admin menu items, subscribe to events, initialize resources.
    }

    public async Task OnUpdateAsync(IPluginContext context)
    {
        // Called periodically (every 50ms) while the plugin is enabled.
        // Use for background tasks, polling, or state updates.
    }

    public async Task OnUnloadAsync()
    {
        // Called when the plugin is disabled or the server is shutting down.
        // Clean up resources, unregister event handlers.
    }
}
```

### Plugin Context

The `IPluginContext` object passed to `OnLoadAsync` and `OnUpdateAsync` provides access to:

- **Logger** — Write to the shared log system
- **Service Scope Factory** — Create scoped service instances from the DI container
- **Service Provider** — Access registered singleton services
- **Admin Menu Service** — Register/unregister sidebar items in the admin panel
- **Plugin Name** — The name of the current plugin instance

### Building a Plugin

1. Create a new Class Library project targeting `net8.0`
2. Add a reference to the SharpPress core (or copy the plugin interface definitions)
3. Implement `IPlugin`
4. Build the project and copy the output DLL to the `plugins/` directory

See `SamplePlugin.cs` at the repository root for a minimal template.

## Database

SharpPress uses **MySQL 8.0** via the `MySqlConnector` library. The built-in ORM (`FeatherDatabase`) provides:

### Auto-Migration
Tables are created automatically from C# model classes that inherit from `FeatherData`. Simply define your model and call `CreateTable<T>()` — the ORM generates the schema, maps properties to columns, and creates a `BIGINT AUTO_INCREMENT` primary key.

### Safety Guards
- `DeleteWhere` requires a `WHERE` clause to prevent accidental full-table deletion
- `ExecuteQuery` restricts destructive commands (`DROP`, `DELETE`, `TRUNCATE`), allowing only `SELECT`
- Reflected property metadata is cached in a `ConcurrentDictionary` for performance

### Core Tables
| Table | Description |
|-------|-------------|
| `User` | User accounts with UUID, roles, 2FA, and lockout fields |
| `Post` | Content entries with title, slug, status, type, and scheduling |
| `Category` | Hierarchical categories with slug and sort order |
| `Tag` | Flat tag system with slug |
| `PostCategory` | Many-to-many post-category join table |
| `PostTag` | Many-to-many post-tag join table |
| `MediaItem` | Uploaded files with metadata, thumbnails, and dimensions |

### Connection Pooling
The MySQL connection string is configured with connection pooling enabled by default, optimized for web application workloads.

## Deployment

### Production Setup with Nginx

SharpPress is designed to run behind Nginx as a reverse proxy. A sample configuration is provided in `Nginx Configuration.txt`:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$host$request_uri;
}

server {
    server_name your-domain.com;
    listen 443 ssl http2;

    ssl_certificate /path/to/your/cert.pem;
    ssl_certificate_key /path/to/your/key.pem;

    location / {
        proxy_pass http://127.0.0.1:12001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
    }
}
```

### Running as a Service

Publish the application and configure it as a systemd service:

```bash
dotnet publish -c Release -o /opt/sharppress
```

Create `/etc/systemd/system/sharppress.service`:
```ini
[Unit]
Description=SharpPress CMS
After=network.target mysql.service

[Service]
WorkingDirectory=/opt/sharppress
ExecStart=/usr/bin/dotnet SharpPress.dll
Restart=always
RestartSec=10
Environment=HTTP_PORT=12001
Environment=ASPNETCORE_ENVIRONMENT=Production

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable sharppress
sudo systemctl start sharppress
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `HTTP_PORT` | Override the default HTTP port (12001) |

You can also pass the port as the first command-line argument: `dotnet run -- 8080`.

## Security

- **Password Hashing**: PBKDF2 with 10,000 iterations and a 16-byte random salt
- **JWT Signing**: HMAC-SHA256 with configurable secret key
- **HTTP-Only Cookies**: Authentication tokens are stored in `HttpOnly`, `Secure`, `SameSite=Lax` cookies
- **HTML Sanitization**: User-generated HTML content is sanitized via the `HtmlSanitizer` library
- **Path Traversal Protection**: All file lookups block directory traversal attempts (`..`, `/`, `\`)
- **SQL Injection Prevention**: Parameterized queries through the ORM; raw `DELETE` and `DROP` are blocked
- **Account Lockout**: Brute-force protection with configurable thresholds and durations
- **Maintenance Mode**: Admins can enable maintenance mode, blocking all non-essential access with a styled 503 page

For security vulnerability reporting, please review the [Security Policy](SECURITY.md).

## Star History

<a href="https://www.star-history.com/?repos=VoidbornGames%2FSharpPress&type=date&logscale=&legend=bottom-right">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=VoidbornGames/SharpPress&type=date&theme=dark&legend=bottom-right" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=VoidbornGames/SharpPress&type=date&legend=bottom-right" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=VoidbornGames/SharpPress&type=date&legend=bottom-right" />
 </picture>
</a>
