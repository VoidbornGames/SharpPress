using SharpPress.Models;
using SharpPress.Services;
using System;

namespace SharpPress.Middlewares
{
    public class UserControlMiddleware
    {
        private readonly string pre_bannedPage = @"<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Account Suspended</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }
        .ban-container {
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 24px;
            padding: 3rem 2rem;
            max-width: 550px;
            width: 100%;
            text-align: center;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(148, 163, 184, 0.1);
        }
        .icon {
            font-size: 5rem;
            margin-bottom: 1.5rem;
            display: inline-block;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        h1 {
            color: #ef4444;
            font-size: 1.875rem;
            margin-bottom: 1rem;
            font-weight: 700;
            letter-spacing: -0.5px;
        }
        .subtitle {
            color: #cbd5e1;
            font-size: 0.95rem;
            margin-bottom: 2rem;
            line-height: 1.7;
        }
        .reason-box {
            background: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 12px;
            padding: 1.25rem;
            margin-bottom: 2rem;
            text-align: left;
        }
        .reason-label {
            color: #94a3b8;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        .reason-text {
            color: #e2e8f0;
            font-size: 0.95rem;
        }
        .contact-section {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(148, 163, 184, 0.2);
            padding: 1.5rem;
            border-radius: 12px;
            margin-bottom: 1.5rem;
        }
        .contact-title {
            color: #94a3b8;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
            margin-bottom: 1rem;
        }
        .contact-info {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }
        .contact-link {
            color: #60a5fa;
            text-decoration: none;
            font-weight: 500;
            font-size: 0.95rem;
            transition: color 0.2s ease;
        }
        .contact-link:hover {
            color: #93c5fd;
            text-decoration: underline;
        }
        .back-link {
            display: inline-block;
            color: #64748b;
            text-decoration: none;
            font-size: 0.9rem;
            padding: 0.75rem 1.5rem;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(148, 163, 184, 0.2);
            border-radius: 8px;
            transition: all 0.2s ease;
        }
        .back-link:hover {
            color: #e2e8f0;
            border-color: rgba(148, 163, 184, 0.4);
            background: rgba(255, 255, 255, 0.05);
        }
    </style>
</head>
<body>
    <div class='ban-container'>
        <div class='icon'>🚫</div>
        <h1>Account Suspended</h1>
        <p class='subtitle'>Your account has been suspended due to a violation of our terms of service and community guidelines.</p>
        
        <div class='reason-box'>
            <div class='reason-label'>Reason for Suspension</div>
            <div class='reason-text'>Your account has been restricted pending review by our moderation team. Further action may be taken based on the severity of the violation.</div>
        </div>

        <div class='contact-section'>
            <div class='contact-title'>Need Help?</div>
            <div class='contact-info'>
                <a href='mailto:%support@mail%' class='contact-link'>📧 Contact Support</a>
                <a href='/appeal' class='contact-link'>📋 Appeal Suspension</a>
            </div>
        </div>

        <a href='/' class='back-link'>← Return to Home</a>
    </div>
</body>
</html>";
        private readonly string pre_maintenancePage = @"<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Maintenance in Progress</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }
        .maintenance-container {
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 24px;
            padding: 3rem 2rem;
            max-width: 550px;
            width: 100%;
            text-align: center;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(251, 146, 60, 0.2);
        }
        .icon {
            font-size: 4.5rem;
            margin-bottom: 1.5rem;
            display: inline-block;
            animation: spin 3s linear infinite;
        }
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        h1 {
            color: #fb9235;
            font-size: 1.875rem;
            margin-bottom: 1rem;
            font-weight: 700;
            letter-spacing: -0.5px;
        }
        .subtitle {
            color: #cbd5e1;
            font-size: 1rem;
            margin-bottom: 2rem;
            line-height: 1.7;
        }
        .info-box {
            background: rgba(251, 146, 60, 0.08);
            border: 1px solid rgba(251, 146, 60, 0.3);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        .info-item {
            color: #e2e8f0;
            font-size: 0.95rem;
            line-height: 1.6;
            margin-bottom: 0.75rem;
        }
        .info-item:last-child {
            margin-bottom: 0;
        }
        .progress-bar {
            width: 100%;
            height: 4px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 2px;
            margin-top: 1.5rem;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #fb9235, #f59e0b);
            animation: progress 2s ease-in-out infinite;
        }
        @keyframes progress {
            0% { width: 0%; }
            50% { width: 100%; }
            100% { width: 100%; }
        }
        .footer {
            margin-top: 2rem;
            color: #64748b;
            font-size: 0.85rem;
        }
    </style>
</head>
<body>
    <div class='maintenance-container'>
        <div class='icon'>🛠️</div>
        <h1>Maintenance in Progress</h1>
        <p class='subtitle'>We're performing scheduled maintenance to improve your experience. We'll be back online shortly.</p>
        
        <div class='info-box'>
            <div class='info-item'>⏳ Estimated time: Less than 15 minutes</div>
            <div class='info-item'>📧 For urgent matters: <a href='mailto:%support@mail%' style='color: #60a5fa; text-decoration: none;'>Contact Support</a></div>
            <div class='progress-bar'>
                <div class='progress-fill'></div>
            </div>
        </div>

        <div class='footer'>Thank you for your patience.</div>
    </div>
</body>
</html>";

        private readonly string _bannedPage = "";
        private readonly string _maintenancePage = "";

        private readonly AuthenticationService _authService;
        private readonly RequestDelegate _next;
        private readonly Logger _logger;
        private bool _isMaintenanceMode = false;

        public UserControlMiddleware(RequestDelegate next, Logger logger, AuthenticationService authenticationService, ServerConfig config)
        {
            _next = next;
            _logger = logger;
            _authService = authenticationService;

            _bannedPage = pre_bannedPage.Replace("%support@mail%", config.SiteSettings?.General?.AdminEmail ?? $"support@{config.PanelDomain}");
            _maintenancePage = pre_maintenancePage.Replace("%support@mail%", config.SiteSettings?.General?.AdminEmail ?? $"support@{config.PanelDomain}");
        }

        public async Task InvokeAsync(HttpContext context, FeatherDatabase database, ServerConfig config)
        {
            _isMaintenanceMode = config.SiteSettings?.Advanced?.MaintenanceMode ?? false;

            if (_isMaintenanceMode && !IsUserAuthorizedForMaintenance(context))
            {
                if (!IsAllowedPath(context.Request.Path.Value) && !IsStaticAsset(context.Request.Path.Value))
                {
                    context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                    context.Response.ContentType = "text/html; charset=utf-8";
                    await context.Response.WriteAsync(_maintenancePage);
                    return;
                }
            }

            if (context.User.Identity?.IsAuthenticated ?? false)
            {
                var username = context.User.Identity?.Name;

                if (string.IsNullOrEmpty(username))
                {
                    _logger.Log("UserControlMiddleware: Username is null or empty");
                    ClearAuthCookie(context);
                    context.Response.Redirect("/");
                    return;
                }

                var user = await database.GetByColumn<User>("Username", username);

                if (user == null)
                {
                    _logger.Log($"UserControlMiddleware: User '{username}' not found in database");
                    ClearAuthCookie(context);
                    context.Response.Redirect(context.Request.Path + context.Request.QueryString);
                    return;
                }

                if (!user.IsAtLeastUser())
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    context.Response.ContentType = "text/html; charset=utf-8";
                    await context.Response.WriteAsync(_bannedPage);
                    return;
                }

                _ = Task.Run(async () =>
                {
                    if (!user.IsActive)
                        user.IsActive = true;

                    var now = DateTime.UtcNow;
                    if ((now - user.LastActive).TotalMinutes > 5)
                    {
                        user.LastActive = now;
                        await database.SaveData(user);
                    }
                });

                if (context.Request.Cookies.TryGetValue("X-Access-Token", out var token))
                {
                    if (string.IsNullOrEmpty(token) || !_authService.ValidateJwtToken(token))
                    {
                        ClearAuthCookie(context);
                        context.Response.Redirect(context.Request.Path + context.Request.QueryString);
                        return;
                    }

                    var renewedToken = _authService.TryRenewTokenIfExpiringSoon(token, user);
                    if (renewedToken != null)
                    {
                        context.Response.Cookies.Append("X-Access-Token", renewedToken, new CookieOptions
                        {
                            HttpOnly = true,
                            Secure = true,
                            SameSite = SameSiteMode.Lax,
                            Expires = DateTimeOffset.UtcNow.AddDays(7)
                        });
                    }
                }
            }

            await _next(context);
        }

        private bool IsUserAuthorizedForMaintenance(HttpContext context)
        {
            if (!context.User.Identity?.IsAuthenticated ?? false)
                return false;

            var username = context.User.Identity?.Name;
            if (string.IsNullOrEmpty(username))
                return false;

            return true;
        }

        private bool IsAllowedPath(string? path)
        {
            if (string.IsNullOrEmpty(path))
                return false;

            path = path.ToLowerInvariant();

            var allowedPaths = new[]
            {
                "/",
                "/login",
                "/register",
                "/forgot-password",
                "/reset-password",
                "/privacy",
                "/terms",
                "/health",
                "/api/auth/login",
                "/api/auth/register"
            };

            return allowedPaths.Any(p => path == p || path.StartsWith(p + "/"));
        }

        private bool IsStaticAsset(string? path)
        {
            if (string.IsNullOrEmpty(path))
                return false;

            path = path.ToLowerInvariant();

            var staticPaths = new[]
            {
                "/css/",
                "/js/",
                "/images/",
                "/assets/",
                "/fonts/",
                "/favicon.ico",
                ".css",
                ".js",
                ".png",
                ".jpg",
                ".gif",
                ".svg",
                ".woff",
                ".woff2"
            };

            return staticPaths.Any(p => path.Contains(p));
        }

        private void ClearAuthCookie(HttpContext context)
        {
            context.Response.Cookies.Delete("X-Access-Token");
        }
    }
}