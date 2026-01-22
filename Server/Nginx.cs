using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics;
using System.Text.RegularExpressions;
using SharpPress.Models;
using SharpPress.Services;

namespace SharpPress
{
    public class Nginx
    {
        private ServerConfig config;

        public Nginx(ConfigManager configManager)
        {
            config = configManager.Config;
        }

        public async Task RunCommand(string command, string arguments)
        {
            try
            {
                var process = new Process();
                process.StartInfo.FileName = command;
                process.StartInfo.Arguments = arguments;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;

                process.Start();

                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                process.WaitForExit();

                if (config.DebugMode)
                {
                    Console.WriteLine("Output: " + output);
                    if (!string.IsNullOrEmpty(error))
                        Console.WriteLine("Error: " + error);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: " + ex.Message);
            }
        }


        public string configHttp = @"
server {
    listen %SitePort%;
    server_name %SiteName%;

    root %SitePath%;
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.3-fpm-%SiteName%.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\.ht {
        deny all;
    }
}";
        public string configSSL = @"
server {
    listen 80;
    server_name %SiteName%;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name %SiteName%;

    ssl_certificate /etc/letsencrypt/live/%SiteName%/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/%SiteName%/privkey.pem;

    root %SitePath%;
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.3-fpm-%SiteName%.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\.ht {
        deny all;
    }
}";
        public string poolConfig = @"
[%SiteName%]
user = www-data
group = www-data
listen = /run/php/php8.3-fpm-%SiteName%.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

; Security restrictions
php_admin_value[open_basedir] = %SitePath%:/tmp
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen,show_source
php_admin_flag[allow_url_fopen] = Off
php_admin_flag[allow_url_include] = Off

; Process management
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
pm.max_requests = 500
";
    }
}