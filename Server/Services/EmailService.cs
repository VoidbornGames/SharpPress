using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using SharpPress.Models;

namespace SharpPress.Services
{
    public class EmailService
    {
        private readonly string _host;
        private readonly int _port;
        private readonly string _username;
        private readonly string _password;
        private readonly bool _useSsl;

        public EmailService(ServerConfig config)
        {
            _host = config.email_host;
            _port = config.email_port;
            _username = config.email_username;
            _password = config.email_password;
            _useSsl = config.email_useSsl;
        }

        public async Task SendAsync(string to, string subject, string body, bool isHtml = false)
        {
            var message = new MimeMessage();
            message.From.Add(MailboxAddress.Parse(_username));
            message.To.Add(MailboxAddress.Parse(to));
            message.Subject = subject;

            var builder = new BodyBuilder();
            if (isHtml)
                builder.HtmlBody = body;
            else
                builder.TextBody = body;

            message.Body = builder.ToMessageBody();

            using var client = new SmtpClient();
            await client.ConnectAsync(_host, _port, _useSsl ? SecureSocketOptions.StartTls : SecureSocketOptions.None);
            await client.AuthenticateAsync(_username, _password);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        }
    }
}
