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


        // For production change the domain (voidgames.ir) in verifyCodeEmail to your own domain that dashboard is running on.
        public string verifyCodeEmail = @"<!DOCTYPE html>
<html lang=""en"">
<head>
<meta charset=""UTF-8"">
<meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
<title>SharpPress Dashboard</title>
<link href=""https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap"" rel=""stylesheet"">
<style>
    /* Base Styles */
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: 'Roboto Mono', monospace;
        background: #121212;
        color: #fff;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: flex-start;
        min-height: 100vh;
        padding: 40px 20px;
    }

    /* Header */
    header {
        text-align: center;
        margin-bottom: 40px;
    }

    header h1 {
        font-size: 2.5em;
        background: linear-gradient(90deg, #ff416c, #ff4b2b);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 10px;
    }

    header p {
        font-size: 1em;
        color: #aaa;
    }

    a.button {
        display: inline-block;
        padding: 12px 28px;
        margin-top: 20px;
        background: linear-gradient(90deg, #00f260, #0575e6);
        color: #fff;
        font-weight: bold;
        text-decoration: none;
        border-radius: 12px;
        box-shadow: 0 8px 20px rgba(0,0,0,0.4);
        transition: all 0.3s ease;
    }

    a.button:hover {
        transform: translateY(-3px);
        box-shadow: 0 12px 25px rgba(0,0,0,0.6);
    }

    /* Container */
    .container {
        max-width: 900px;
        width: 100%;
        padding: 30px;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 20px;
        backdrop-filter: blur(10px);
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        display: flex;
        flex-direction: column;
        gap: 30px;
    }

    /* Stats Section */
    .stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 20px;
    }

    .stat-box {
        background: rgba(255,255,255,0.08);
        border-radius: 15px;
        padding: 20px;
        text-align: center;
        transition: transform 0.3s ease, background 0.3s ease;
        box-shadow: 0 5px 15px rgba(0,0,0,0.3);
    }

    .stat-box:hover {
        background: rgba(255,255,255,0.12);
        transform: scale(1.05);
    }

    .stat-box strong {
        display: block;
        font-size: 0.9em;
        color: #ff9e80;
        margin-bottom: 10px;
    }

    .stat-box p {
        font-size: 1.2em;
        font-weight: bold;
        color: #fff;
    }

    /* Commands */
    .commands {
        display: flex;
        flex-wrap: wrap;
        justify-content: center;
        gap: 12px;
    }

    .commands code {
        background: rgba(0,0,0,0.5);
        padding: 6px 12px;
        border-radius: 8px;
        font-size: 0.8em;
        color: #00f2ff;
        cursor: default;
        transition: background 0.3s ease;
    }

    .commands code:hover {
        background: rgba(0,255,255,0.2);
    }

    /* Footer */
    footer {
        margin-top: 50px;
        font-size: 0.7em;
        color: #888;
    }

    /* Responsive */
    @media (max-width: 600px) {
        .stat-box p { font-size: 1em; }
        header h1 { font-size: 2em; }
    }
</style>
</head>
<body>

<div id="":nn"" class=""ii gt"" jslog=""20277; u014N:xr6bB; 1:WyIjdGhyZWFkLWY6MTg0NTg3Njk0OTE4OTcyNjM0NCJd; 4:WyIjbXNnLWY6MTg0NTg3Njk0OTE4OTcyNjM0NCIsbnVsbCxudWxsLG51bGwsMSwwLFsxLDAsMF0sNTgsMzY0LG51bGwsbnVsbCxudWxsLG51bGwsbnVsbCwxLG51bGwsbnVsbCxudWxsLG51bGwsbnVsbCxudWxsLG51bGwsbnVsbCxudWxsLDAsMF0.""><div id="":no"" class=""a3s aiL msg-6714434747736195579""><u></u>



    
    

    




<div style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';color:#718096;height:100%;line-height:1.4;margin:0;padding:0;width:100%;background-color:#f2f4f6"">
    <table width=""100%"" cellpadding=""0"" cellspacing=""0"" style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol'"">
        <tbody><tr>
            <td style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';width:100%;margin:0;padding:0;background-color:#f2f4f6"" align=""center"">
                <table width=""100%"" cellpadding=""0"" cellspacing=""0"" style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol'"">
                    
                    <tbody><tr>
                        <td style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';padding:25px 0;text-align:center"">
                            <a style=""box-sizing:border-box;font-family:Arial,'Helvetica Neue',Helvetica,sans-serif;font-size:16px;font-weight:bold;color:#2f3133;text-decoration:none"" href=""https://voidborn-games.ir"" target=""_blank"" data-saferedirecturl=""https://www.google.com/url?q=https://voidborn-games.ir&amp;source=gmail&amp;ust=1760822014733000&amp;usg=AOvVaw3-U8xHE6T1MKQO_3vKIsjB"">
                                Voidborn Games
                            </a>
                        </td>
                    </tr>

                    
                    <tr>
                        <td style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';width:100%;margin:0;padding:0;border-top:1px solid #edeff2;border-bottom:1px solid #edeff2;background-color:#fff"" width=""100%"">
                            <table style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';width:auto;max-width:570px;margin:0 auto;padding:0"" align=""center"" width=""570"" cellpadding=""0"" cellspacing=""0"">
                                <tbody><tr>
                                    <td style=""box-sizing:border-box;font-family:Arial,'Helvetica Neue',Helvetica,sans-serif;padding:35px"">
                                        
                                        <h1 style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';margin-top:0;color:#2f3133;font-size:19px;font-weight:bold;text-align:left"">
                                                                                            Hello %User_Name%.
                                                                                    </h1>

                                        
                                                                                    <p style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';text-align:left;margin-top:0;color:#74787e;font-size:16px;line-height:1.5em"">
                                                Your password reset link has arrived!
                                            </p>
                                                                                    <p style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';text-align:left;margin-top:0;color:#74787e;font-size:16px;line-height:1.5em"">
                                                Username: %Username%
                                            </p>
                                        
                                        
                                                                                    <table style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';width:100%;margin:30px auto;padding:0;text-align:center"" align=""center"" width=""100%"" cellpadding=""0"" cellspacing=""0"">
                                                <tbody><tr>
                                                    <td align=""center"" style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol'"">
                                                        
                                                        <a href=""%Reset_Link%"" style=""box-sizing:border-box;overflow:hidden;font-family:Arial,'Helvetica Neue',Helvetica,sans-serif;display:inline-block;width:200px;min-height:20px;padding:10px;background-color:#3869d4;border-radius:3px;color:#ffffff;font-size:15px;line-height:25px;text-align:center;text-decoration:none"" class=""m_-6714434747736195579button"" target=""_blank"" data-saferedirecturl=""https://www.google.com/url?q=https://voidborn-games.ir&amp;source=gmail&amp;ust=1760822014733000&amp;usg=AOvVaw3-U8xHE6T1MKQO_3vKIsjB"">
                                                            Reset My Password
                                                        </a>
                                                    </td>
                                                </tr>
                                            </tbody></table>
                                        
                                        
                                        
                                        
                                        <p style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';text-align:left;margin-top:0;color:#74787e;font-size:16px;line-height:1.5em"">
                                            Regards,<br>Voidborn Games
                                        </p>

                                        
                                                                                    <table style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';margin-top:25px;padding-top:25px;border-top:1px solid #edeff2"">
                                                <tbody><tr>
                                                    <td style=""box-sizing:border-box;font-family:Arial,'Helvetica Neue',Helvetica,sans-serif"">
                                            </a>
                                                        </p>
                                                    </td>
                                                </tr>
                                            </tbody></table>
                                                                            </td>
                                </tr>
                            </tbody></table>
                        </td>
                    </tr>

                    
                    <tr>
                        <td style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol'"">
                            <table style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';width:auto;max-width:570px;margin:0 auto;padding:0;text-align:center"" align=""center"" width=""570"" cellpadding=""0"" cellspacing=""0"">
                                <tbody><tr>
                                    <td style=""box-sizing:border-box;font-family:Arial,'Helvetica Neue',Helvetica,sans-serif;color:#aeaeae;padding:35px;text-align:center"">
                                        <p style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';text-align:left;margin-top:0;color:#74787e;font-size:12px;line-height:1.5em"">
                                            © 2025
                                            <a style=""box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';color:#3869d4"" href=""https://voidgames.ir"" target=""_blank"" data-saferedirecturl=""https://www.google.com/url?q=https://voidgames.ir&amp;source=gmail&amp;ust=1760822014733000&amp;usg=AOvVaw3-U8xHE6T1MKQO_3vKIsjB"">Voidborn Games</a>.
                                            All rights reserved.
                                        </p>
                                    </td>
                                </tr>
                            </tbody></table>
                        </td>
                    </tr>
                </tbody></table>
            </td>
        </tr>
    </tbody></table><div class=""yj6qo""></div><div class=""adL"">
</div></div><div class=""adL"">
</div></div></div>

</body>
</html>
";
    }
}
