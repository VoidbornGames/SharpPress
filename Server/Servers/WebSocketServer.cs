using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.WebSockets;
using System.Text;
using Newtonsoft.Json;
using SharpPress.Models;
using SharpPress.Services;

namespace SharpPress.Servers
{
    public class ClientConnection
    {
        public WebSocket Socket { get; }
        public string Id { get; }
        public DateTime ConnectedAt { get; }

        public ClientConnection(WebSocket socket)
        {
            Socket = socket;
            Id = Guid.NewGuid().ToString("N");
            ConnectedAt = DateTime.UtcNow;
        }
    }

    public class WebSocketServer : IManualServer
    {
        private readonly HttpListener _http;
        private readonly Logger _logger;
        private readonly CancellationTokenSource _cts = new();
        private readonly ConcurrentDictionary<string, ClientConnection> _clients = new();
        private readonly int _bufferSize = 4 * 1024;

        public WebSocketServer(ServerSettings settings, Logger logger)
        {
            _logger = logger;
            _http = new HttpListener();
            _http.Prefixes.Add($"http://*:{settings.httpPort}/ws/");
        }

        public async Task Start()
        {
            _http.Start();
            _logger.Log($"🌐 WebSocketServer listening: {string.Join(", ", _http.Prefixes)}");

            _ = AcceptLoop(_cts.Token);
        }

        public async Task StopAsync()
        {
            _cts.Cancel();

            try
            {
                _http.Stop();
            }
            catch { }

            foreach (var client in _clients.Values)
            {
                try
                {
                    await client.Socket.CloseAsync(
                        WebSocketCloseStatus.NormalClosure,
                        "Server Shutting Down",
                        CancellationToken.None);
                }
                catch { }
            }

            _logger.Log("🛑 WebSocketServer stopped.");
        }

        private async Task AcceptLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                HttpListenerContext? ctx = null;

                try
                {
                    ctx = await _http.GetContextAsync();
                }
                catch when (token.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogError($"⚠ AcceptLoop error: {ex}");
                    continue;
                }

                if (ctx.Request.IsWebSocketRequest)
                {
                    _ = HandleClient(ctx, token);
                }
                else
                {
                    ctx.Response.StatusCode = 400;
                    byte[] msg = Encoding.UTF8.GetBytes("<html><head><style>body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;font-family:sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);color:white;}</style></head><body>This endpoint only accepts WebSocket connections.</body></html>");
                    ctx.Response.OutputStream.Write(msg, 0, msg.Length);
                    ctx.Response.Close();
                }
            }
        }

        private async Task HandleClient(HttpListenerContext ctx, CancellationToken token)
        {
            WebSocketContext wsCtx;

            try
            {
                wsCtx = await ctx.AcceptWebSocketAsync(null);
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Failed accepting websocket: {ex}");
                ctx.Response.StatusCode = 500;
                ctx.Response.Close();
                return;
            }

            var client = new ClientConnection(wsCtx.WebSocket);
            _clients.TryAdd(client.Id, client);
            _logger.Log($"🔵 Client connected: {client.Id}");

            try
            {
                await ReceiveLoop(client, token);
            }
            catch (Exception ex)
            {
                _logger.LogError($"⚠ Client error ({client.Id}): {ex}");
            }
            finally
            {
                _clients.TryRemove(client.Id, out _);

                if (client.Socket.State == WebSocketState.Open)
                {
                    try { await client.Socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closed", CancellationToken.None); } catch { }
                }

                _logger.Log($"🔴 Client disconnected: {client.Id}");
            }
        }

        private async Task ReceiveLoop(ClientConnection client, CancellationToken token)
        {
            var socket = client.Socket;
            var buffer = new ArraySegment<byte>(new byte[_bufferSize]);
            var ms = new MemoryStream();

            while (!token.IsCancellationRequested && socket.State == WebSocketState.Open)
            {
                ms.SetLength(0);
                WebSocketReceiveResult? result;

                do
                {
                    result = await socket.ReceiveAsync(buffer, token);

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", token);
                        return;
                    }

                    ms.Write(buffer.Array!, buffer.Offset, result.Count);

                } while (!result.EndOfMessage);

                string json = Encoding.UTF8.GetString(ms.ToArray());
                _logger.Log($"📥 [{client.Id}]: {json}");

                Data? req = null;
                try { req = JsonConvert.DeserializeObject<Data>(json); } catch { }

                if (req == null)
                {
                    await Send(client.Socket, new Data { command = "error", jsond = "Invalid JSON" }, token);
                    continue;
                }

                switch (req.command)
                {
                    case "broadcast":
                        await Broadcast(new Data
                        {
                            command = "broadcast",
                            jsond = req.jsond
                        });
                        break;

                    default:
                        await Send(socket, new Data
                        {
                            command = "echo",
                            jsond = req.jsond
                        }, token);
                        break;
                }
            }
        }

        public async Task Send(WebSocket socket, Data data, CancellationToken token)
        {
            string json = JsonConvert.SerializeObject(data);
            byte[] bytes = Encoding.UTF8.GetBytes(json);

            try
            {
                await socket.SendAsync(bytes, WebSocketMessageType.Text, true, token);
                _logger.Log($"📤 Sent: {json}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"⚠ Send failed: {ex}");
            }
        }

        public async Task Broadcast(Data data)
        {
            string json = JsonConvert.SerializeObject(data);
            byte[] bytes = Encoding.UTF8.GetBytes(json);

            foreach (var client in _clients.Values)
            {
                if (client.Socket.State == WebSocketState.Open)
                {
                    try
                    {
                        await client.Socket.SendAsync(bytes, WebSocketMessageType.Text, true, CancellationToken.None);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"⚠ Broadcast failed to {client.Id}: {ex}");
                    }
                }
            }

            _logger.Log($"📣 Broadcast to {_clients.Count} clients: {json}");
        }
    }
}
