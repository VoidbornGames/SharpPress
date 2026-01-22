using System;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using SharpPress.Models;
using SharpPress.Services;

namespace SharpPress.Services
{
    public class AuthenticationService
    {
        private readonly string _jwtSecret;
        private readonly SymmetricSecurityKey _jwtKey;
        private readonly ServerConfig _config;
        private readonly Logger _logger;
        private readonly ConcurrentDictionary<string, int> _failedLoginAttempts = new();
        private readonly ConcurrentDictionary<string, DateTime> _lockedAccounts = new();

        public AuthenticationService(ServerConfig config, Logger logger)
        {
            _jwtSecret = config.JwtSecret ?? "your-super-secret-jwt-key-change-this-in-production-32-chars-min";
            _jwtKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret));
            _config = config;
            _logger = logger;
        }

        public string HashPassword(string password)
        {
            byte[] salt;
            new RNGCryptoServiceProvider().GetBytes(salt = new byte[16]);

            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000);
            byte[] hash = pbkdf2.GetBytes(20);

            byte[] hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);

            return Convert.ToBase64String(hashBytes);
        }

        public bool VerifyPassword(string inputPassword, string storedPassword)
        {
            try
            {
                byte[] hashBytes = Convert.FromBase64String(storedPassword);

                byte[] salt = new byte[16];
                Array.Copy(hashBytes, 0, salt, 0, 16);

                var pbkdf2 = new Rfc2898DeriveBytes(inputPassword, salt, 10000);
                byte[] hash = pbkdf2.GetBytes(20);

                for (int i = 0; i < 20; i++)
                {
                    if (hashBytes[i + 16] != hash[i])
                        return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        public string GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Role, user.Role),
                    new Claim("uuid", user.uuid.ToString()),
                    new Claim("email", user.Email)
                }),
                Expires = DateTime.UtcNow.AddHours(_config.JwtExpiryHours),
                SigningCredentials = new SigningCredentials(_jwtKey, SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _jwtKey,
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }

        public bool ValidateJwtToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = _jwtKey,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                return true;
            }
            catch
            {
                return false;
            }
        }

        public string GetRoleFromToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _jwtKey,
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            }, out _);

            return principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
        }


        public async Task<bool> IsAccountLocked(string username)
        {
            if (_lockedAccounts.TryGetValue(username, out var lockTime))
            {
                if (lockTime > DateTime.UtcNow)
                {
                    return true;
                }
                else
                {
                    _lockedAccounts.TryRemove(username, out _);
                    _failedLoginAttempts.TryRemove(username, out _);
                }
            }
            return false;
        }

        public void RecordFailedLoginAttempt(string username)
        {
            var attempts = _failedLoginAttempts.AddOrUpdate(username, 1, (key, value) => value + 1);

            if (attempts >= _config.MaxFailedLoginAttempts)
            {
                var lockTime = DateTime.UtcNow.AddMinutes(_config.LockoutDurationMinutes);
                _lockedAccounts.AddOrUpdate(username, lockTime, (key, value) => lockTime);
                _logger.Log($"🔒 Account {username} locked until {lockTime}");
            }
        }

        public void ResetFailedLoginAttempts(string username)
        {
            _failedLoginAttempts.TryRemove(username, out _);
            _lockedAccounts.TryRemove(username, out _);
        }

        public string GeneratePasswordResetToken()
        {
            var tokenBytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(tokenBytes);
            return Convert.ToBase64String(tokenBytes);
        }

        public bool ValidatePasswordResetToken(User user, string token)
        {
            return user != null &&
                   !string.IsNullOrEmpty(token) &&
                   user.PasswordResetToken == token &&
                   user.PasswordResetTokenExpiry > DateTime.UtcNow;
        }

        public string GenerateResetToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber).Replace("+", "-").Replace("/", "_").TrimEnd('=');
        }
    }
}