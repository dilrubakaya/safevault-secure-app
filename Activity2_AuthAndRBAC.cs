// Activity 2: Authentication & Authorization with RBAC
// SafeVault Application

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace SafeVault.Auth
{
    // ─── Password Hashing ────────────────────────────────────────────────────────
    public static class PasswordHasher
    {
        private const int SaltSize   = 16;
        private const int HashSize   = 32;
        private const int Iterations = 100_000;

        // ✅ Hash password using PBKDF2 + random salt
        public static string Hash(string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);

            using var pbkdf2 = new Rfc2898DeriveBytes(
                password, salt, Iterations, HashAlgorithmName.SHA256);

            byte[] hash   = pbkdf2.GetBytes(HashSize);
            byte[] result = new byte[SaltSize + HashSize];
            Buffer.BlockCopy(salt, 0, result, 0,        SaltSize);
            Buffer.BlockCopy(hash, 0, result, SaltSize, HashSize);

            return Convert.ToBase64String(result);
        }

        // ✅ Verify password against stored hash
        public static bool Verify(string password, string storedHash)
        {
            byte[] hashBytes = Convert.FromBase64String(storedHash);
            byte[] salt      = new byte[SaltSize];
            Buffer.BlockCopy(hashBytes, 0, salt, 0, SaltSize);

            using var pbkdf2 = new Rfc2898DeriveBytes(
                password, salt, Iterations, HashAlgorithmName.SHA256);

            byte[] hash = pbkdf2.GetBytes(HashSize);

            // ✅ Constant-time comparison prevents timing attacks
            return CryptographicOperations.FixedTimeEquals(
                hash,
                hashBytes[SaltSize..]);
        }
    }

    // ─── JWT Service ─────────────────────────────────────────────────────────────
    public class JwtService
    {
        private readonly string _secretKey;
        private readonly string _issuer;
        private readonly string _audience;
        private readonly int    _expiryMinutes;

        public JwtService(string secretKey, string issuer, string audience, int expiryMinutes = 60)
        {
            _secretKey     = secretKey;
            _issuer        = issuer;
            _audience      = audience;
            _expiryMinutes = expiryMinutes;
        }

        // ✅ Generate a signed JWT with role claim
        public string GenerateToken(int userId, string username, string role)
        {
            var key   = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, username),
                new Claim(ClaimTypes.Role, role),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer:             _issuer,
                audience:           _audience,
                claims:             claims,
                expires:            DateTime.UtcNow.AddMinutes(_expiryMinutes),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // ✅ Validate token and return principal
        public ClaimsPrincipal ValidateToken(string token)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));

            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey         = key,
                ValidateIssuer           = true,
                ValidIssuer              = _issuer,
                ValidateAudience         = true,
                ValidAudience            = _audience,
                ValidateLifetime         = true,
                ClockSkew                = TimeSpan.Zero   // No tolerance for expired tokens
            };

            return new JwtSecurityTokenHandler()
                .ValidateToken(token, parameters, out _);
        }
    }

    // ─── Role-Based Access Control (RBAC) ────────────────────────────────────────
    public enum UserRole { Admin, Editor, Viewer }

    public static class RbacPolicy
    {
        // Permissions per role
        private static readonly Dictionary<UserRole, HashSet<string>> _permissions = new()
        {
            [UserRole.Admin]  = new() { "read", "write", "delete", "manage_users" },
            [UserRole.Editor] = new() { "read", "write" },
            [UserRole.Viewer] = new() { "read" }
        };

        // ✅ Check if a role has a specific permission
        public static bool HasPermission(UserRole role, string permission)
            => _permissions.TryGetValue(role, out var perms) && perms.Contains(permission);

        // ✅ Authorize action — throws if unauthorized
        public static void Authorize(ClaimsPrincipal user, string requiredPermission)
        {
            var roleClaim = user.FindFirst(ClaimTypes.Role)?.Value;
            if (!Enum.TryParse(roleClaim, out UserRole role))
                throw new UnauthorizedAccessException("Invalid role.");

            if (!HasPermission(role, requiredPermission))
                throw new UnauthorizedAccessException(
                    $"Role '{role}' does not have '{requiredPermission}' permission.");
        }
    }

    // ─── Auth Service ─────────────────────────────────────────────────────────────
    public class AuthService
    {
        private readonly JwtService _jwtService;

        public AuthService(JwtService jwtService)
        {
            _jwtService = jwtService;
        }

        // ✅ Login: verify credentials, return JWT
        public string Login(string username, string storedHash, string password, int userId, string role)
        {
            if (!PasswordHasher.Verify(password, storedHash))
                throw new UnauthorizedAccessException("Invalid credentials.");

            return _jwtService.GenerateToken(userId, username, role);
        }
    }
}
