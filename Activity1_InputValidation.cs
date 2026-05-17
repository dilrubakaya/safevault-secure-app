// Activity 1: Secure Code - Input Validation & SQL Injection Prevention
// SafeVault Application

using System;
using System.Data.SqlClient;
using System.Text.RegularExpressions;

namespace SafeVault.Security
{
    public class InputValidator
    {
        // ✅ Validates that username contains only safe characters
        public static bool IsValidUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username)) return false;
            if (username.Length < 3 || username.Length > 50) return false;

            // Only allow alphanumeric characters and underscores
            return Regex.IsMatch(username, @"^[a-zA-Z0-9_]+$");
        }

        // ✅ Validates email format
        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) return false;
            return Regex.IsMatch(email,
                @"^[^@\s]+@[^@\s]+\.[^@\s]+$",
                RegexOptions.IgnoreCase);
        }

        // ✅ Validates password strength
        public static bool IsValidPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password)) return false;
            if (password.Length < 8) return false;

            bool hasUpper   = Regex.IsMatch(password, @"[A-Z]");
            bool hasLower   = Regex.IsMatch(password, @"[a-z]");
            bool hasDigit   = Regex.IsMatch(password, @"[0-9]");
            bool hasSpecial = Regex.IsMatch(password, @"[!@#$%^&*(),.?"":{}|<>]");

            return hasUpper && hasLower && hasDigit && hasSpecial;
        }

        // ✅ Sanitizes input to prevent XSS
        public static string SanitizeInput(string input)
        {
            if (string.IsNullOrEmpty(input)) return string.Empty;

            return input
                .Replace("&",  "&amp;")
                .Replace("<",  "&lt;")
                .Replace(">",  "&gt;")
                .Replace("\"", "&quot;")
                .Replace("'",  "&#x27;");
        }
    }

    public class UserRepository
    {
        private readonly string _connectionString;

        public UserRepository(string connectionString)
        {
            _connectionString = connectionString;
        }

        // ✅ SECURE: Uses parameterized query - prevents SQL Injection
        public User GetUserByUsername(string username)
        {
            if (!InputValidator.IsValidUsername(username))
                throw new ArgumentException("Invalid username format.");

            const string query = "SELECT Id, Username, Email, Role FROM Users WHERE Username = @Username";

            using var connection = new SqlConnection(_connectionString);
            using var command    = new SqlCommand(query, connection);

            // Parameterized query: user input NEVER concatenated into SQL
            command.Parameters.AddWithValue("@Username", username);

            connection.Open();
            using var reader = command.ExecuteReader();

            if (!reader.Read()) return null;

            return new User
            {
                Id       = reader.GetInt32(0),
                Username = reader.GetString(1),
                Email    = reader.GetString(2),
                Role     = reader.GetString(3)
            };
        }

        // ✅ SECURE: Parameterized INSERT
        public void CreateUser(string username, string email, string passwordHash)
        {
            if (!InputValidator.IsValidUsername(username))
                throw new ArgumentException("Invalid username.");
            if (!InputValidator.IsValidEmail(email))
                throw new ArgumentException("Invalid email.");

            const string query = @"
                INSERT INTO Users (Username, Email, PasswordHash, CreatedAt)
                VALUES (@Username, @Email, @PasswordHash, @CreatedAt)";

            using var connection = new SqlConnection(_connectionString);
            using var command    = new SqlCommand(query, connection);

            command.Parameters.AddWithValue("@Username",     username);
            command.Parameters.AddWithValue("@Email",        email);
            command.Parameters.AddWithValue("@PasswordHash", passwordHash);
            command.Parameters.AddWithValue("@CreatedAt",    DateTime.UtcNow);

            connection.Open();
            command.ExecuteNonQuery();
        }

        // ❌ INSECURE EXAMPLE (for comparison only - never use this!)
        // public User GetUserUnsafe(string username)
        // {
        //     string query = "SELECT * FROM Users WHERE Username = '" + username + "'";
        //     // SQL Injection vulnerability! An attacker could input: ' OR '1'='1
        // }
    }

    public class User
    {
        public int    Id       { get; set; }
        public string Username { get; set; }
        public string Email    { get; set; }
        public string Role     { get; set; }
    }
}
