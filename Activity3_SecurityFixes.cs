// Activity 3: Debugging & Resolving Security Vulnerabilities
// SafeVault Application

using System;
using System.Text.RegularExpressions;
using SafeVault.Security;

namespace SafeVault.Debugging
{
    // ════════════════════════════════════════════════════════════════════════════
    // VULNERABILITY 1: SQL INJECTION
    // ════════════════════════════════════════════════════════════════════════════

    public class SqlInjectionFix
    {
        // ❌ VULNERABLE (before fix)
        // public string GetUser_Vulnerable(string username)
        // {
        //     string query = "SELECT * FROM Users WHERE Username = '" + username + "'";
        //     // Attack: username = "' OR '1'='1" → returns all users
        //     // Attack: username = "'; DROP TABLE Users;--" → deletes table
        // }

        // ✅ FIXED: Parameterized query
        public void GetUser_Fixed(System.Data.SqlClient.SqlConnection conn, string username)
        {
            const string query = "SELECT * FROM Users WHERE Username = @Username";
            using var cmd = new System.Data.SqlClient.SqlCommand(query, conn);
            cmd.Parameters.AddWithValue("@Username", username);
            // User input is treated as DATA, never as SQL code
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // VULNERABILITY 2: CROSS-SITE SCRIPTING (XSS)
    // ════════════════════════════════════════════════════════════════════════════

    public class XssFix
    {
        // ❌ VULNERABLE (before fix)
        // public string RenderComment_Vulnerable(string userComment)
        // {
        //     return "<div>" + userComment + "</div>";
        //     // Attack: userComment = "<script>document.cookie</script>"
        // }

        // ✅ FIXED: Encode output before rendering
        public string RenderComment_Fixed(string userComment)
        {
            string safeComment = InputValidator.SanitizeInput(userComment);
            return $"<div>{safeComment}</div>";
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // VULNERABILITY 3: INSECURE PASSWORD STORAGE
    // ════════════════════════════════════════════════════════════════════════════

    public class PasswordStorageFix
    {
        // ❌ VULNERABLE (before fix)
        // public void SavePassword_Vulnerable(string password)
        // {
        //     database.Save(password);           // Plain text — catastrophic breach risk
        //     database.Save(MD5Hash(password));  // MD5 is broken and reversible
        // }

        // ✅ FIXED: PBKDF2 with salt (see Activity 2 PasswordHasher)
        public string SavePassword_Fixed(string password)
        {
            return SafeVault.Auth.PasswordHasher.Hash(password);
            // Stored value is salted hash — cannot be reversed
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // VULNERABILITY 4: MISSING INPUT VALIDATION
    // ════════════════════════════════════════════════════════════════════════════

    public class InputValidationFix
    {
        // ❌ VULNERABLE (before fix)
        // public void Register_Vulnerable(string username, string email)
        // {
        //     database.Insert(username, email);  // No validation at all
        // }

        // ✅ FIXED: Validate before processing
        public void Register_Fixed(string username, string email, string password)
        {
            if (!InputValidator.IsValidUsername(username))
                throw new ArgumentException("Username must be 3-50 alphanumeric characters.");

            if (!InputValidator.IsValidEmail(email))
                throw new ArgumentException("Invalid email format.");

            if (!InputValidator.IsValidPassword(password))
                throw new ArgumentException(
                    "Password must be 8+ chars with uppercase, lowercase, digit, and special character.");

            // Safe to proceed
            string hash = SafeVault.Auth.PasswordHasher.Hash(password);
            Console.WriteLine($"User '{username}' registered securely.");
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // VULNERABILITY 5: BROKEN ACCESS CONTROL
    // ════════════════════════════════════════════════════════════════════════════

    public class AccessControlFix
    {
        // ❌ VULNERABLE (before fix)
        // public void DeleteUser_Vulnerable(int targetUserId)
        // {
        //     database.Delete(targetUserId);  // No role check!
        // }

        // ✅ FIXED: Check permission before action
        public void DeleteUser_Fixed(System.Security.Claims.ClaimsPrincipal currentUser, int targetUserId)
        {
            SafeVault.Auth.RbacPolicy.Authorize(currentUser, "manage_users");
            // Only reaches here if user has Admin role
            Console.WriteLine($"User {targetUserId} deleted by authorized admin.");
        }
    }
}
