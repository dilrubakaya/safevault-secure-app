// SafeVault Security Tests
// Tests for Input Validation, Auth/RBAC, and Vulnerability Fixes

using System;
using SafeVault.Security;
using SafeVault.Auth;

namespace SafeVault.Tests
{
    class Program
    {
        static int _passed = 0;
        static int _failed = 0;

        static void Main()
        {
            Console.WriteLine("╔══════════════════════════════════════════╗");
            Console.WriteLine("║     SafeVault Security Test Suite        ║");
            Console.WriteLine("╚══════════════════════════════════════════╝\n");

            RunInputValidationTests();
            RunPasswordHasherTests();
            RunSanitizationTests();
            RunRbacTests();

            Console.WriteLine("\n══════════════════════════════════════════");
            Console.WriteLine($"  Results: {_passed} passed, {_failed} failed");
            Console.WriteLine("══════════════════════════════════════════");
        }

        // ─── Input Validation Tests ───────────────────────────────────────────
        static void RunInputValidationTests()
        {
            Console.WriteLine("── Input Validation Tests ──────────────────");

            Assert("Valid username 'john_doe'",
                InputValidator.IsValidUsername("john_doe"));

            Assert("Reject empty username",
                !InputValidator.IsValidUsername(""));

            Assert("Reject SQL injection username: ' OR 1=1--",
                !InputValidator.IsValidUsername("' OR 1=1--"));

            Assert("Reject username with special chars: admin<script>",
                !InputValidator.IsValidUsername("admin<script>"));

            Assert("Reject too-short username: 'ab'",
                !InputValidator.IsValidUsername("ab"));

            Assert("Valid email: user@example.com",
                InputValidator.IsValidEmail("user@example.com"));

            Assert("Reject invalid email: notanemail",
                !InputValidator.IsValidEmail("notanemail"));

            Assert("Valid strong password",
                InputValidator.IsValidPassword("Secure@123"));

            Assert("Reject weak password: 'password'",
                !InputValidator.IsValidPassword("password"));

            Assert("Reject short password: 'Ab1!'",
                !InputValidator.IsValidPassword("Ab1!"));
        }

        // ─── Password Hasher Tests ────────────────────────────────────────────
        static void RunPasswordHasherTests()
        {
            Console.WriteLine("\n── Password Hasher Tests ───────────────────");

            string password = "Secure@123";
            string hash1    = PasswordHasher.Hash(password);
            string hash2    = PasswordHasher.Hash(password);

            Assert("Hash is not plain text",
                hash1 != password);

            Assert("Same password produces different hashes (salted)",
                hash1 != hash2);

            Assert("Correct password verifies successfully",
                PasswordHasher.Verify(password, hash1));

            Assert("Wrong password fails verification",
                !PasswordHasher.Verify("WrongPassword!", hash1));

            Assert("Hash is base64 string",
                IsBase64(hash1));
        }

        // ─── XSS Sanitization Tests ───────────────────────────────────────────
        static void RunSanitizationTests()
        {
            Console.WriteLine("\n── XSS Sanitization Tests ──────────────────");

            string xssInput  = "<script>alert('xss')</script>";
            string sanitized = InputValidator.SanitizeInput(xssInput);

            Assert("Script tags are encoded",
                !sanitized.Contains("<script>") && sanitized.Contains("&lt;script&gt;"));

            Assert("Ampersand is encoded",
                InputValidator.SanitizeInput("a&b").Contains("&amp;"));

            Assert("Quotes are encoded",
                InputValidator.SanitizeInput("say \"hello\"").Contains("&quot;"));

            Assert("Single quotes are encoded",
                InputValidator.SanitizeInput("it's").Contains("&#x27;"));

            Assert("Empty input returns empty string",
                InputValidator.SanitizeInput("") == string.Empty);

            Assert("Normal text is unchanged",
                InputValidator.SanitizeInput("Hello World") == "Hello World");
        }

        // ─── RBAC Tests ───────────────────────────────────────────────────────
        static void RunRbacTests()
        {
            Console.WriteLine("\n── RBAC Permission Tests ───────────────────");

            Assert("Admin can read",
                RbacPolicy.HasPermission(UserRole.Admin, "read"));

            Assert("Admin can manage_users",
                RbacPolicy.HasPermission(UserRole.Admin, "manage_users"));

            Assert("Editor can write",
                RbacPolicy.HasPermission(UserRole.Editor, "write"));

            Assert("Editor cannot manage_users",
                !RbacPolicy.HasPermission(UserRole.Editor, "manage_users"));

            Assert("Editor cannot delete",
                !RbacPolicy.HasPermission(UserRole.Editor, "delete"));

            Assert("Viewer can read",
                RbacPolicy.HasPermission(UserRole.Viewer, "read"));

            Assert("Viewer cannot write",
                !RbacPolicy.HasPermission(UserRole.Viewer, "write"));

            Assert("Viewer cannot delete",
                !RbacPolicy.HasPermission(UserRole.Viewer, "delete"));
        }

        // ─── Helpers ──────────────────────────────────────────────────────────
        static void Assert(string testName, bool condition)
        {
            if (condition)
            {
                Console.WriteLine($"  ✅ PASS: {testName}");
                _passed++;
            }
            else
            {
                Console.WriteLine($"  ❌ FAIL: {testName}");
                _failed++;
            }
        }

        static bool IsBase64(string s)
        {
            try { Convert.FromBase64String(s); return true; }
            catch { return false; }
        }
    }
}
