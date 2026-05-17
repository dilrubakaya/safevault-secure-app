# SafeVault – Secure Application Project

A secure ASP.NET application demonstrating input validation, SQL injection prevention, authentication, authorization (RBAC), and security vulnerability fixes.

---

## Project Structure

| File | Activity | Description |
|------|----------|-------------|
| `Activity1_InputValidation.cs` | Activity 1 | Input validation & SQL injection prevention |
| `Activity2_AuthAndRBAC.cs` | Activity 2 | Authentication, JWT, and RBAC |
| `Activity3_SecurityFixes.cs` | Activity 3 | Debugging & resolving vulnerabilities |
| `SafeVault.Tests.cs` | All | Security test suite |

---

## Activity 1: Input Validation & SQL Injection Prevention

### Vulnerabilities Identified
- **SQL Injection**: User input was concatenated directly into SQL queries, allowing attackers to manipulate the query (e.g., `' OR '1'='1`).
- **Missing Input Validation**: No checks on username/email/password format.

### Fixes Applied
- **Parameterized Queries**: All SQL commands use `@Parameter` syntax — user input is treated as data, never as SQL code.
- **Input Validation**: Regex-based validation for username, email, and password strength.
- **XSS Sanitization**: HTML-encoding of user input before rendering (`<` → `&lt;`, etc.).

### How Copilot Assisted
Copilot generated the parameterized query pattern and suggested the regex validation rules for email and username formats. It also recommended the `SanitizeInput` method for XSS prevention.

---

## Activity 2: Authentication & Authorization (RBAC)

### Implementation
- **Password Hashing**: PBKDF2 with SHA-256 and random 16-byte salt (100,000 iterations).
- **JWT Tokens**: Signed with HMAC-SHA256, includes `sub`, `username`, and `role` claims.
- **Token Validation**: Validates signature, issuer, audience, and expiration on every request.
- **RBAC**: Three roles with distinct permissions:

| Role | Permissions |
|------|------------|
| Admin | read, write, delete, manage_users |
| Editor | read, write |
| Viewer | read |

### How Copilot Assisted
Copilot generated the `JwtService` class with proper `TokenValidationParameters`, suggested PBKDF2 over MD5/SHA1 for password hashing, and recommended constant-time comparison (`CryptographicOperations.FixedTimeEquals`) to prevent timing attacks.

---

## Activity 3: Debugging & Resolving Security Vulnerabilities

### Vulnerabilities Found & Fixed

| # | Vulnerability | Before (Broken) | After (Fixed) |
|---|--------------|-----------------|---------------|
| 1 | SQL Injection | String concatenation in queries | Parameterized queries |
| 2 | XSS | Raw user input rendered in HTML | HTML-encoded output |
| 3 | Insecure Passwords | Plain text / MD5 storage | PBKDF2 + salt |
| 4 | Missing Validation | No input checks | Regex validation on all inputs |
| 5 | Broken Access Control | No role check before actions | RBAC policy enforcement |

### How Copilot Assisted
Copilot identified the vulnerable patterns during code review, suggested the specific fixes for each vulnerability, and generated the before/after comparison comments for documentation.

---

## Security Test Results

Running `SafeVault.Tests.cs` covers:
- ✅ Input validation (valid/invalid usernames, emails, passwords)
- ✅ SQL injection attempt rejection
- ✅ XSS sanitization
- ✅ Password hashing (salted, non-reversible, constant-time verify)
- ✅ RBAC permission enforcement per role

---

## Security Best Practices Applied

- Parameterized queries (no string concatenation in SQL)
- PBKDF2 password hashing with random salt
- JWT with short expiry + signature validation
- Role-based access control (least privilege)
- Input validation on all user-supplied data
- Output encoding to prevent XSS
- Secrets stored in environment variables (not source code)
