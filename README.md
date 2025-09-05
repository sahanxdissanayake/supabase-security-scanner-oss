# 🔍 Supabase Security Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/Shell-Bash-blue.svg)](https://www.gnu.org/software/bash/)
[![Security](https://img.shields.io/badge/Security-Scanner-red.svg)](https://github.com/sahanxdissanayake/supabase-security-scanner-oss)

A comprehensive security scanner for Supabase instances that automatically detects common vulnerabilities and misconfigurations. This tool helps developers and security researchers identify critical security gaps before they become data breaches.

## Why This Matters

Many Supabase developers don't realize that tables are **publicly accessible by default** unless Row Level Security (RLS) is properly configured. This scanner helps identify these critical security gaps that could lead to:

- **Data breaches** - Unauthorized access to sensitive information
- **Privacy violations** - Exposure of user data
- **Compliance issues** - GDPR, SOC2, HIPAA violations
- **Reputation damage** - Loss of user trust

## 🚀 Quick Start

```bash
# Clone the repository
git clone git@github.com:sahanxdissanayake/supabase-security-scanner-oss.git
cd supabase-security-scanner-oss

# or using HTTPS
git clone https://github.com/sahanxdissanayake/supabase-security-scanner-oss.git
cd supabase-security-scanner-oss

# Make executable
chmod +x supabase_security_scanner.sh

# Run scan
./supabase_security_scanner.sh <SUPABASE_URL> <ANON_KEY>
```

### Example

```bash
./supabase_security_scanner.sh https://your-project.supabase.co eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## ✅ Prerequisites

- bash (>= 4)
- curl
- jq

Install jq on macOS: `brew install jq`

## 🧩 Usage

```bash
./supabase_security_scanner.sh --help
```

The script also supports environment variables:

```bash
export SUPABASE_URL="https://your-project.supabase.co"
export SUPABASE_ANON_KEY="eyJhbGciOiJIUzI1NiIs..."
./supabase_security_scanner.sh
```

## 📊 What It Checks

### **REST API Security**

- **Anonymous data exposure** - Tables accessible without authentication
- **RLS bypasses** - Row Level Security misconfigurations
- **CSV export vulnerabilities** - Unauthorized data downloads
- **JSON data exposure** - Sensitive information in API responses

### **RPC Function Security**

- **Public function calls** - Database functions accessible anonymously
- **Parameter injection** - SQL injection vulnerabilities
- **Function permissions** - Improper access controls

### **Storage Security**

- **Bucket access** - File storage permissions
- **Public file exposure** - Unprotected file access
- **Upload vulnerabilities** - File upload security

### **CORS Configuration**

- **Overly permissive policies** - Wildcard origins
- **Missing security headers** - CORS misconfigurations

### **Authentication Bypass**

- **JWT token validation** - Token security issues
- **Session management** - Authentication bypasses

## Security Features

- **Non-destructive** - Read-only operations only
- **Rate limited** - Respects API rate limits
- **Detailed reporting** - Clear vulnerability descriptions
- **Remediation guidance** - Step-by-step fixes
- **Multiple formats** - JSON, CSV, and human-readable output
- **Safe scanning** - No data modification or deletion

## 🧾 Sample Output

```
[WARNING] VULNERABLE: public.users returned data (status: 200, size: 123 bytes)
[SUCCESS] SECURE: CSV export blocked for user_profiles (status: 401)
Summary: 3 high, 2 medium, 0 low
Report: ./supabase_security_scan_YYYYMMDD_HHMMSS/security_report.md
```

## ⚠️ Ethical Use

Run this scanner only against projects you own or have explicit permission to assess.

## 🛠️ Troubleshooting

- Missing jq: install via `brew install jq` (macOS) or your package manager
- 401/403 errors: verify `ANON_KEY` and that the `SUPABASE_URL` is correct
- Empty results: ensure the project exposes REST via PostgREST and tables exist

## 🤝 Contributing

Contributions are welcome! Please open an issue or pull request.
