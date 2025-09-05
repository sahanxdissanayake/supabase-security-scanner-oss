#!/bin/bash

# Supabase Security Scanner
# Tests for common RLS bypasses and data exposure vulnerabilities
# Usage: ./supabase_security_scanner.sh <SUPABASE_URL> <ANON_KEY>

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SUPABASE_URL="${1:-}"
ANON_KEY="${2:-}"
OUTPUT_DIR="./supabase_security_scan_$(date +%Y%m%d_%H%M%S)"
VERBOSE="${VERBOSE:-false}"

# Check arguments
if [[ -z "$SUPABASE_URL" || -z "$ANON_KEY" ]]; then
    echo -e "${RED}Usage: $0 <SUPABASE_URL> <ANON_KEY>${NC}"
    echo "Example: $0 https://your-project.supabase.co eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Test function
test_endpoint() {
    local endpoint="$1"
    local test_name="$2"
    local output_file="$OUTPUT_DIR/${test_name}.json"
    
    log "Testing $test_name: $endpoint"
    
    local response
    response=$(curl -s -w "\n%{http_code}" \
        -H "apikey: $ANON_KEY" \
        -H "accept: application/json" \
        "$SUPABASE_URL/rest/v1$endpoint?select=*&limit=1" 2>/dev/null || echo -e "\n000")
    
    local body=$(echo "$response" | head -n -1)
    local status=$(echo "$response" | tail -n 1)
    
    echo "$body" > "$output_file"
    
    if [[ "$status" == "200" && ${#body} -gt 2 ]]; then
        warn "VULNERABLE: $test_name returned data (status: $status, size: ${#body} bytes)"
        echo "$endpoint" >> "$OUTPUT_DIR/vulnerable_endpoints.txt"
        return 1
    else
        success "SECURE: $test_name properly blocked (status: $status)"
        return 0
    fi
}

# CSV export test
test_csv_export() {
    local endpoint="$1"
    local test_name="$2"
    local output_file="$OUTPUT_DIR/${test_name}_csv.csv"
    
    log "Testing CSV export: $test_name"
    
    local response
    response=$(curl -s -w "\n%{http_code}" \
        -H "apikey: $ANON_KEY" \
        -H "accept: text/csv" \
        "$SUPABASE_URL/rest/v1$endpoint?select=*&limit=5" 2>/dev/null || echo -e "\n000")
    
    local body=$(echo "$response" | head -n -1)
    local status=$(echo "$response" | tail -n 1)
    
    echo "$body" > "$output_file"
    
    if [[ "$status" == "200" && ${#body} -gt 10 ]]; then
        warn "VULNERABLE: CSV export allowed for $test_name (status: $status, size: ${#body} bytes)"
        echo "$endpoint" >> "$OUTPUT_DIR/vulnerable_csv_endpoints.txt"
        return 1
    else
        success "SECURE: CSV export blocked for $test_name (status: $status)"
        return 0
    fi
}

# RPC test
test_rpc() {
    local rpc_name="$1"
    local test_name="$2"
    local output_file="$OUTPUT_DIR/${test_name}_rpc.json"
    
    log "Testing RPC: $test_name"
    
    local response
    response=$(curl -s -w "\n%{http_code}" \
        -X POST \
        -H "apikey: $ANON_KEY" \
        -H "content-type: application/json" \
        -d '{}' \
        "$SUPABASE_URL/rest/v1/rpc/$rpc_name" 2>/dev/null || echo -e "\n000")
    
    local body=$(echo "$response" | head -n -1)
    local status=$(echo "$response" | tail -n 1)
    
    echo "$body" > "$output_file"
    
    if [[ "$status" == "200" && ${#body} -gt 2 ]]; then
        warn "VULNERABLE: RPC $test_name returned data (status: $status, size: ${#body} bytes)"
        echo "$rpc_name" >> "$OUTPUT_DIR/vulnerable_rpc.txt"
        return 1
    else
        success "SECURE: RPC $test_name properly protected (status: $status)"
        return 0
    fi
}

# Storage test
test_storage() {
    log "Testing storage bucket listing"
    
    local response
    response=$(curl -s -w "\n%{http_code}" \
        -H "apikey: $ANON_KEY" \
        "$SUPABASE_URL/storage/v1/bucket" 2>/dev/null || echo -e "\n000")
    
    local body=$(echo "$response" | head -n -1)
    local status=$(echo "$response" | tail -n 1)
    
    echo "$body" > "$OUTPUT_DIR/storage_buckets.json"
    
    if [[ "$status" == "200" ]]; then
        warn "VULNERABLE: Storage bucket listing allowed (status: $status)"
        echo "storage_buckets" >> "$OUTPUT_DIR/vulnerable_endpoints.txt"
        return 1
    else
        success "SECURE: Storage bucket listing blocked (status: $status)"
        return 0
    fi
}

# Auth endpoint test
test_auth() {
    log "Testing auth endpoint"
    
    local response
    response=$(curl -s -w "\n%{http_code}" \
        -H "apikey: $ANON_KEY" \
        "$SUPABASE_URL/auth/v1/user" 2>/dev/null || echo -e "\n000")
    
    local body=$(echo "$response" | head -n -1)
    local status=$(echo "$response" | tail -n 1)
    
    echo "$body" > "$OUTPUT_DIR/auth_user.json"
    
    if [[ "$status" == "200" ]]; then
        warn "VULNERABLE: Auth endpoint accessible without JWT (status: $status)"
        echo "auth_user" >> "$OUTPUT_DIR/vulnerable_endpoints.txt"
        return 1
    else
        success "SECURE: Auth endpoint requires authentication (status: $status)"
        return 0
    fi
}

# CORS test
test_cors() {
    log "Testing CORS configuration"
    
    local response
    response=$(curl -s -I \
        -X OPTIONS \
        -H "origin: https://evil.example" \
        -H "access-control-request-method: GET" \
        "$SUPABASE_URL/rest/v1/user_profiles" 2>/dev/null || echo "")
    
    echo "$response" > "$OUTPUT_DIR/cors_headers.txt"
    
    if echo "$response" | grep -q "access-control-allow-origin: \*"; then
        warn "VULNERABLE: CORS allows wildcard origin"
        echo "cors_wildcard" >> "$OUTPUT_DIR/vulnerable_endpoints.txt"
        return 1
    else
        success "SECURE: CORS properly configured"
        return 0
    fi
}

# Get OpenAPI spec to discover endpoints
discover_endpoints() {
    log "Discovering available endpoints via OpenAPI"
    
    local response
    response=$(curl -s -H "apikey: $ANON_KEY" \
        -H "accept: application/openapi+json" \
        "$SUPABASE_URL/rest/v1/" 2>/dev/null || echo "{}")
    
    echo "$response" > "$OUTPUT_DIR/openapi_spec.json"
    
    # Extract endpoint paths
    echo "$response" | jq -r '.paths | keys[]' 2>/dev/null | grep -v '^/$' > "$OUTPUT_DIR/discovered_endpoints.txt" || {
        warn "Could not parse OpenAPI spec, using default endpoints"
        cat > "$OUTPUT_DIR/discovered_endpoints.txt" << EOF
/user_profiles
/admin_users
/chat_messages
/documents
/conversations
/email_audit_logs
/storage_files
EOF
    }
}

# Generate report
generate_report() {
    local report_file="$OUTPUT_DIR/security_report.md"
    
    cat > "$report_file" << EOF
# Supabase Security Scan Report

**Scan Date**: $(date)
**Target**: $SUPABASE_URL
**Scanner Version**: 1.0

## Summary

EOF

    local vulnerable_count=0
    if [[ -f "$OUTPUT_DIR/vulnerable_endpoints.txt" ]]; then
        vulnerable_count=$(wc -l < "$OUTPUT_DIR/vulnerable_endpoints.txt")
    fi

    if [[ $vulnerable_count -gt 0 ]]; then
        echo -e "**Status**: ${RED}VULNERABLE${NC} - $vulnerable_count endpoints exposed" >> "$report_file"
        echo "## Vulnerable Endpoints" >> "$report_file"
        echo "" >> "$report_file"
        while IFS= read -r endpoint; do
            echo "- \`$endpoint\`" >> "$report_file"
        done < "$OUTPUT_DIR/vulnerable_endpoints.txt"
    else
        echo -e "**Status**: ${GREEN}SECURE${NC} - No vulnerabilities detected" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

## Recommendations

1. **Enable RLS**: Ensure Row Level Security is enabled on all tables
2. **Revoke Grants**: Remove SELECT grants from 'anon' role on sensitive tables
3. **Add Policies**: Implement least-privilege policies for all operations
4. **Review Views**: Check that views don't bypass RLS
5. **Secure RPC**: Ensure RPC functions have proper authorization
6. **CORS Configuration**: Restrict CORS origins to known domains
7. **Storage Security**: Review storage bucket policies

## Files Generated

- \`openapi_spec.json\` - Discovered API endpoints
- \`vulnerable_endpoints.txt\` - List of exposed endpoints
- \`security_report.md\` - This report
- Individual test results in JSON/CSV format

## Next Steps

1. Review vulnerable endpoints
2. Implement recommended fixes
3. Re-run this scanner to verify remediation
4. Consider regular security audits

EOF

    log "Report generated: $report_file"
}

# Main execution
main() {
    log "Starting Supabase Security Scan"
    log "Target: $SUPABASE_URL"
    log "Output Directory: $OUTPUT_DIR"
    
    # Discover endpoints
    discover_endpoints
    
    # Test common sensitive endpoints
    local vulnerable_count=0
    
    # Test discovered endpoints
    while IFS= read -r endpoint; do
        if [[ -n "$endpoint" && "$endpoint" != "/" ]]; then
            local safe_name=$(echo "$endpoint" | sed 's#^/##; s#[^a-zA-Z0-9_\-]#_#g')
            if ! test_endpoint "$endpoint" "$safe_name"; then
                ((vulnerable_count++))
            fi
            test_csv_export "$endpoint" "$safe_name"
        fi
    done < "$OUTPUT_DIR/discovered_endpoints.txt"
    
    # Test RPC functions
    test_rpc "is_admin_user" "admin_check"
    test_rpc "get_user_data" "user_data"
    
    # Test storage
    test_storage
    
    # Test auth
    test_auth
    
    # Test CORS
    test_cors
    
    # Generate report
    generate_report
    
    # Summary
    echo ""
    log "Scan completed!"
    if [[ $vulnerable_count -gt 0 ]]; then
        error "Found $vulnerable_count vulnerable endpoints"
        echo "Check $OUTPUT_DIR/vulnerable_endpoints.txt for details"
    else
        success "No vulnerabilities detected"
    fi
    echo "Full report: $OUTPUT_DIR/security_report.md"
}

# Run main function
main "$@"
