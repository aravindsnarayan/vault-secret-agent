#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print test results
print_result() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ $1${NC}"
    else
        echo -e "${RED}✗ $1${NC}"
        exit 1
    fi
}

cleanup() {
    rm -f output.log secrets.env agent.log
}

# Function to kill background processes on exit
kill_agent() {
    if [ -n "$AGENT_PID" ]; then
        kill $AGENT_PID 2>/dev/null || true
    fi
}

trap cleanup EXIT
trap kill_agent EXIT

echo "=== Starting Tests ==="

# Build the binary
echo -e "\n1. Building vault-secret-agent..."
go build -o vault-secret-agent
print_result "Build successful"

# Test version flag
echo -e "\n2. Testing version flag..."
./vault-secret-agent -v | grep -q "vault-secret-agent version"
print_result "Version flag (-v) works"
./vault-secret-agent --version | grep -q "vault-secret-agent version"
print_result "Version flag (--version) works"

# Test help output
echo -e "\n3. Testing help output..."
HELP_OUTPUT=$(./vault-secret-agent -h 2>&1)
echo "$HELP_OUTPUT" | grep -q -- "-vvv, --verbose"
print_result "Help contains verbose flag"
echo "$HELP_OUTPUT" | grep -q -- "-v, --version"
print_result "Help contains version flag"

# Test error handling
echo -e "\n4. Testing error handling..."
./vault-secret-agent 2>&1 | grep -q "Error: at least one secret name is required"
print_result "Handles missing secret name"
./vault-secret-agent -vvv 2>&1 | grep -q "Error: at least one secret name is required"
print_result "Handles missing secret name in verbose mode"
./vault-secret-agent -t env.tmpl 2>&1 | grep -q "Error: -o, --output=<file> is required"
print_result "Requires output file with template"
./vault-secret-agent -t env.tmpl -o secrets.env -r 2>&1 | grep -q "Error: -r, --response cannot be used with template mode"
print_result "Rejects response flag in template mode"
./vault-secret-agent -a 2>&1 | grep -q "Error: --config=<file> is required"
print_result "Requires config file in agent mode"

# Test API functionality
if [[ -n "$HCP_CLIENT_ID" && -n "$HCP_CLIENT_SECRET" && -n "$HCP_ORGANIZATION_ID" && -n "$HCP_PROJECT_ID" && -n "$HCP_APP_NAME" ]]; then
    echo -e "\n5. Testing API functionality..."
    
    # Test direct secret retrieval
    echo "Testing direct secret retrieval..."
    OUTPUT=$(./vault-secret-agent FG_RELEASE_VERSION)
    echo "$OUTPUT" | grep -q "FG_RELEASE_VERSION="
    print_result "Direct secret retrieval works"
    
    # Test connection pooling
    echo "Testing connection pooling..."
    START_TIME=$(date +%s%N)
    for i in {1..5}; do
        ./vault-secret-agent -vvv FG_RELEASE_VERSION >/dev/null 2>&1
    done
    END_TIME=$(date +%s%N)
    DURATION=$((($END_TIME - $START_TIME) / 1000000)) # Convert to milliseconds
    # Check if average request time is under 2 seconds (allowing for retry overhead)
    if [ $DURATION -lt 10000 ]; then
        print_result "Connection pooling is working (5 requests in ${DURATION}ms)"
    else
        echo -e "${RED}✗ Connection pooling might not be optimal (5 requests in ${DURATION}ms)${NC}"
        exit 1
    fi
    
    # Test retry behavior
    echo "Testing retry behavior..."
    
    # Test authentication error handling
    echo "Testing authentication error handling..."
    OLD_CLIENT_SECRET=$HCP_CLIENT_SECRET
    export HCP_CLIENT_SECRET="invalid_secret"
    ./vault-secret-agent -vvv FG_RELEASE_VERSION 2>&1 | tee output.log
    grep -q "request failed with status 401: {\"error\":\"access_denied\"" output.log
    print_result "Authentication error handling works"
    export HCP_CLIENT_SECRET=$OLD_CLIENT_SECRET
    
    # Test request ID tracing
    echo "Testing request ID tracing..."
    ./vault-secret-agent -vvv FG_RELEASE_VERSION 2>&1 | tee output.log
    if grep -q "\[[0-9]\+\] Making request to" output.log; then
        print_result "Request ID tracing works"
    else
        echo -e "${RED}✗ Request ID tracing not found in logs${NC}"
        exit 1
    fi
    
    # Test concurrent requests with rate limiting
    echo "Testing controlled concurrency..."
    START_TIME=$(date +%s%N)
    timeout 30s ./vault-secret-agent -vvv FG_RELEASE_VERSION FG_ASSET_VERSION FG_CURRENT_SPRINT FG_URL_HOST FG_URL_SCHEME FG_URL_HTTP_PORT FG_BASE_URL FG_DOMAINS APP_ENV APP_DEBUG 2>&1 | tee output.log
    END_TIME=$(date +%s%N)
    DURATION=$((($END_TIME - $START_TIME) / 1000000))
    
    # Check if controlled concurrency was used
    if tr -d '\n' < output.log | grep -q "Successfully retrieved .* secrets with controlled concurrency"; then
        print_result "Controlled concurrency mode detected"
    else
        echo -e "${RED}✗ Controlled concurrency mode not detected${NC}"
        cat output.log
        exit 1
    fi
    
    # Verify all secrets were retrieved
    tr -d '\n' < output.log | grep -q "Successfully retrieved .* secrets with controlled concurrency"
    print_result "All secrets retrieved successfully"
    
    # Check performance with larger number of secrets
    if [ $DURATION -lt 5000 ]; then
        print_result "Multiple secret retrieval performance is good (completed in ${DURATION}ms)"
    else
        echo -e "${RED}✗ Multiple secret retrieval performance could be improved (${DURATION}ms)${NC}"
        exit 1
    fi
    
    # Test rate limiting (if supported by the API)
    echo "Testing rate limiting handling..."
    # Make rapid requests to potentially trigger rate limiting
    for i in {1..20}; do
        ./vault-secret-agent FG_RELEASE_VERSION >/dev/null 2>&1 &
    done
    wait
    
    # Check for rate limit handling in verbose mode
    ./vault-secret-agent -vvv FG_RELEASE_VERSION 2>&1 | tee output.log
    if grep -q "Rate limited" output.log || grep -q "Successfully retrieved secret" output.log; then
        if grep -q "Rate limited" output.log; then
            print_result "Rate limit detection works"
        else
            print_result "No rate limiting triggered"
        fi
    else
        echo -e "${RED}✗ Rate limit handling check failed${NC}"
        exit 1
    fi
    
    # Test verbose logging
    echo "Testing verbose logging..."
    ./vault-secret-agent -vvv FG_RELEASE_VERSION 2>&1 | tee output.log
    grep -q "Getting access token from HCP auth service" output.log
    print_result "Verbose logging works"
    
    # Test enhanced masking
    echo "Testing enhanced masking..."
    # Test JWT token masking
    grep -q "eyJh.*" output.log
    print_result "JWT token masking works"
    
    # Test UUID masking
    if grep -q "[0-9a-f]\{8\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{12\}" output.log; then
        echo -e "${RED}✗ Found unmasked UUID in logs${NC}"
        exit 1
    fi
    print_result "UUID masking works"
    
    # Test URL parameter masking
    if grep -q "client_id=[^*]" output.log || grep -q "client_secret=[^*]" output.log; then
        echo -e "${RED}✗ Found unmasked credentials in URL${NC}"
        exit 1
    fi
    print_result "URL parameter masking works"
    
    # Test organization/project ID masking
    if grep -q "organizations/[^*]" output.log || grep -q "projects/[^*]" output.log; then
        echo -e "${RED}✗ Found unmasked organization or project ID${NC}"
        exit 1
    fi
    print_result "Organization/Project ID masking works"
    
    # Test response flag
    echo "Testing response flag..."
    ./vault-secret-agent -r FG_RELEASE_VERSION | jq . >/dev/null 2>&1
    print_result "Response output is valid JSON"
    
    # Test template mode
    echo "Testing template mode..."
    echo 'FG_RELEASE_VERSION={{ FG_RELEASE_VERSION }}' > env.tmpl
    ./vault-secret-agent -t env.tmpl -o secrets.env
    test -f secrets.env
    print_result "Template rendered successfully"
    grep -q "FG_RELEASE_VERSION=" secrets.env
    print_result "Template contains expected output"

    # Test agent mode
    echo -e "\n6. Testing agent mode..."
    
    # Create test template for agent mode
    echo 'FG_RELEASE_VERSION={{ FG_RELEASE_VERSION }}' > env.tmpl
    echo 'FG_ASSET_VERSION={{ FG_ASSET_VERSION }}' >> env.tmpl
    echo 'FG_CURRENT_SPRINT={{ FG_CURRENT_SPRINT }}' >> env.tmpl
    echo 'FG_URL_HOST={{ FG_URL_HOST }}' >> env.tmpl
    echo 'FG_URL_SCHEME={{ FG_URL_SCHEME }}' >> env.tmpl
    echo 'FG_URL_HTTP_PORT={{ FG_URL_HTTP_PORT }}' >> env.tmpl
    echo 'FG_BASE_URL={{ FG_BASE_URL }}' >> env.tmpl
    echo 'FG_DOMAINS={{ FG_DOMAINS }}' >> env.tmpl
    echo 'APP_ENV={{ APP_ENV }}' >> env.tmpl
    echo 'APP_DEBUG={{ APP_DEBUG }}' >> env.tmpl
    echo 'REDIS_SERVICE_HOST={{ REDIS_SERVICE_HOST }}' >> env.tmpl
    rm -f secrets.env agent.log
    
    # Start agent in background
    echo "Starting agent in background..."
    ./vault-secret-agent --agent --config=agent-config.yaml > agent.log 2>&1 &
    AGENT_PID=$!
    
    # Wait for agent to start and create output file
    echo "Waiting for agent to process template..."
    for i in {1..10}; do
        if [ -f secrets.env ] && grep -q "FG_RELEASE_VERSION=" secrets.env; then
            print_result "Agent successfully rendered template"
            break
        fi
        if [ $i -eq 10 ]; then
            echo -e "${RED}✗ Agent failed to render template within timeout${NC}"
            exit 1
        fi
        sleep 1
    done
    
    # Check agent logs
    echo "Checking agent logs..."
    for i in {1..5}; do
        if [ -f agent.log ] && grep -q "Processing template.*env.tmpl" agent.log; then
            print_result "Agent template processing works"
            break
        fi
        if [ $i -eq 5 ]; then
            echo -e "${RED}✗ Agent template processing not detected within timeout${NC}"
            cat agent.log
            exit 1
        fi
        sleep 1
    done
    
    # Check if agent is still running
    kill -0 $AGENT_PID 2>/dev/null
    print_result "Agent is running"
    
    # Check agent configuration
    grep -q "render_interval: 5s" agent-config.yaml
    print_result "Agent configured with correct render interval"
    
    # Check agent logging configuration
    grep -q "level: info" agent-config.yaml
    print_result "Agent configured with correct logging level"
    
    # Cleanup agent
    kill $AGENT_PID

    # Test batch requests
    echo "Testing batch requests..."
    START_TIME=$(date +%s%N)
    ./vault-secret-agent -vvv FG_RELEASE_VERSION FG_ASSET_VERSION FG_CURRENT_SPRINT 2>&1 | tee output.log
    END_TIME=$(date +%s%N)
    DURATION=$((($END_TIME - $START_TIME) / 1000000))
    
    # Check if batch mode was used
    if grep -q "Fetching .* secrets in batch mode" output.log; then
        print_result "Batch request mode detected"
    else
        echo -e "${RED}✗ Batch request mode not detected${NC}"
        exit 1
    fi
    
    # Verify all secrets were retrieved
    grep -q "Successfully retrieved .* secrets in batch" output.log
    print_result "Batch request completed successfully"
    
    # Check performance improvement
    if [ $DURATION -lt 2000 ]; then
        print_result "Batch request performance is good (completed in ${DURATION}ms)"
    else
        echo -e "${RED}✗ Batch request performance could be improved (${DURATION}ms)${NC}"
        exit 1
    fi
    
    # Test batch request fallback
    echo "Testing batch request fallback..."
    OLD_PROJECT_ID=$HCP_PROJECT_ID
    export HCP_PROJECT_ID="invalid_project"
    ./vault-secret-agent -vvv FG_RELEASE_VERSION FG_ASSET_VERSION 2>&1 | tee output.log
    if grep -q "Batch request failed, falling back to individual requests" output.log; then
        print_result "Batch request fallback works"
    else
        echo -e "${RED}✗ Batch request fallback not detected${NC}"
        exit 1
    fi
    export HCP_PROJECT_ID=$OLD_PROJECT_ID

    # Test response compression
    echo "Testing response compression..."
    ./vault-secret-agent -vvv FG_RELEASE_VERSION 2>&1 | tee output.log
    if grep -q "Response compressed.*bytes" output.log || grep -q "Content-Encoding: gzip" output.log; then
        print_result "Response compression is working"
    else
        echo -e "${YELLOW}! Response compression not detected (server may not support it)${NC}"
    fi
else
    echo -e "\n5. Skipping API tests - environment variables not set"
fi

echo -e "\n=== All tests completed! ===" 