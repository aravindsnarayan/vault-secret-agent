#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
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
    
    # Test verbose logging
    echo "Testing verbose logging..."
    ./vault-secret-agent -vvv FG_RELEASE_VERSION 2>&1 | tee output.log
    grep -q "Getting access token from HCP auth service" output.log
    print_result "Verbose logging works"
    
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
        if [ -f agent.log ] && grep -q "Found 1 variables in template" agent.log; then
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
    grep -q "level: debug" agent-config.yaml
    print_result "Agent configured with debug logging"
    
    # Cleanup agent
    kill $AGENT_PID
else
    echo -e "\n5. Skipping API tests - environment variables not set"
fi

echo -e "\n=== All tests completed! ===" 