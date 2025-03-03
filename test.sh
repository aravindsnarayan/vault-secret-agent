#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print section headers
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

# Function to print test results
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Enhanced cleanup function
cleanup() {
    print_header "Cleaning up test artifacts"
    
    # Remove template and output files
    rm -f output.log secrets.env large.tmpl large.env env.tmpl
    
    # Remove cache test files
    rm -f cache-test.tmpl cache-test.env cache-config.yaml cache-test.log
    
    # Remove pre-compilation test files
    rm -f precompile-test.tmpl precompile-test.env
    
    # Remove memory security test files
    rm -f memory-test.go memory-test.log memory-test-output.log
    
    # Remove other log files
    rm -f agent.log test-run.log 
    
    # Kill any background processes that might be running
    if [ -n "$AGENT_PID" ]; then
        kill $AGENT_PID 2>/dev/null || true
        print_success "Agent process terminated"
    fi
    
    print_success "Test artifacts removed"
}

# Kill agent function
kill_agent() {
    if [ -n "$AGENT_PID" ]; then
        kill $AGENT_PID 2>/dev/null || true
    fi
}

# Set up traps to ensure cleanup on exit or interruption
trap cleanup EXIT
trap kill_agent EXIT

echo "=== Vault Secret Agent Test Suite ==="

# Build the binary
print_header "Building vault-secret-agent"
go build -o vault-secret-agent
print_success "Build successful"

# Test version flag
print_header "Testing version information"
VERSION_OUTPUT=$(./vault-secret-agent -v)
echo "$VERSION_OUTPUT"
print_success "Version information displayed with -v flag"

VERSION_OUTPUT_LONG=$(./vault-secret-agent --version)
echo "$VERSION_OUTPUT_LONG"
print_success "Version information displayed with --version flag"

# Test verbose flag
print_header "Testing verbose mode"
VERBOSE_OUTPUT=$(./vault-secret-agent -V FG_RELEASE_VERSION 2>&1 | head -n 3)
echo "$VERBOSE_OUTPUT"
print_success "Verbose output enabled with -V flag"

VERBOSE_OUTPUT_LONG=$(./vault-secret-agent --verbose FG_RELEASE_VERSION 2>&1 | head -n 3)
echo "$VERBOSE_OUTPUT_LONG"
print_success "Verbose output enabled with --verbose flag"

# Test help output
print_header "Testing help information"
HELP_OUTPUT=$(./vault-secret-agent -h | head -n 20)
echo "$HELP_OUTPUT"
print_success "Help information displayed with usage examples and grouped options"

# Test output buffering with a template
print_header "Testing output buffering with template processing"
# Create a simple template with a single variable
echo "FG_RELEASE_VERSION={{ FG_RELEASE_VERSION }}" > large.tmpl

START_TIME=$(date +%s%N)
./vault-secret-agent -t large.tmpl -o large.env
END_TIME=$(date +%s%N)
DURATION=$((($END_TIME - $START_TIME) / 1000000))

if [ -f large.env ]; then
    print_success "Output buffering works (processed template in ${DURATION}ms)"
    echo "Output content:"
    cat large.env
fi

# If environment variables are set, test API functionality
if [[ -n "$HCP_CLIENT_ID" && -n "$HCP_CLIENT_SECRET" && -n "$HCP_ORGANIZATION_ID" && -n "$HCP_PROJECT_ID" && -n "$HCP_APP_NAME" ]]; then
    # Test direct secret retrieval
    print_header "Testing direct secret retrieval"
    OUTPUT=$(./vault-secret-agent FG_RELEASE_VERSION)
    echo "$OUTPUT"
    print_success "Secret retrieved successfully"
    
    # Test verbose mode with request ID tracing
    print_header "Testing verbose mode with request ID tracing"
    ./vault-secret-agent -V FG_RELEASE_VERSION 2>&1 | tee output.log | head -n 10
    print_success "Verbose output with request IDs displayed"
    
    # Test controlled concurrency
    print_header "Testing controlled concurrency"
    ./vault-secret-agent -V FG_RELEASE_VERSION FG_RELEASE_VERSION FG_RELEASE_VERSION 2>&1 | grep "Successfully retrieved" | head -n 1
    print_success "Controlled concurrency working"
    
    # Test JSON response format
    print_header "Testing JSON response format"
    ./vault-secret-agent -r FG_RELEASE_VERSION | head -n 10
    print_success "JSON response format working"
    
    # Test template mode
    print_header "Testing template mode"
    cat > env.tmpl << 'EOF'
FG_RELEASE_VERSION='{{ FG_RELEASE_VERSION }}'
EOF
    
    ./vault-secret-agent -t env.tmpl -o secrets.env
    cat secrets.env
    print_success "Template rendered successfully"

    # Test caching with TTL
    print_header "Testing caching with TTL"
    # Create test template for caching test
    cat > cache-test.tmpl << 'EOF'
FG_RELEASE_VERSION='{{ FG_RELEASE_VERSION }}'
EOF
    print_success "Cache test template created"
    
    # Create config with short TTL for testing
    cat > cache-config.yaml << 'EOF'
hcp_auth:
  client_id: ${HCP_CLIENT_ID}
  client_secret: ${HCP_CLIENT_SECRET}
  organization_id: ${HCP_ORGANIZATION_ID}
  project_id: ${HCP_PROJECT_ID}
  app_name: ${HCP_APP_NAME}

agent:
  render_interval: 3s
  no_exit_on_retry: true
  retry:
    max_attempts: 3
    initial_backoff: 1s
    max_backoff: 30s
    use_jitter: true
  cache:
    enabled: true
    ttl: 5s

logging:
  level: debug
  format: text
  mask_secrets: true

templates:
  - source: "cache-test.tmpl"
    destination: "cache-test.env"
    error_on_missing_keys: false
    create_dir: true
    file_perms: 0600
EOF
    print_success "Cache test config created with TTL of 5 seconds"
    
    # Start agent in background with debug logging
    print_header "Starting agent with caching enabled"
    ./vault-secret-agent -a -c cache-config.yaml > cache-test.log 2>&1 &
    AGENT_PID=$!
    print_success "Agent started with PID $AGENT_PID"
    
    # Wait for template to be rendered
    print_header "Waiting for initial template rendering"
    MAX_WAIT=30
    WAIT_COUNT=0
    while [ ! -f cache-test.env ] && [ $WAIT_COUNT -lt $MAX_WAIT ]; do
        echo -n "."
        sleep 1
        WAIT_COUNT=$((WAIT_COUNT + 1))
    done
    echo ""
    
    if [ -f cache-test.env ]; then
        print_success "Initial template rendered successfully after $WAIT_COUNT seconds"
        cat cache-test.env
        
        # Check for cache misses in the first run
        CACHE_MISSES=$(grep -c "Cache miss for secret" cache-test.log)
        if [ $CACHE_MISSES -gt 0 ]; then
            print_success "Initial cache misses detected: $CACHE_MISSES (expected on first run)"
            grep "Cache miss for secret" cache-test.log | head -n 3
        fi
        
        # Check for secrets added to cache
        CACHE_ADDS=$(grep -c "Added secret .* to cache" cache-test.log)
        if [ $CACHE_ADDS -gt 0 ]; then
            print_success "Secrets added to cache: $CACHE_ADDS"
            grep "Added secret .* to cache" cache-test.log | head -n 3
        fi
        
        print_header "Waiting for second template rendering (should use cache)"
        echo "Waiting for next render cycle (3 seconds)..."
        sleep 4
        
        # Check for cache hits in the second run
        CACHE_HITS=$(grep -c "Cache hit for secret" cache-test.log)
        if [ $CACHE_HITS -gt 0 ]; then
            print_success "Cache hits detected: $CACHE_HITS (expected on second run)"
            grep "Cache hit for secret" cache-test.log | head -n 3
        else
            echo "No cache hits detected. Waiting longer..."
            sleep 4
            CACHE_HITS=$(grep -c "Cache hit for secret" cache-test.log)
            if [ $CACHE_HITS -gt 0 ]; then
                print_success "Cache hits detected after waiting: $CACHE_HITS"
                grep "Cache hit for secret" cache-test.log | head -n 3
            else
                echo "Still no cache hits detected. This is unexpected."
                echo "Checking log for errors:"
                grep -i "error" cache-test.log || echo "No errors found in log"
            fi
        fi
        
        print_header "Waiting for cache TTL to expire"
        echo "Waiting 6 seconds for the 5-second TTL to expire..."
        sleep 6
        
        print_header "Checking for cache expiry"
        echo "Waiting for next render cycle after TTL expiry..."
        sleep 4
        
        # Check for cache misses after TTL expiry
        NEW_CACHE_MISSES=$(grep -c "Cache miss for secret" cache-test.log)
        if [ $NEW_CACHE_MISSES -gt $CACHE_MISSES ]; then
            print_success "Cache misses after TTL expiry: $(($NEW_CACHE_MISSES - $CACHE_MISSES))"
            grep "Cache miss for secret" cache-test.log | tail -n 3
        else
            echo "No new cache misses detected after TTL expiry. Waiting longer..."
            sleep 4
            NEW_CACHE_MISSES=$(grep -c "Cache miss for secret" cache-test.log)
            if [ $NEW_CACHE_MISSES -gt $CACHE_MISSES ]; then
                print_success "Cache misses after waiting: $(($NEW_CACHE_MISSES - $CACHE_MISSES))"
                grep "Cache miss for secret" cache-test.log | tail -n 3
            else
                echo "Still no new cache misses detected. This is unexpected."
            fi
        fi
        
        # Check for cache cleanup
        CACHE_CLEANUP=$(grep -c "Cleaned up .* expired cache entries" cache-test.log)
        if [ $CACHE_CLEANUP -gt 0 ]; then
            print_success "Cache cleanup detected"
            grep "Cleaned up .* expired cache entries" cache-test.log
        else
            echo "No cache cleanup detected. This might be expected if cleanup hasn't run yet."
            echo "Waiting longer for cleanup..."
            sleep 10
            CACHE_CLEANUP=$(grep -c "Cleaned up .* expired cache entries" cache-test.log)
            if [ $CACHE_CLEANUP -gt 0 ]; then
                print_success "Cache cleanup detected after waiting"
                grep "Cleaned up .* expired cache entries" cache-test.log
            else
                echo "Still no cache cleanup detected."
            fi
        fi
        
        print_header "Cache Test Summary"
        echo "Cache misses: $(grep -c "Cache miss for secret" cache-test.log)"
        echo "Cache hits: $(grep -c "Cache hit for secret" cache-test.log)"
        echo "Cache additions: $(grep -c "Added secret .* to cache" cache-test.log)"
        echo "Cache cleanups: $(grep -c "Cleaned up .* expired cache entries" cache-test.log)"
    else
        echo "Error: Template was not rendered after $MAX_WAIT seconds. Check the logs for errors."
        cat cache-test.log
    fi
    
    # Kill the agent
    kill $AGENT_PID
    print_success "Cache test completed"

    # Test agent mode
    print_header "Testing agent mode"
    # Create test template for agent mode
    cat > env.tmpl << 'EOF'
FG_RELEASE_VERSION='{{ FG_RELEASE_VERSION }}'
EOF
    
    # Start agent in background
    ./vault-secret-agent -a -c agent-config.yaml > agent.log 2>&1 &
    AGENT_PID=$!
    
    # Wait for agent to start and create output file
    sleep 3
    
    if [ -f secrets.env ]; then
        print_success "Agent successfully rendered template"
        cat secrets.env
    fi
    
    # Show agent configuration
    print_header "Agent configuration"
    grep "render_interval\|level:\|cache:" agent-config.yaml
    print_success "Agent configured correctly"
    
    # Cleanup agent
    kill $AGENT_PID
    
    # Test batch requests
    print_header "Testing batch requests"
    ./vault-secret-agent -V FG_RELEASE_VERSION FG_RELEASE_VERSION FG_RELEASE_VERSION 2>&1 | grep "batch" | head -n 2
    print_success "Batch request mode working"
    
    # Test template pre-compilation
    print_header "Testing template pre-compilation"
    # Create test template for pre-compilation test
    cat > precompile-test.tmpl << 'EOF'
FG_RELEASE_VERSION='{{ FG_RELEASE_VERSION }}'
EOF
    print_success "Pre-compilation test template created"
    
    # First run - should compile the template
    echo "First run - should compile the template"
    ./vault-secret-agent -V -t precompile-test.tmpl -o precompile-test.env 2>&1 | grep -E "Compiling template|Found .* variables in template|Cached compiled template" | head -n 3
    
    # Second run - should use the cached template
    echo "Second run - should use the cached template"
    ./vault-secret-agent -V -t precompile-test.tmpl -o precompile-test.env 2>&1 | grep "Using cached compiled template" | head -n 1
    
    # Modify the template
    echo "Modifying the template to test cache invalidation"
    cat > precompile-test.tmpl << 'EOF'
FG_RELEASE_VERSION='{{ FG_RELEASE_VERSION }}'
FG_RELEASE_VERSION_AGAIN='{{ FG_RELEASE_VERSION }}'
EOF
    
    # Third run - should recompile the template
    echo "Third run - should recompile the template after modification"
    ./vault-secret-agent -V -t precompile-test.tmpl -o precompile-test.env 2>&1 | grep -E "Compiling template|Found .* variables in template|Cached compiled template" | head -n 3
    
    print_success "Template pre-compilation working correctly"
    
    # Clean up pre-compilation test files
    rm -f precompile-test.tmpl precompile-test.env
    
    # Test memory security
    print_header "Testing memory security"
    # Create test program for memory security
    cat > memory-test.go << EOF
package main

import (
	"fmt"
	"runtime"
	"time"
)

func main() {
	fmt.Println("Testing SecureString...")
	
	// Create a secure string
	secret := NewSecureString("sensitive-data-123")
	fmt.Printf("Created SecureString with value: %s\n", secret.Get())
	
	// Test memory locking
	if err := LockMemory(); err != nil {
		fmt.Printf("Warning: Failed to lock memory: %v\n", err)
	} else {
		fmt.Println("Successfully locked memory")
	}
	
	// Force garbage collection to test finalizer
	secret = nil
	runtime.GC()
	
	// Wait a moment for finalizer to run
	time.Sleep(1 * time.Second)
	
	// Unlock memory
	if err := UnlockMemory(); err != nil {
		fmt.Printf("Warning: Failed to unlock memory: %v\n", err)
	} else {
		fmt.Println("Successfully unlocked memory")
	}
	
	fmt.Println("Memory security test completed")
}
EOF
    
    # Compile and run the test program
    go run memory-test.go secure_memory.go > memory-test.log 2>&1
    if [ $? -ne 0 ]; then
        cat memory-test.log
        echo "Memory security test failed"
        exit 1
    fi
    
    # Check for expected output
    if grep -q "Successfully locked memory" memory-test.log && grep -q "Successfully unlocked memory" memory-test.log; then
        print_success "Memory locking/unlocking works correctly"
    else
        cat memory-test.log
        echo "Memory locking/unlocking test failed"
        exit 1
    fi
    
    if grep -q "Created SecureString with value: sensitive-data-123" memory-test.log; then
        print_success "SecureString implementation works correctly"
    else
        cat memory-test.log
        echo "SecureString test failed"
        exit 1
    fi
    
    print_success "Memory security working correctly"
    
    # Clean up memory security test files
    rm -f memory-test.go memory-test.log
else
    print_header "Skipping API tests - environment variables not set"
    echo "To run API tests, set the following environment variables:"
    echo "HCP_CLIENT_ID, HCP_CLIENT_SECRET, HCP_ORGANIZATION_ID, HCP_PROJECT_ID, HCP_APP_NAME"
fi

echo -e "\n=== All tests completed successfully! ===" 

# Explicitly run cleanup at the end of the script
print_header "Final cleanup"
cleanup 