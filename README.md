# Vault Secret Agent

A powerful and flexible tool for managing secrets from HashiCorp Cloud Platform (HCP) Vault. This agent helps you securely retrieve and manage secrets in your applications.

## 🌟 Features

- **Multiple Operating Modes**:
  - Direct secret retrieval
  - Template-based secret injection
  - Background agent mode for continuous updates

- **User-Friendly Interface**:
  - Simple command-line interface
  - Clear error messages
  - Detailed help documentation

- **Secure by Design**:
  - Automatic secret masking in logs
  - Secure file permissions
  - Environment variable support for credentials

## 🚀 Quick Start

### Prerequisites

- HCP Vault account credentials
- The following environment variables set:
  ```bash
  export HCP_CLIENT_ID="your-client-id"
  export HCP_CLIENT_SECRET="your-client-secret"
  export HCP_ORGANIZATION_ID="your-org-id"
  export HCP_PROJECT_ID="your-project-id"
  export HCP_APP_NAME="your-app-name"
  ```

### Installation

```bash
go build -o vault-secret-agent
```

### Basic Usage

1. **Get a Single Secret**:
   ```bash
   ./vault-secret-agent SECRET_NAME
   ```

2. **Get Multiple Secrets**:
   ```bash
   ./vault-secret-agent SECRET1 SECRET2 SECRET3
   ```

3. **Get Full Secret Response** (includes metadata):
   ```bash
   ./vault-secret-agent --response SECRET_NAME
   ```

### Template Mode

Create environment files from templates:

1. Create a template file (e.g., `env.tmpl`):
   ```
   DATABASE_URL={{ DATABASE_URL }}
   API_KEY={{ API_KEY }}
   ```

2. Generate the environment file:
   ```bash
   ./vault-secret-agent --template=env.tmpl --output=.env
   ```

### Agent Mode

Run as a background service that automatically updates secrets:

1. Create a configuration file (e.g., `agent-config.yaml`):
   ```yaml
   agent:
     hcp:
       client_id: ${HCP_CLIENT_ID}
       client_secret: ${HCP_CLIENT_SECRET}
       organization_id: ${HCP_ORGANIZATION_ID}
       project_id: ${HCP_PROJECT_ID}
       app_name: ${HCP_APP_NAME}

     settings:
       exit_on_retry_failure: false
       retry:
         max_attempts: 3
         backoff_initial: 1s
         backoff_max: 30s
         jitter: true
       cache:
         enabled: true         # Enable secret caching
         ttl: 86400s           # Cache TTL (24 hours)
         version_check: true   # Enable version checking
         version_check_interval: 10s  # Check versions every 10 seconds
         batch_api: true        # Enable batch processing for multiple secrets

     logging:
       level: info
       format: text
       mask_secrets: true

     templates:
       - source: "env.tmpl"
         destination: "secrets.env"
         error_on_missing_key: true
         create_directories: true
         permissions: "0600"
   ```

2. Start the agent:
   ```bash
   ./vault-secret-agent --agent --config=agent-config.yaml
   ```

## 🛠️ Command-Line Options

- `-a, --agent`: Run in agent mode
- `-c, --config=<file>`: Path to agent configuration file
- `-h, --help`: Show help message
- `-o, --output=<file>`: Output file for template mode
- `-r, --response`: Show full API response
- `-t, --template=<file>`: Template file to process
- `-v, --version`: Show version information
- `-vvv, --verbose`: Enable verbose logging

## 📝 Configuration

### Agent Configuration Options

- **HCP Settings**:
  - Authentication credentials can be specified:
    - Directly in the config file (values take precedence)
    - As environment variables using `${VAR_NAME}` syntax (fallback)
    - As environment variables without any config entry (final fallback)
  - Supports all key HCP credentials: client_id, client_secret, organization_id, project_id, app_name

- **Behavior Settings**:
  - `exit_on_retry_failure`: Whether to exit on repeated failures
  - Retry settings for resilience
  - Cache settings for improved performance:
    - `cache.enabled`: Enable secret caching
    - `cache.ttl`: Cache lifetime for secrets
    - `cache.version_check`: Enable version checking to detect secret changes
    - `cache.version_check_interval`: How often to check for secret version changes
    - `cache.batch_api`: Enable batch processing for multiple secrets

- **Logging**:
  - Log level (debug, info, warn, error)
  - Format (text or JSON)
  - Secret masking for security

- **Templates**:
  - Source and destination paths
  - Error handling options
  - File permissions

## 🚀 Performance Optimizations

The Vault Secret Agent includes several high-performance optimizations:

### Secret Caching with TTL
- Implements a thread-safe cache with configurable TTL
- Automatically invalidates cache entries when secrets change
- Dramatically reduces API calls in agent mode

### Connection Pooling and HTTP Optimization
- Configures optimal connection pool settings
- Implements connection reuse with keep-alive
- Optimizes compression settings for API communication

### Batch Secret Processing
- Retrieves multiple secrets in a single API call
- Integrates with the caching system to only fetch cache misses
- Includes fallback mechanisms for reliability
- Implements pagination for handling large numbers of secrets

### Automatic Template Re-rendering
- Monitors template files for changes in real-time
- Automatically re-renders templates when they change
- Uses smart modification time tracking to prevent unnecessary renders
- Provides timestamped logs for template change events

### Optimized Logging
- Reduces verbosity by only printing meaningful state changes
- Includes ISO-8601 timestamps on all important log messages
- Maintains detailed debug logs while keeping stdout clean
- Improves log readability with consistent formatting

### Intelligent Template Rendering

The agent uses an intelligent approach to template rendering:

1. **On-Demand Rendering**: Templates are only rendered:
   - When the agent starts
   - When a secret's value changes
   - When a template file changes

2. **Efficient Version Checking**:
   - Retrieves metadata for all secrets in a single API call (with pagination)
   - Only fetches full secret values when a version change is detected
   - Dramatically reduces API calls and resource usage

3. **Configurable Settings**:
   - Control caching behavior with `cache.ttl`
   - Adjust `version_check_interval` to control how frequently to check for secret changes
   - Enable/disable batch processing with `cache.batch_api`

This approach ensures that your applications always have the latest secrets while minimizing resource usage and API calls.

## 🔒 Security Best Practices

1. Store credentials in environment variables
2. Use appropriate file permissions (default: 0600)
3. Enable secret masking in logs
4. Regularly rotate HCP credentials
5. Use the minimum required permissions

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run the test suite: `./test.sh`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and feature requests, please create an issue in the repository.

### Environment Variable Override Examples

The agent supports three ways to configure credentials:

1. **Direct Values in Config** (highest priority):
   ```yaml
   hcp:
     client_id: "actual-client-id-here"  # Will use this exact value
     organization_id: ${HCP_ORGANIZATION_ID}  # Will use env var
   ```

2. **Environment Variables via Placeholders**:
   ```yaml
   hcp:
     client_id: ${HCP_CLIENT_ID}  # Will use env var HCP_CLIENT_ID
   ```

3. **Environment Variables Direct Fallback** (lowest priority):
   ```yaml
   hcp:
     # client_id not specified - will use HCP_CLIENT_ID env var
   ```

This flexibility allows for:
- Environment-specific configurations
- Secure credential management
- Easy local development and testing 