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

- **Performance Optimizations**:
  - Output buffering for faster processing
  - Batch request mode for multiple secrets
  - Connection pooling for efficient API usage
  - Controlled concurrency for large secret sets
  - Caching with TTL for improved response times

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
   hcp_auth:
     client_id: ${HCP_CLIENT_ID}
     client_secret: ${HCP_CLIENT_SECRET}
     organization_id: ${HCP_ORGANIZATION_ID}
     project_id: ${HCP_PROJECT_ID}
     app_name: ${HCP_APP_NAME}

   agent:
     render_interval: 5s
     no_exit_on_retry: false
     retry:
       max_attempts: 3
       initial_backoff: 1s
       max_backoff: 30s
       use_jitter: true
     cache:
       enabled: true
       ttl: 5m

   logging:
     level: info
     format: text
     mask_secrets: true

   templates:
     - source: "env.tmpl"
       destination: "secrets.env"
       error_on_missing_keys: true
       create_dir: true
       file_perms: 0600
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

- **HCP Authentication**:
  - `client_id`, `client_secret`: Authentication credentials
  - `organization_id`, `project_id`, `app_name`: Organization and project details

- **Agent Behavior Settings**:
  - `render_interval`: How often to check for updates
  - `no_exit_on_retry`: Whether to continue running after retry failures
  - Retry settings: `max_attempts`, `initial_backoff`, `max_backoff`, `use_jitter`
  - Cache settings: `enabled`, `ttl` (time-to-live)

- **Logging**:
  - `level`: Log level (debug, info, warn, error)
  - `format`: Output format (text or JSON)
  - `mask_secrets`: Enable secret masking for security

- **Templates**:
  - `source`: Template file path
  - `destination`: Output file path
  - `error_on_missing_keys`: Whether to error on missing template variables
  - `create_dir`: Create destination directory if it doesn't exist
  - `file_perms`: File permissions for the output file

## 🔒 Security Best Practices

1. Store credentials in environment variables
2. Use appropriate file permissions (default: 0600)
3. Enable secret masking in logs
4. Regularly rotate HCP credentials
5. Use the minimum required permissions

## 🚀 Performance Optimizations

The Vault Secret Agent includes several performance optimizations:

1. **Output Buffering**: Significantly improves performance when processing large templates or multiple secrets by buffering output operations.

2. **Batch Request Mode**: Retrieves multiple secrets in a single API call, reducing network overhead and improving response times.

3. **Connection Pooling**: Reuses HTTP connections to minimize connection establishment overhead for multiple requests.

4. **Controlled Concurrency**: Manages parallel requests to balance between performance and API rate limits.

5. **Response Compression**: Supports gzip compression for API responses to reduce bandwidth usage.

6. **Caching with TTL**: Implements an in-memory cache with configurable Time-To-Live (TTL) for secrets, reducing API calls and improving response times while ensuring data freshness.

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