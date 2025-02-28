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
       render_interval: 5s
       exit_on_retry_failure: false
       retry:
         max_attempts: 3
         backoff_initial: 1s
         backoff_max: 30s
         jitter: true

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
  - Authentication credentials
  - Organization and project details

- **Behavior Settings**:
  - `render_interval`: How often to check for updates
  - `exit_on_retry_failure`: Whether to exit on repeated failures
  - Retry settings for resilience

- **Logging**:
  - Log level (debug, info, warn, error)
  - Format (text or JSON)
  - Secret masking for security

- **Templates**:
  - Source and destination paths
  - Error handling options
  - File permissions

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