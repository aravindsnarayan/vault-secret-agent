# HCP Vault Secret Agent

A command-line tool that fetches secrets from HCP Vault Secrets, similar to vault agent for self-hosted vault.

## Features

- Fetch secrets from HCP Vault Secrets using the latest API (2023-11-28)
- Automatic token refresh
- Retryable HTTP client with error handling
- Simple CLI interface
- Verbose logging option for debugging

## Prerequisites

- Go 1.21 or later
- HCP account with access to Vault Secrets
- Required environment variables:
  - `HCP_CLIENT_ID`: Your HCP service principal client ID
  - `HCP_CLIENT_SECRET`: Your HCP service principal client secret
  - `HCP_ORGANIZATION_ID`: Your HCP organization ID
  - `HCP_PROJECT_ID`: Your HCP project ID
  - `HCP_APP_NAME`: Your HCP Vault Secrets application name

## Installation

```bash
go install github.com/aravindsnarayan/vault-secret-agent@latest
```

Or build from source:

```bash
git clone https://github.com/aravindsnarayan/vault-secret-agent.git
cd vault-secret-agent
go build
```

## Usage

```bash
# Set required environment variables
export HCP_CLIENT_ID="your-client-id"
export HCP_CLIENT_SECRET="your-client-secret"
export HCP_ORGANIZATION_ID="your-org-id"
export HCP_PROJECT_ID="your-project-id"
export HCP_APP_NAME="your-app-name"

# Fetch a secret
./vault-secret-agent SECRET_NAME

# Fetch a secret with verbose logging
./vault-secret-agent --verbose SECRET_NAME

# Fetch a secret with full JSON output
./vault-secret-agent --json SECRET_NAME
```

The tool will output the secret value to stdout, making it easy to use in scripts or other automation tools.

When using the `--verbose` flag, the tool will output detailed information about:
- Authentication process
- API requests and responses
- Token refresh attempts
- Secret retrieval status

When using the `--json` flag, the tool will output the full JSON response from HCP Vault Secrets instead of just the secret value.

## Error Handling

The tool includes comprehensive error handling:
- Environment variable validation
- API authentication errors with automatic token refresh
- Structured error responses from the API
- Network retries with backoff

## License

This project is licensed under the MIT License - see the LICENSE file for details. 