package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

const (
	hcpAPIBaseURL = "https://api.cloud.hashicorp.com/secrets/2023-11-28"
	authURL       = "https://auth.hashicorp.com/oauth/token"
)

// maskString masks a string by showing only the first 4 and last 4 characters
func maskString(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// maskURL replaces sensitive information in URLs with masked versions
func maskURL(url string) string {
	// List of parameters to mask in URLs
	sensitiveParams := []string{
		"client_id",
		"client_secret",
		"access_token",
		"token",
	}

	maskedURL := url
	for _, param := range sensitiveParams {
		// Find parameter in query string
		paramIndex := strings.Index(maskedURL, param+"=")
		if paramIndex == -1 {
			continue
		}

		// Find the end of the parameter value
		valueStart := paramIndex + len(param) + 1
		valueEnd := strings.Index(maskedURL[valueStart:], "&")
		if valueEnd == -1 {
			valueEnd = len(maskedURL)
		} else {
			valueEnd += valueStart
		}

		// Replace the value with masked version
		maskedURL = maskedURL[:valueStart] + "****" + maskedURL[valueEnd:]
	}

	// Also mask organization and project IDs in path segments
	parts := strings.Split(maskedURL, "/")
	for i, part := range parts {
		if i > 0 && (parts[i-1] == "organizations" || parts[i-1] == "projects") {
			if len(part) > 8 {
				parts[i] = maskString(part)
			}
		}
	}
	maskedURL = strings.Join(parts, "/")

	return maskedURL
}

type Client struct {
	baseURL     string
	httpClient  *retryablehttp.Client
	verbose     bool
	logger      *log.Logger
	accessToken string
	orgID       string
	projectID   string
	appName     string
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type SecretResponse struct {
	Name     string
	Value    string
	Response interface{}
	Error    error
}

type ErrorResponse struct {
	Code    int      `json:"code"`
	Message string   `json:"message"`
	Details []string `json:"details"`
}

type SecretResult struct {
	Name     string
	Value    string
	Error    error
	Response *SecretResponse
}

var (
	verbose     bool
	response    bool
	template    string
	output      string
	agentMode   bool
	agentConfig string
)

func init() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging")
	flag.BoolVar(&response, "response", false, "Output full API response")
	flag.BoolVar(&response, "r", false, "Output full API response")
	flag.StringVar(&template, "template", "", "Path to template file")
	flag.StringVar(&template, "t", "", "Path to template file")
	flag.StringVar(&output, "output", "", "Path to output file")
	flag.StringVar(&output, "o", "", "Path to output file")
	flag.BoolVar(&agentMode, "agent", false, "Run in agent mode")
	flag.StringVar(&agentConfig, "config", "", "Path to agent configuration file")
}

func newClient(verbose bool) (*Client, error) {
	// Get required environment variables
	clientID := os.Getenv("HCP_CLIENT_ID")
	clientSecret := os.Getenv("HCP_CLIENT_SECRET")
	orgID := os.Getenv("HCP_ORGANIZATION_ID")
	projectID := os.Getenv("HCP_PROJECT_ID")
	appName := os.Getenv("HCP_APP_NAME")

	if clientID == "" || clientSecret == "" || orgID == "" || projectID == "" || appName == "" {
		return nil, fmt.Errorf("HCP_CLIENT_ID, HCP_CLIENT_SECRET, HCP_ORGANIZATION_ID, HCP_PROJECT_ID, and HCP_APP_NAME must be set")
	}

	// Create retryable HTTP client
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.Logger = nil // Disable internal logging

	// Create client
	client := &Client{
		baseURL:    "https://api.cloud.hashicorp.com/secrets/2023-11-28",
		httpClient: retryClient,
		verbose:    verbose,
		logger:     log.New(os.Stderr, "vault-secret-agent: ", log.LstdFlags),
		orgID:      orgID,
		projectID:  projectID,
		appName:    appName,
	}

	// Get access token
	token, err := client.getAccessToken(clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}
	client.accessToken = token

	return client, nil
}

func (c *Client) logf(format string, v ...interface{}) {
	if c.verbose {
		c.logger.Printf(format, v...)
	}
}

func (c *Client) getAccessToken(clientID, clientSecret string) (string, error) {
	c.logf("Getting access token from HCP auth service...")

	// Create request body with audience parameter
	params := url.Values{}
	params.Set("grant_type", "client_credentials")
	params.Set("client_id", clientID)
	params.Set("client_secret", clientSecret)
	params.Set("audience", "https://api.hashicorp.cloud")

	// Create request
	req, err := retryablehttp.NewRequest("POST", "https://auth.hashicorp.com/oauth/token", strings.NewReader(params.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	c.logf("Successfully obtained access token (masked: %s)", maskString(tokenResp.AccessToken))
	return tokenResp.AccessToken, nil
}

func (c *Client) doWithRetry(req *retryablehttp.Request) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// Handle unauthorized response by refreshing token and retrying
	if resp.StatusCode == http.StatusUnauthorized {
		c.logf("Received unauthorized response, refreshing token...")
		resp.Body.Close()

		// Get new token
		token, err := c.getAccessToken(os.Getenv("HCP_CLIENT_ID"), os.Getenv("HCP_CLIENT_SECRET"))
		if err != nil {
			return nil, fmt.Errorf("failed to refresh token: %w", err)
		}
		c.accessToken = token

		// Retry request with new token
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
		return c.httpClient.Do(req)
	}

	return resp, nil
}

func (c *Client) getSecret(ctx context.Context, name string) (*SecretResponse, error) {
	c.logf("Fetching secret %q from HCP Vault Secrets (org: %s, project: %s, app: %s)...",
		name, maskString(c.orgID), maskString(c.projectID), c.appName)

	url := fmt.Sprintf("%s/organizations/%s/projects/%s/apps/%s/secrets/%s:open",
		c.baseURL, c.orgID, c.projectID, c.appName, name)

	c.logf("Making request to GET %s", maskURL(url))

	req, err := retryablehttp.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp struct {
		Secret struct {
			Name          string    `json:"name"`
			Type          string    `json:"type"`
			LatestVersion int       `json:"latest_version"`
			CreatedAt     time.Time `json:"created_at"`
			CreatedByID   string    `json:"created_by_id"`
			SyncStatus    struct{}  `json:"sync_status"`
			StaticVersion struct {
				Version     int       `json:"version"`
				Value       string    `json:"value"`
				CreatedAt   time.Time `json:"created_at"`
				CreatedByID string    `json:"created_by_id"`
			} `json:"static_version"`
		} `json:"secret"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	c.logf("Successfully retrieved secret %q (version %d)", name, apiResp.Secret.StaticVersion.Version)

	return &SecretResponse{
		Name:     name,
		Value:    apiResp.Secret.StaticVersion.Value,
		Response: apiResp,
	}, nil
}

func (c *Client) getSecrets(ctx context.Context, names []string) []*SecretResponse {
	results := make([]*SecretResponse, len(names))
	var wg sync.WaitGroup

	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			secret, err := c.getSecret(ctx, name)
			if err != nil {
				results[i] = &SecretResponse{
					Name:  name,
					Error: err,
				}
				return
			}
			results[i] = secret
		}(i, name)
	}

	wg.Wait()
	return results
}

// extractTemplateVars extracts variable names from template content
func extractTemplateVars(content string) []string {
	var vars []string
	var unique = make(map[string]bool)

	// Find all occurrences of {{ VAR_NAME }}
	parts := strings.Split(content, "{{")
	for _, part := range parts[1:] { // Skip first part (before any {{)
		if idx := strings.Index(part, "}}"); idx != -1 {
			varName := strings.TrimSpace(part[:idx])
			if !unique[varName] {
				unique[varName] = true
				vars = append(vars, varName)
			}
		}
	}
	return vars
}

// renderTemplate replaces variables in template with their values
func renderTemplate(content string, secrets map[string]string) string {
	result := content
	for name, value := range secrets {
		placeholder := "{{ " + name + " }}"
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

// processTemplate reads template file, extracts variables, fetches secrets, and writes output
func (c *Client) processTemplate(ctx context.Context, templatePath, outputPath string) error {
	// Read template file
	tmplData, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("failed to read template: %w", err)
	}

	// Find all variables in template
	var variables []string
	re := regexp.MustCompile(`\{\{\s*([^}\s]+)\s*}}`)
	matches := re.FindAllStringSubmatch(string(tmplData), -1)
	for _, match := range matches {
		variables = append(variables, match[1])
	}

	if len(variables) == 0 {
		return fmt.Errorf("no variables found in template")
	}

	c.logf("Found %d variables in template: %v", len(variables), variables)

	// Get all secrets concurrently
	var wg sync.WaitGroup
	secretCh := make(chan *SecretResponse, len(variables))
	errCh := make(chan error, len(variables))

	for _, name := range variables {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			secret, err := c.getSecret(ctx, name)
			if err != nil {
				errCh <- fmt.Errorf("failed to get secret %q: %w", name, err)
				return
			}
			secretCh <- secret
		}(name)
	}

	// Wait for all goroutines to finish
	wg.Wait()
	close(secretCh)
	close(errCh)

	// Check for errors
	if len(errCh) > 0 {
		var errs []string
		for err := range errCh {
			errs = append(errs, err.Error())
		}
		return fmt.Errorf("failed to get secrets: %s", strings.Join(errs, "; "))
	}

	// Create map of variables to values
	values := make(map[string]string)
	for secret := range secretCh {
		values[secret.Name] = secret.Value
	}

	// Replace variables in template
	result := string(tmplData)
	for name, value := range values {
		placeholder := fmt.Sprintf("{{ %s }}", name)
		result = strings.ReplaceAll(result, placeholder, value)
	}

	// Write output file with secure permissions
	if err := os.WriteFile(outputPath, []byte(result), 0600); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	c.logf("Successfully rendered template and wrote output to %s", outputPath)
	return nil
}

func main() {
	// Set custom usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <secret-name>... or\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s [options] --template=<file> --output=<file> or\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s --agent --config=<file>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -v, --verbose         Enable verbose logging\n")
		fmt.Fprintf(os.Stderr, "  -r, --response        Output full API response\n")
		fmt.Fprintf(os.Stderr, "  -t, --template=<file> Path to template file\n")
		fmt.Fprintf(os.Stderr, "  -o, --output=<file>   Path to output file (required with template)\n")
		fmt.Fprintf(os.Stderr, "  --agent               Run in agent mode\n")
		fmt.Fprintf(os.Stderr, "  --config=<file>       Path to agent configuration file (required with agent)\n")
	}

	flag.Parse()

	// Handle agent mode
	if agentMode {
		if agentConfig == "" {
			fmt.Fprintf(os.Stderr, "Error: --config=<file> is required when using --agent\n")
			os.Exit(1)
		}

		// Create and start agent
		agent, err := NewAgent(agentConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating agent: %v\n", err)
			os.Exit(1)
		}

		// Setup signal handling for graceful shutdown
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		// Start agent
		if err := agent.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting agent: %v\n", err)
			os.Exit(1)
		}

		// Wait for shutdown signal
		sig := <-sigCh
		fmt.Printf("Received signal %v, shutting down...\n", sig)
		agent.Stop()
		os.Exit(0)
	}

	// Create context that we can cancel in a defer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create client with verbose flag
	client, err := newClient(verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	// Handle template mode
	if template != "" {
		if output == "" {
			fmt.Fprintf(os.Stderr, "Error: -o, --output=<file> is required when using -t, --template\n")
			os.Exit(1)
		}
		if response {
			fmt.Fprintf(os.Stderr, "Error: -r, --response cannot be used with template mode\n")
			fmt.Fprintf(os.Stderr, "Template mode renders variables into a file, while response mode outputs detailed API responses\n")
			os.Exit(1)
		}
		if err := client.processTemplate(ctx, template, output); err != nil {
			fmt.Fprintf(os.Stderr, "Error processing template: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Get secret names from remaining args
	secretNames := flag.Args()
	if len(secretNames) == 0 {
		fmt.Fprintf(os.Stderr, "Error: at least one secret name is required\n")
		os.Exit(1)
	}

	// Process each secret
	for _, name := range secretNames {
		secret, err := client.getSecret(ctx, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting secret: %v\n", err)
			os.Exit(1)
		}

		if response {
			// Create a map for response output
			output := make(map[string]interface{})
			output[name] = secret.Response

			// Marshal to JSON
			jsonBytes, err := json.MarshalIndent(output, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(string(jsonBytes))
		} else {
			fmt.Printf("%s=%s\n", name, secret.Value)
		}
	}
}
