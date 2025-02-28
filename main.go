package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"
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
	httpClient *retryablehttp.Client
	baseURL    string
	token      string
	verbose    bool
	logger     *log.Logger
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type SecretResponse struct {
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

func newClient(verbose bool) (*Client, error) {
	retryClient := retryablehttp.NewClient()
	retryClient.HTTPClient = cleanhttp.DefaultClient()
	retryClient.RetryMax = 3

	logger := log.New(io.Discard, "", 0)
	if verbose {
		logger = log.New(os.Stderr, "vault-secret-agent: ", log.Ltime)
	}
	// Disable retryablehttp's internal logging
	retryClient.Logger = nil

	return &Client{
		httpClient: retryClient,
		baseURL:    hcpAPIBaseURL,
		verbose:    verbose,
		logger:     logger,
	}, nil
}

func (c *Client) logf(format string, v ...interface{}) {
	if c.verbose {
		c.logger.Printf(format, v...)
	}
}

func (c *Client) getAccessToken() error {
	clientID := os.Getenv("HCP_CLIENT_ID")
	clientSecret := os.Getenv("HCP_CLIENT_SECRET")

	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("HCP_CLIENT_ID and HCP_CLIENT_SECRET must be set")
	}

	c.logf("Getting access token from HCP auth service...")
	data := strings.NewReader("grant_type=client_credentials&audience=https://api.hashicorp.cloud")
	req, err := retryablehttp.NewRequest(http.MethodPost, authURL, data)
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}

	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get access token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to get access token. Status: %d, Body: %s", resp.StatusCode, string(body))
	}

	var tokenResp AccessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	c.token = tokenResp.AccessToken
	c.logf("Successfully obtained access token (masked: %s)", maskString(tokenResp.AccessToken))
	return nil
}

func (c *Client) doWithRetry(req *retryablehttp.Request) (*http.Response, error) {
	maskedURL := maskURL(req.URL.String())
	c.logf("Making request to %s %s", req.Method, maskedURL)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// If we get an authentication error, try to refresh the token and retry once
	if resp.StatusCode == http.StatusUnauthorized {
		c.logf("Received unauthorized response, refreshing token...")
		resp.Body.Close()
		if err := c.getAccessToken(); err != nil {
			return nil, fmt.Errorf("failed to refresh token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		c.logf("Retrying request with new token...")
		return c.httpClient.Do(req)
	}

	return resp, nil
}

func (c *Client) getSecret(ctx context.Context, secretName string) (*SecretResponse, error) {
	orgID := os.Getenv("HCP_ORGANIZATION_ID")
	projectID := os.Getenv("HCP_PROJECT_ID")
	appName := os.Getenv("HCP_APP_NAME")

	if orgID == "" || projectID == "" || appName == "" {
		return nil, fmt.Errorf("HCP_ORGANIZATION_ID, HCP_PROJECT_ID, and HCP_APP_NAME must be set")
	}

	c.logf("Fetching secret %q from HCP Vault Secrets (org: %s, project: %s, app: %s)...",
		secretName, maskString(orgID), maskString(projectID), appName)

	url := fmt.Sprintf("%s/organizations/%s/projects/%s/apps/%s/secrets/%s:open",
		c.baseURL, orgID, projectID, appName, secretName)

	req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		body, _ := io.ReadAll(resp.Body)
		if err := json.Unmarshal(body, &errResp); err == nil {
			return nil, fmt.Errorf("failed to get secret: %s (code: %d)", errResp.Message, errResp.Code)
		}
		return nil, fmt.Errorf("failed to get secret. Status: %d, Body: %s", resp.StatusCode, string(body))
	}

	var secretResp SecretResponse
	if err := json.NewDecoder(resp.Body).Decode(&secretResp); err != nil {
		return nil, fmt.Errorf("failed to decode secret response: %w", err)
	}

	c.logf("Successfully retrieved secret %q (version %d)", secretName, secretResp.Secret.LatestVersion)
	return &secretResp, nil
}

func (c *Client) getSecrets(ctx context.Context, secretNames []string) []SecretResult {
	results := make([]SecretResult, len(secretNames))
	resultChan := make(chan SecretResult, len(secretNames))

	// Create a goroutine for each secret
	for _, name := range secretNames {
		go func(secretName string) {
			result := SecretResult{Name: secretName}
			resp, err := c.getSecret(ctx, secretName)
			if err != nil {
				result.Error = err
			} else {
				result.Value = resp.Secret.StaticVersion.Value
				result.Response = resp
			}
			resultChan <- result
		}(name)
	}

	// Collect results
	for i := 0; i < len(secretNames); i++ {
		result := <-resultChan
		// Find the correct position in results slice
		for j := range secretNames {
			if secretNames[j] == result.Name {
				results[j] = result
				break
			}
		}
	}

	return results
}

func main() {
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	jsonOutput := flag.Bool("json", false, "Output full JSON response")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [--verbose] [--json] <secret-name>...\n", os.Args[0])
		os.Exit(1)
	}

	secretNames := args
	client, err := newClient(*verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	if err := client.getAccessToken(); err != nil {
		fmt.Fprintf(os.Stderr, "Error getting access token: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	results := client.getSecrets(ctx, secretNames)

	// Check if any errors occurred
	hasErrors := false
	for _, result := range results {
		if result.Error != nil {
			hasErrors = true
			fmt.Fprintf(os.Stderr, "Error getting secret %q: %v\n", result.Name, result.Error)
		}
	}

	if *jsonOutput {
		// Create a map for JSON output
		output := make(map[string]interface{})
		for _, result := range results {
			if result.Error == nil {
				output[result.Name] = result.Response
			}
		}
		// Pretty print the JSON output
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(output); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Print values in the order they were requested
		for _, result := range results {
			if result.Error == nil {
				fmt.Printf("%s=%s\n", result.Name, result.Value)
			}
		}
	}

	if hasErrors {
		os.Exit(1)
	}
}
