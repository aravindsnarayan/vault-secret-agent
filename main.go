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
	"reflect"
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
	version       = "0.1.0" // Current version of the binary
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
	// Cache-related fields
	secretCache    map[string]cachedSecret
	secretCacheMu  sync.RWMutex
	secretCacheTTL time.Duration
}

// cachedSecret represents a secret stored in the cache
type cachedSecret struct {
	response *SecretResponse
	expiry   time.Time
	version  int // Version of the secret from the API
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
	showVersion bool
)

func init() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&verbose, "vvv", false, "Enable verbose logging")
	flag.BoolVar(&response, "response", false, "Output full API response")
	flag.BoolVar(&response, "r", false, "Output full API response")
	flag.StringVar(&template, "template", "", "Path to template file")
	flag.StringVar(&template, "t", "", "Path to template file")
	flag.StringVar(&output, "output", "", "Path to output file")
	flag.StringVar(&output, "o", "", "Path to output file")
	flag.BoolVar(&agentMode, "agent", false, "Run in agent mode")
	flag.BoolVar(&agentMode, "a", false, "Run in agent mode")
	flag.StringVar(&agentConfig, "config", "", "Path to agent configuration file")
	flag.StringVar(&agentConfig, "c", "", "Path to agent configuration file")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.BoolVar(&showVersion, "v", false, "Show version information")
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
		baseURL:        "https://api.cloud.hashicorp.com/secrets/2023-11-28",
		httpClient:     retryClient,
		verbose:        verbose,
		logger:         log.New(os.Stderr, "vault-secret-agent: ", log.LstdFlags),
		orgID:          orgID,
		projectID:      projectID,
		appName:        appName,
		secretCache:    make(map[string]cachedSecret),
		secretCacheTTL: 0, // Default to disabled - only enable for Agent mode
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
	req, err := retryablehttp.NewRequest("POST", authURL, strings.NewReader(params.Encode()))
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
		hcpAPIBaseURL, c.orgID, c.projectID, c.appName, name)

	c.logf("Making request to GET %s", maskURL(url))

	req, err := retryablehttp.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))

	// Use context
	req.WithContext(ctx)

	// Use doWithRetry instead of direct client.Do
	resp, err := c.doWithRetry(req)
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

	// Clear expired cache entries before batch processing
	c.clearExpiredCache()

	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			secret, err := c.getSecretWithCache(ctx, name)
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

	// Get all secrets concurrently using getSecrets
	secrets := c.getSecrets(ctx, variables)

	// Check for errors
	var errs []string
	values := make(map[string]string)
	for _, secret := range secrets {
		if secret.Error != nil {
			errs = append(errs, fmt.Sprintf("failed to get secret %q: %v", secret.Name, secret.Error))
			continue
		}
		values[secret.Name] = secret.Value
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to get secrets: %s", strings.Join(errs, "; "))
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

// getSecretWithCache retrieves a secret, using the cache if valid
// Cache is disabled by default for CLI and template modes, and only enabled in agent mode
func (c *Client) getSecretWithCache(ctx context.Context, name string) (*SecretResponse, error) {
	// If cache is disabled, directly call getSecret
	if c.secretCacheTTL <= 0 {
		return c.getSecret(ctx, name)
	}

	// Check cache first
	c.secretCacheMu.RLock()
	cached, exists := c.secretCache[name]
	c.secretCacheMu.RUnlock()

	// If cached and not expired, use cached value
	if exists && time.Now().Before(cached.expiry) {
		c.logf("Using cached secret %q (expires in %v)", name, time.Until(cached.expiry).Round(time.Second))
		return cached.response, nil
	}

	// Otherwise fetch from API
	c.logf("Cache miss for secret %q, fetching from API", name)
	secret, err := c.getSecret(ctx, name)
	if err != nil {
		return nil, err
	}

	// Extract version from response if available
	var version int
	if secret.Response != nil {
		c.logf("Extracting version information from secret %q", name)
		if v, ok := c.extractVersionFromResponse(name, secret.Response); ok {
			version = v
			c.logf("Secret %q has version: %d", name, version)
		}
	}

	// Store in cache
	c.secretCacheMu.Lock()
	c.secretCache[name] = cachedSecret{
		response: secret,
		expiry:   time.Now().Add(c.secretCacheTTL),
		version:  version,
	}
	c.secretCacheMu.Unlock()

	return secret, nil
}

// clearExpiredCache removes expired entries from the cache
func (c *Client) clearExpiredCache() {
	if c.secretCacheTTL <= 0 {
		return // Cache disabled
	}

	now := time.Now()
	c.secretCacheMu.Lock()
	defer c.secretCacheMu.Unlock()

	for name, cached := range c.secretCache {
		if now.After(cached.expiry) {
			c.logf("Removing expired cache entry for %q", name)
			delete(c.secretCache, name)
		}
	}
}

// checkSecretVersions periodically checks if any cached secrets have new versions
// Returns true if any secrets were updated, false otherwise
func (c *Client) checkSecretVersions(ctx context.Context) bool {
	c.secretCacheMu.RLock()
	secretNames := make([]string, 0, len(c.secretCache))
	for name := range c.secretCache {
		secretNames = append(secretNames, name)
	}
	c.secretCacheMu.RUnlock()

	if len(secretNames) == 0 {
		c.logf("No cached secrets to check versions for")
		return false
	}

	c.logf("Checking for version changes on %d cached secrets", len(secretNames))

	// Get metadata for all secrets in a single API call
	versions, err := c.getSecretsMetadata(ctx)
	if err != nil {
		c.logf("Error fetching secret metadata: %v", err)
		return false
	}

	// Check for version changes
	c.secretCacheMu.RLock()
	secretsToUpdate := make(map[string]int)
	for name, cachedSecret := range c.secretCache {
		// Skip secrets that aren't in the response (could be deleted)
		newVersion, exists := versions[name]
		if !exists {
			c.logf("Secret %q not found in metadata response, skipping", name)
			continue
		}

		// Compare versions
		oldVersion := cachedSecret.version
		c.logf("Secret %q: current version=%d, cached version=%d", name, newVersion, oldVersion)

		if newVersion != oldVersion {
			c.logf("Secret %q has a new version (%d -> %d), marking for update", name, oldVersion, newVersion)
			secretsToUpdate[name] = newVersion
		}
	}
	c.secretCacheMu.RUnlock()

	// Update any secrets with new versions
	if len(secretsToUpdate) > 0 {
		c.logf("Updating %d secrets with new versions", len(secretsToUpdate))
		for name, newVersion := range secretsToUpdate {
			// Fetch the updated secret
			secret, err := c.getSecret(ctx, name)
			if err != nil {
				c.logf("Error fetching updated secret %q: %v", name, err)
				continue
			}

			// Update the cache
			c.secretCacheMu.Lock()
			c.secretCache[name] = cachedSecret{
				response: secret,
				expiry:   time.Now().Add(c.secretCacheTTL), // Reset TTL
				version:  newVersion,
			}
			c.secretCacheMu.Unlock()
			c.logf("Updated cache for secret %q to version %d", name, newVersion)
		}
		return true // Indicate that secrets were updated
	} else {
		c.logf("No secrets need version updates")
		return false
	}
}

// extractVersionFromResponse extracts version information from a secret response
func (c *Client) extractVersionFromResponse(name string, response interface{}) (int, bool) {
	if response == nil {
		c.logf("Warning: Secret %q has nil response", name)
		return 0, false
	}

	// Debug log the response structure
	if c.verbose {
		jsonData, _ := json.MarshalIndent(response, "", "  ")
		c.logf("Response structure for %q: %s", name, string(jsonData))
	}

	// Use reflection to examine the concrete type
	responseVal := reflect.ValueOf(response)
	responseType := responseVal.Type()

	// Special handling for the specific struct type from the API
	if responseType.String() == "struct { Secret struct { Name string \"json:\\\"name\\\"\"; Type string \"json:\\\"type\\\"\"; LatestVersion int \"json:\\\"latest_version\\\"\"; CreatedAt time.Time \"json:\\\"created_at\\\"\"; CreatedByID string \"json:\\\"created_by_id\\\"\"; SyncStatus struct {} \"json:\\\"sync_status\\\"\"; StaticVersion struct { Version int \"json:\\\"version\\\"\"; Value string \"json:\\\"value\\\"\"; CreatedAt time.Time \"json:\\\"created_at\\\"\"; CreatedByID string \"json:\\\"created_by_id\\\"\" } \"json:\\\"static_version\\\"\" } \"json:\\\"secret\\\"\" }" {
		// Access fields via reflection
		secretField := responseVal.FieldByName("Secret")
		if secretField.IsValid() {
			staticVersionField := secretField.FieldByName("StaticVersion")
			if staticVersionField.IsValid() {
				versionField := staticVersionField.FieldByName("Version")
				if versionField.IsValid() {
					version := int(versionField.Int())
					c.logf("Successfully extracted version %d from %q (via reflection)", version, name)
					return version, true
				}
			}

			// Also try LatestVersion field
			latestVersionField := secretField.FieldByName("LatestVersion")
			if latestVersionField.IsValid() {
				version := int(latestVersionField.Int())
				c.logf("Successfully extracted version %d from %q (via reflection, latest_version)", version, name)
				return version, true
			}
		}
	}

	// Try to extract from map (original method)
	respMap, ok := response.(map[string]interface{})
	if !ok {
		c.logf("Warning: Secret %q response is not a recognized format, type: %T", name, response)
		return 0, false
	}

	// The API might return the secret directly or nested under a "secret" key
	var secretObj map[string]interface{}
	if secretField, hasSecretField := respMap["secret"]; hasSecretField {
		secretObj, ok = secretField.(map[string]interface{})
		if !ok {
			c.logf("Warning: Secret %q 'secret' field is not a map, type: %T", name, respMap["secret"])
			return 0, false
		}
	} else {
		// Assume the response itself is the secret object
		secretObj = respMap
	}

	// Look for version information in multiple possible locations
	// 1. Try static_version.version path
	if staticVersion, ok := secretObj["static_version"].(map[string]interface{}); ok {
		if versionVal, ok := staticVersion["version"].(float64); ok {
			c.logf("Successfully extracted version %d from %q (map path: static_version.version)", int(versionVal), name)
			return int(versionVal), true
		}
	}

	// 2. Try latest_version field
	if latestVersion, ok := secretObj["latest_version"].(float64); ok {
		c.logf("Successfully extracted version %d from %q (map path: latest_version)", int(latestVersion), name)
		return int(latestVersion), true
	}

	// 3. Try direct version field
	if versionVal, ok := secretObj["version"].(float64); ok {
		c.logf("Successfully extracted version %d from %q (map path: version)", int(versionVal), name)
		return int(versionVal), true
	}

	c.logf("Warning: Couldn't find version information in response for %q", name)
	return 0, false
}

// getSecretsMetadata retrieves metadata for all secrets without fetching their values
// This is a more efficient way to check for version changes
func (c *Client) getSecretsMetadata(ctx context.Context) (map[string]int, error) {
	versions := make(map[string]int)
	pageToken := ""
	pageSize := 100 // Fetch up to 100 secrets per request

	// Check if context is already canceled
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Continue if context is not canceled
	}

	for {
		// Construct the URL with pagination parameters
		url := fmt.Sprintf("%s/organizations/%s/projects/%s/apps/%s/secrets?pagination.page_size=%d",
			c.baseURL, c.orgID, c.projectID, c.appName, pageSize)

		if pageToken != "" {
			url += fmt.Sprintf("&pagination.next_page_token=%s", pageToken)
		}

		// Create the request
		req, err := retryablehttp.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		// Associate the request with the context
		req = req.WithContext(ctx)

		// Set headers
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
		req.Header.Set("Content-Type", "application/json")

		// Make the request
		c.logf("Fetching metadata for secrets from HCP Vault Secrets (org: %s, project: %s, app: %s, page: %s)...",
			maskString(c.orgID), maskString(c.projectID), c.appName, pageToken)

		// Use doWithRetry instead of direct client.Do
		resp, err := c.doWithRetry(req)
		if err != nil {
			return nil, fmt.Errorf("failed to make request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
		}

		// Parse the response
		var apiResp struct {
			Secrets []struct {
				Name          string `json:"name"`
				Type          string `json:"type"`
				LatestVersion int    `json:"latest_version"`
				CreatedAt     string `json:"created_at"`
				StaticVersion struct {
					Version int `json:"version"`
				} `json:"static_version"`
			} `json:"secrets"`
			Pagination struct {
				NextPageToken string `json:"next_page_token"`
			} `json:"pagination"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		resp.Body.Close()

		// Process this page of results
		for _, secret := range apiResp.Secrets {
			// Use static_version.version if available, otherwise use latest_version
			version := secret.LatestVersion
			if secret.StaticVersion.Version > 0 {
				version = secret.StaticVersion.Version
			}
			versions[secret.Name] = version
			c.logf("Secret %q metadata: latest_version=%d", secret.Name, version)
		}

		c.logf("Retrieved metadata for %d secrets on this page", len(apiResp.Secrets))

		// Check if context is canceled before proceeding to next page
		select {
		case <-ctx.Done():
			return versions, ctx.Err()
		default:
			// Continue if context is not canceled
		}

		// Check if there are more pages
		if apiResp.Pagination.NextPageToken == "" {
			break // No more pages
		}

		// Set token for next page
		pageToken = apiResp.Pagination.NextPageToken
	}

	c.logf("Successfully retrieved metadata for %d secrets in total", len(versions))
	return versions, nil
}

func main() {
	// Set custom usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <secret-name>... or\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s [options] --template=<file> --output=<file> or\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s --agent --config=<file>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -a, --agent           Run in agent mode\n")
		fmt.Fprintf(os.Stderr, "  -c, --config=<file>   Path to agent configuration file (required with agent)\n")
		fmt.Fprintf(os.Stderr, "  -h, --help            Show this help message\n")
		fmt.Fprintf(os.Stderr, "  -o, --output=<file>   Path to output file (required with template)\n")
		fmt.Fprintf(os.Stderr, "  -r, --response        Output full API response\n")
		fmt.Fprintf(os.Stderr, "  -t, --template=<file> Path to template file\n")
		fmt.Fprintf(os.Stderr, "  -v, --version         Show version information\n")
		fmt.Fprintf(os.Stderr, "  -vvv, --verbose       Enable verbose logging\n")
	}

	flag.Parse()

	// Handle version flag
	if showVersion {
		fmt.Printf("vault-secret-agent version %s\n", version)
		os.Exit(0)
	}

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

	// Validate template mode arguments
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
	} else {
		// Not in template mode, validate secret names
		secretNames := flag.Args()
		if len(secretNames) == 0 {
			fmt.Fprintf(os.Stderr, "Error: at least one secret name is required\n")
			os.Exit(1)
		}
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
		if err := client.processTemplate(ctx, template, output); err != nil {
			fmt.Fprintf(os.Stderr, "Error processing template: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Process each secret
	secretNames := flag.Args()
	for _, name := range secretNames {
		secret, err := client.getSecretWithCache(ctx, name)
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
