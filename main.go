package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"compress/gzip"

	"github.com/hashicorp/go-retryablehttp"
)

const (
	hcpAPIBaseURL = "https://api.cloud.hashicorp.com/secrets/2023-11-28"
	authURL       = "https://auth.hashicorp.com/oauth/token"
	version       = "0.1.0"         // Current version of the binary
	defaultTTL    = 5 * time.Minute // Default TTL for cached secrets
)

// maskString masks a string by showing only the first 4 and last 4 characters
func maskString(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// maskSensitiveData masks sensitive data in a string based on common patterns
func maskSensitiveData(s string) string {
	// Common sensitive data patterns
	patterns := []struct {
		regex       *regexp.Regexp
		maskFunc    func(string) string
		description string
	}{
		{
			// JWT tokens (base64 encoded strings with dots)
			regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`),
			maskString,
			"JWT token",
		},
		{
			// UUIDs
			regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
			maskString,
			"UUID",
		},
		{
			// API keys (common formats)
			regexp.MustCompile(`(?i)(key|token|secret)[-_]?[0-9a-f]{8,}`),
			maskString,
			"API key",
		},
		{
			// Base64 encoded strings (at least 20 chars)
			regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`),
			maskString,
			"Base64 data",
		},
		{
			// IP addresses
			regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			func(s string) string { return "***.***.***.**" },
			"IP address",
		},
		{
			// Email addresses
			regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
			func(s string) string {
				parts := strings.Split(s, "@")
				if len(parts) != 2 {
					return "****@****.***"
				}
				maskedLocal := maskString(parts[0])
				return maskedLocal + "@" + parts[1]
			},
			"email address",
		},
	}

	result := s
	for _, p := range patterns {
		result = p.regex.ReplaceAllStringFunc(result, func(match string) string {
			masked := p.maskFunc(match)
			return masked
		})
	}

	return result
}

// maskURL replaces sensitive information in URLs with masked versions
func maskURL(url string) string {
	// List of parameters to mask in URLs
	sensitiveParams := []string{
		"client_id",
		"client_secret",
		"access_token",
		"token",
		"key",
		"password",
		"secret",
		"auth",
		"credential",
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

	// Apply general sensitive data masking
	return maskSensitiveData(maskedURL)
}

// CachedSecret represents a secret stored in the cache
type CachedSecret struct {
	Secret    *SecretResponse
	ExpiresAt time.Time
}

// Cache represents a cache of secrets with TTL
type Cache struct {
	mu      sync.RWMutex
	secrets map[string]CachedSecret
	ttl     time.Duration
	enabled bool
}

// NewCache creates a new cache with the specified TTL
func NewCache(ttl time.Duration, enabled bool) *Cache {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	return &Cache{
		secrets: make(map[string]CachedSecret),
		ttl:     ttl,
		enabled: enabled,
	}
}

// Get retrieves a secret from the cache if it exists and is not expired
func (c *Cache) Get(name string) (*SecretResponse, bool) {
	if !c.enabled {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	cached, ok := c.secrets[name]
	if !ok {
		return nil, false
	}

	// Check if the secret has expired
	if time.Now().After(cached.ExpiresAt) {
		return nil, false
	}

	return cached.Secret, true
}

// Set adds a secret to the cache with the configured TTL
func (c *Cache) Set(name string, secret *SecretResponse) {
	if !c.enabled {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.secrets[name] = CachedSecret{
		Secret:    secret,
		ExpiresAt: time.Now().Add(c.ttl),
	}
}

// Clear removes all secrets from the cache
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.secrets = make(map[string]CachedSecret)
}

// ClearExpired removes all expired secrets from the cache
func (c *Cache) ClearExpired() int {
	if !c.enabled {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	count := 0

	for name, cached := range c.secrets {
		if now.After(cached.ExpiresAt) {
			delete(c.secrets, name)
			count++
		}
	}

	return count
}

// Size returns the number of secrets in the cache
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.secrets)
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
	cache       *Cache
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

// BatchSecretRequest represents a batch request for multiple secrets
type BatchSecretRequest struct {
	Names []string `json:"names"`
}

// BatchSecretResponse represents the response from a batch request
type BatchSecretResponse struct {
	Secrets map[string]struct {
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
	} `json:"secrets"`
}

// CacheConfig contains cache settings
type CacheConfig struct {
	Enabled bool          `yaml:"enabled"`
	TTL     time.Duration `yaml:"ttl"`
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

	// Create transport with optimized connection pooling
	transport := &http.Transport{
		MaxIdleConns:          100,              // Maximum number of idle connections
		MaxIdleConnsPerHost:   20,               // Increased from 10 to 20 for better connection reuse
		MaxConnsPerHost:       50,               // Limit total connections per host
		IdleConnTimeout:       90 * time.Second, // How long to keep idle connections alive
		TLSHandshakeTimeout:   10 * time.Second, // Timeout for TLS handshake
		ExpectContinueTimeout: 1 * time.Second,  // Timeout for Expect: 100-continue
		DisableCompression:    false,            // Enable compression for better performance
		ForceAttemptHTTP2:     true,             // Prefer HTTP/2 when available
	}

	// Create retryable HTTP client with optimized settings
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.RetryWaitMin = 1 * time.Second
	retryClient.RetryWaitMax = 30 * time.Second
	retryClient.Logger = nil // Disable internal logging
	retryClient.HTTPClient.Transport = transport
	retryClient.HTTPClient.Timeout = 30 * time.Second // Set overall request timeout

	// Create client with default cache settings
	client := &Client{
		baseURL:    hcpAPIBaseURL,
		httpClient: retryClient,
		verbose:    verbose,
		logger:     log.New(os.Stderr, "vault-secret-agent: ", log.LstdFlags),
		orgID:      orgID,
		projectID:  projectID,
		appName:    appName,
		cache:      NewCache(defaultTTL, true), // Enable caching by default with default TTL
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
		// Apply masking to all string arguments
		maskedArgs := make([]interface{}, len(v))
		for i, arg := range v {
			if str, ok := arg.(string); ok {
				maskedArgs[i] = maskSensitiveData(str)
			} else {
				maskedArgs[i] = arg
			}
		}
		c.logger.Printf(format, maskedArgs...)
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
	// Add request ID for better tracing
	reqID := fmt.Sprintf("%d", time.Now().UnixNano())
	req.Header.Set("X-Request-ID", reqID)

	// Add Accept-Encoding header for compression
	req.Header.Set("Accept-Encoding", "gzip")

	// Log request attempt
	c.logf("[%s] Making request to %s", reqID, maskURL(req.URL.String()))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logf("[%s] Request failed: %v", reqID, err)
		return nil, err
	}

	// Handle gzip compressed responses
	if resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		resp.Body = io.NopCloser(reader)
		if c.verbose {
			c.logf("[%s] Decompressing gzip response", reqID)
		}
	}

	// Log compression info if verbose
	if c.verbose && resp.Header.Get("Content-Encoding") != "" {
		originalSize := resp.Header.Get("X-Original-Content-Length")
		if originalSize != "" {
			compressedSize := resp.Header.Get("Content-Length")
			c.logf("[%s] Response compressed: %s -> %s bytes (%s encoding)",
				reqID, originalSize, compressedSize, resp.Header.Get("Content-Encoding"))
		}
	}

	// Handle various status codes that warrant retries
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		c.logf("[%s] Received unauthorized response, refreshing token...", reqID)
		resp.Body.Close()

		// Get new token
		token, err := c.getAccessToken(os.Getenv("HCP_CLIENT_ID"), os.Getenv("HCP_CLIENT_SECRET"))
		if err != nil {
			return nil, fmt.Errorf("failed to refresh token: %w", err)
		}
		c.accessToken = token

		// Retry request with new token
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
		c.logf("[%s] Retrying request with new token", reqID)
		return c.httpClient.Do(req)

	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		// Get retry delay from response header or use default
		retryAfter := resp.Header.Get("Retry-After")
		var delay time.Duration
		if retryAfter != "" {
			if seconds, err := strconv.Atoi(retryAfter); err == nil {
				delay = time.Duration(seconds) * time.Second
			}
		}
		if delay == 0 {
			delay = 5 * time.Second
		}

		c.logf("[%s] Rate limited, waiting %v before retry", reqID, delay)
		resp.Body.Close()
		time.Sleep(delay)

		// Retry the request
		c.logf("[%s] Retrying rate-limited request", reqID)
		return c.httpClient.Do(req)
	}

	return resp, nil
}

func (c *Client) getSecret(ctx context.Context, name string) (*SecretResponse, error) {
	// Check cache first if enabled
	if cached, found := c.cache.Get(name); found {
		c.logf("Cache hit for secret %q", name)
		return cached, nil
	}

	c.logf("Cache miss for secret %q, fetching from HCP Vault Secrets (org: %s, project: %s, app: %s)...",
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

	secret := &SecretResponse{
		Name:     name,
		Value:    apiResp.Secret.StaticVersion.Value,
		Response: apiResp,
	}

	// Add to cache
	c.cache.Set(name, secret)
	c.logf("Added secret %q to cache", name)

	return secret, nil
}

// getSecretsInBatch fetches multiple secrets in a single API call
func (c *Client) getSecretsInBatch(ctx context.Context, names []string) ([]*SecretResponse, error) {
	if len(names) == 0 {
		return nil, nil
	}

	// Check which secrets are in the cache and which need to be fetched
	var cachedSecrets []*SecretResponse
	var missingNames []string

	for _, name := range names {
		if cached, found := c.cache.Get(name); found {
			cachedSecrets = append(cachedSecrets, cached)
			c.logf("Cache hit for secret %q", name)
		} else {
			missingNames = append(missingNames, name)
		}
	}

	// If all secrets were in the cache, return them
	if len(missingNames) == 0 {
		c.logf("All %d secrets found in cache", len(names))
		return cachedSecrets, nil
	}

	c.logf("Fetching %d/%d secrets in batch mode (cache miss)", len(missingNames), len(names))

	url := fmt.Sprintf("%s/organizations/%s/projects/%s/apps/%s/secrets:batchOpen",
		hcpAPIBaseURL, c.orgID, c.projectID, c.appName)

	// Create batch request
	batchReq := BatchSecretRequest{
		Names: missingNames,
	}

	reqBody, err := json.Marshal(batchReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch request: %w", err)
	}

	req, err := retryablehttp.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create batch request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))

	// Use context
	req.WithContext(ctx)

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make batch request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("batch request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var batchResp BatchSecretResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("failed to decode batch response: %w", err)
	}

	// Convert batch response to SecretResponse array and add to cache
	var fetchedSecrets []*SecretResponse
	for _, name := range missingNames {
		if secretData, ok := batchResp.Secrets[name]; ok {
			secret := &SecretResponse{
				Name:     name,
				Value:    secretData.Secret.StaticVersion.Value,
				Response: secretData,
			}
			fetchedSecrets = append(fetchedSecrets, secret)

			// Add to cache
			c.cache.Set(name, secret)
			c.logf("Added secret %q to cache", name)
		} else {
			secret := &SecretResponse{
				Name:  name,
				Error: fmt.Errorf("secret not found in batch response"),
			}
			fetchedSecrets = append(fetchedSecrets, secret)
		}
	}

	// Combine cached and fetched secrets
	results := append(cachedSecrets, fetchedSecrets...)

	// Sort results to match the original order of names
	sortedResults := make([]*SecretResponse, len(names))
	nameToSecret := make(map[string]*SecretResponse)

	for _, secret := range results {
		nameToSecret[secret.Name] = secret
	}

	for i, name := range names {
		sortedResults[i] = nameToSecret[name]
	}

	c.logf("Successfully retrieved %d secrets (%d from cache, %d from API)",
		len(sortedResults), len(cachedSecrets), len(fetchedSecrets))
	return sortedResults, nil
}

func (c *Client) getSecrets(ctx context.Context, names []string) []*SecretResponse {
	results := make([]*SecretResponse, len(names))
	var wg sync.WaitGroup

	// Create a semaphore to limit concurrent requests
	semaphore := make(chan struct{}, 5) // Allow up to 5 concurrent requests

	c.logf("Fetching %d secrets with controlled concurrency", len(names))

	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() {
				// Release semaphore
				<-semaphore
			}()

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
	c.logf("Successfully retrieved %d secrets with controlled concurrency", len(names))
	return results
}

// bufferOutput creates a buffered writer for the given file path
func bufferOutput(path string) (*bufio.Writer, *os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open output file: %w", err)
	}
	return bufio.NewWriterSize(file, 32*1024), file, nil // 32KB buffer
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

	// Use buffered output for writing the file
	writer, file, err := bufferOutput(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Write to buffer
	if _, err := writer.WriteString(result); err != nil {
		return fmt.Errorf("failed to write to buffer: %w", err)
	}

	// Flush buffer to disk
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush buffer: %w", err)
	}

	c.logf("Successfully wrote output to %s", outputPath)
	return nil
}

// SetCacheConfig configures the client's cache
func (c *Client) SetCacheConfig(config CacheConfig) {
	c.cache = NewCache(config.TTL, config.Enabled)
	c.logf("Cache configuration updated: enabled=%v, ttl=%v", config.Enabled, config.TTL)
}

// Periodically clean up expired cache entries
func (c *Client) startCacheCleanup(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			count := c.cache.ClearExpired()
			if count > 0 {
				c.logf("Cleaned up %d expired cache entries", count)
			}
		}
	}
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

	// Create buffered stdout writer
	stdoutBuf := bufio.NewWriterSize(os.Stdout, 16*1024)
	defer stdoutBuf.Flush()

	// Handle version flag
	if showVersion {
		fmt.Fprintf(stdoutBuf, "vault-secret-agent version %s\n", version)
		stdoutBuf.Flush()
		os.Exit(0)
	}

	// Handle agent mode
	if agentMode {
		if agentConfig == "" {
			fmt.Fprintf(os.Stderr, "Error: --config=<file> is required when using --agent\n")
			os.Exit(1)
		}

		// Create agent
		agent, err := NewAgent(agentConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating agent: %v\n", err)
			os.Exit(1)
		}

		// Create context for the agent
		ctx := context.Background()

		// Run the agent
		if err := agent.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error running agent: %v\n", err)
			os.Exit(1)
		}

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
	if len(secretNames) > 1 {
		// Use getSecrets for multiple secrets
		secrets := client.getSecrets(ctx, secretNames)
		for _, secret := range secrets {
			if secret.Error != nil {
				fmt.Fprintf(os.Stderr, "Error getting secret %q: %v\n", secret.Name, secret.Error)
				os.Exit(1)
			}

			if response {
				// Create a map for response output
				output := make(map[string]interface{})
				output[secret.Name] = secret.Response

				// Marshal to JSON
				jsonBytes, err := json.MarshalIndent(output, "", "  ")
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
					os.Exit(1)
				}

				// Write JSON to buffered stdout
				fmt.Fprintf(stdoutBuf, "%s\n", jsonBytes)
			} else {
				// Write key=value to buffered stdout
				fmt.Fprintf(stdoutBuf, "%s=%s\n", secret.Name, secret.Value)
			}
		}
		// Flush buffer at the end
		stdoutBuf.Flush()
		return
	}

	// Single secret case
	secret, err := client.getSecret(ctx, secretNames[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting secret: %v\n", err)
		os.Exit(1)
	}

	if response {
		// Create a map for response output
		output := make(map[string]interface{})
		output[secret.Name] = secret.Response

		// Marshal to JSON
		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			os.Exit(1)
		}

		// Write JSON to buffered stdout
		fmt.Fprintf(stdoutBuf, "%s\n", jsonBytes)
	} else {
		// Write key=value to buffered stdout
		fmt.Fprintf(stdoutBuf, "%s=%s\n", secret.Name, secret.Value)
	}

	// Flush buffer at the end
	stdoutBuf.Flush()
}
