package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

type Client struct {
	httpClient *retryablehttp.Client
	baseURL    string
	token      string
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

func newClient() (*Client, error) {
	retryClient := retryablehttp.NewClient()
	retryClient.HTTPClient = cleanhttp.DefaultClient()
	retryClient.RetryMax = 3
	retryClient.Logger = nil // Disable logging

	return &Client{
		httpClient: retryClient,
		baseURL:    hcpAPIBaseURL,
	}, nil
}

func (c *Client) getAccessToken() error {
	clientID := os.Getenv("HCP_CLIENT_ID")
	clientSecret := os.Getenv("HCP_CLIENT_SECRET")

	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("HCP_CLIENT_ID and HCP_CLIENT_SECRET must be set")
	}

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
	return nil
}

func (c *Client) doWithRetry(req *retryablehttp.Request) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// If we get an authentication error, try to refresh the token and retry once
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		if err := c.getAccessToken(); err != nil {
			return nil, fmt.Errorf("failed to refresh token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
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

	return &secretResp, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <secret-name>\n", os.Args[0])
		os.Exit(1)
	}

	secretName := os.Args[1]
	client, err := newClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	if err := client.getAccessToken(); err != nil {
		fmt.Fprintf(os.Stderr, "Error getting access token: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	secretResp, err := client.getSecret(ctx, secretName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting secret: %v\n", err)
		os.Exit(1)
	}

	// Print just the secret value
	fmt.Println(secretResp.Secret.StaticVersion.Value)
}
