package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// AgentConfig represents the top-level configuration
type AgentConfig struct {
	Agent struct {
		HCP       HCPConfig        `yaml:"hcp"`
		Settings  AgentSettings    `yaml:"settings"`
		Logging   LoggingConfig    `yaml:"logging"`
		Templates []TemplateConfig `yaml:"templates"`
	} `yaml:"agent"`
}

// HCPConfig contains HCP authentication settings
type HCPConfig struct {
	ClientID       string `yaml:"client_id"`
	ClientSecret   string `yaml:"client_secret"`
	OrganizationID string `yaml:"organization_id"`
	ProjectID      string `yaml:"project_id"`
	AppName        string `yaml:"app_name"`
}

// AgentSettings contains agent behavior configuration
type AgentSettings struct {
	ExitOnRetryFailure bool        `yaml:"exit_on_retry_failure"`
	Retry              RetryConfig `yaml:"retry"`
	Cache              Cache       `yaml:"cache"`
}

// RetryConfig contains retry settings
type RetryConfig struct {
	MaxAttempts    int           `yaml:"max_attempts"`
	BackoffInitial time.Duration `yaml:"backoff_initial"`
	BackoffMax     time.Duration `yaml:"backoff_max"`
	Jitter         bool          `yaml:"jitter"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level       string `yaml:"level"`
	Format      string `yaml:"format"`
	MaskSecrets bool   `yaml:"mask_secrets"`
}

// TemplateConfig contains template rendering settings
type TemplateConfig struct {
	Source            string `yaml:"source"`
	Destination       string `yaml:"destination"`
	ErrorOnMissingKey bool   `yaml:"error_on_missing_key"`
	CreateDirectories bool   `yaml:"create_directories"`
	Permissions       string `yaml:"permissions"`
}

// Cache represents cache configuration for the agent
type Cache struct {
	Enabled              bool          `yaml:"enabled"`
	TTL                  time.Duration `yaml:"ttl"`
	VersionCheck         bool          `yaml:"version_check"`
	VersionCheckInterval time.Duration `yaml:"version_check_interval"`
	BatchAPI             bool          `yaml:"batch_api"`
}

// Settings contains agent settings
type Settings struct {
	ReloadInterval time.Duration `yaml:"reload_interval"`
	IsConsoleUser  bool          `yaml:"is_console_user"`
	WorkerCount    int           `yaml:"worker_count"`
	Cache          Cache         `yaml:"cache"`
}

// Agent represents the vault-secret-agent process
type Agent struct {
	config           AgentConfig
	client           *Client
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	versionCheckStop chan struct{} // Channel to stop version checking
}

// expandEnvVars replaces ${VAR} or $VAR in the string according to the values
// of the current environment variables. References to undefined variables are
// replaced by the empty string.
func expandEnvVars(s string) string {
	var buf bytes.Buffer
	i := 0
	for j := 0; j < len(s); j++ {
		if s[j] == '$' && j+1 < len(s) {
			buf.WriteString(s[i:j])
			name, w := getEnvVarName(s[j+1:])
			buf.WriteString(os.Getenv(name))
			j += w
			i = j + 1
		}
	}
	buf.WriteString(s[i:])
	return buf.String()
}

// getEnvVarName returns the name of the environment variable referenced by the
// leading portion of s and the number of bytes consumed. If s does not begin with
// a reference to an environment variable, getEnvVarName returns an empty string
// and 0.
func getEnvVarName(s string) (string, int) {
	if s[0] == '{' {
		// ${VAR}
		for i := 1; i < len(s); i++ {
			if s[i] == '}' {
				return s[1:i], i + 1
			}
		}
		return "", 0
	}
	// $VAR
	for i := 0; i < len(s); i++ {
		if !isEnvVarChar(s[i]) {
			return s[:i], i
		}
	}
	return s, len(s)
}

// isEnvVarChar reports whether c is a valid character in an environment variable
// name. Environment variable names consist of alphanumeric characters and '_'.
func isEnvVarChar(c byte) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// NewAgent creates a new agent from config file
func NewAgent(configPath string) (*Agent, error) {
	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	// Expand environment variables in the config
	configStr := expandEnvVars(string(data))

	// Parse config
	var config AgentConfig
	if err := yaml.Unmarshal([]byte(configStr), &config); err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Create client
	client, err := newClient(config.Agent.Logging.Level == "debug")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("error creating client: %w", err)
	}

	// Set client fields from config
	client.orgID = config.Agent.HCP.OrganizationID
	client.projectID = config.Agent.HCP.ProjectID
	client.appName = config.Agent.HCP.AppName

	// Configure cache from settings
	if config.Agent.Settings.Cache.Enabled {
		client.secretCacheTTL = config.Agent.Settings.Cache.TTL
		client.logf("Secret caching enabled with TTL: %s", client.secretCacheTTL)

		if config.Agent.Settings.Cache.VersionCheck {
			client.logf("Secret version checking enabled with interval: %s",
				config.Agent.Settings.Cache.VersionCheckInterval)
		}

		// Configure batch API usage
		client.useBatchAPI = config.Agent.Settings.Cache.BatchAPI
		if client.useBatchAPI {
			client.logf("Batch API enabled for retrieving multiple secrets")
		} else {
			client.logf("Batch API disabled, using individual requests")
		}
	} else {
		client.secretCacheTTL = 0 // Disable cache
		client.logf("Secret caching disabled")
	}

	// Get initial access token
	token, err := client.getAccessToken(config.Agent.HCP.ClientID, config.Agent.HCP.ClientSecret)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("error getting initial access token: %w", err)
	}
	client.accessToken = token

	return &Agent{
		config:           config,
		client:           client,
		ctx:              ctx,
		cancel:           cancel,
		versionCheckStop: nil, // Will be initialized in Start if needed
	}, nil
}

// Start begins the agent process
func (a *Agent) Start() error {
	// Validate templates
	for _, tmpl := range a.config.Agent.Templates {
		if err := a.validateTemplate(tmpl); err != nil {
			return fmt.Errorf("template validation error: %w", err)
		}
	}

	// Start template processors
	for _, tmpl := range a.config.Agent.Templates {
		a.wg.Add(1)
		go a.processTemplate(tmpl)
	}

	// Start version checker if enabled
	if a.config.Agent.Settings.Cache.Enabled &&
		a.config.Agent.Settings.Cache.VersionCheck &&
		a.config.Agent.Settings.Cache.VersionCheckInterval > 0 {
		a.versionCheckStop = make(chan struct{})
		a.wg.Add(1)
		go a.runVersionChecker()
	}

	return nil
}

// Stop gracefully shuts down the agent
func (a *Agent) Stop() {
	// Stop version checker if running
	if a.versionCheckStop != nil {
		close(a.versionCheckStop)
	}

	a.cancel()
	a.wg.Wait()
}

// validateTemplate checks if template configuration is valid
func (a *Agent) validateTemplate(tmpl TemplateConfig) error {
	// Check if source exists
	if _, err := os.Stat(tmpl.Source); err != nil {
		return fmt.Errorf("template source error: %w", err)
	}

	// Check if destination directory exists or can be created
	if tmpl.CreateDirectories {
		dir := filepath.Dir(tmpl.Destination)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create destination directory: %w", err)
		}
	}

	return nil
}

// renderAllTemplates renders all templates
func (a *Agent) renderAllTemplates() {
	for _, tmpl := range a.config.Agent.Templates {
		if err := a.renderTemplate(tmpl); err != nil {
			if a.config.Agent.Settings.ExitOnRetryFailure {
				fmt.Fprintf(os.Stderr, "Fatal error rendering template: %v\n", err)
				a.Stop()
				return
			}
			fmt.Fprintf(os.Stderr, "Error rendering template: %v\n", err)
		}
	}
}

// processTemplate handles the template rendering
// It renders the template once on startup
func (a *Agent) processTemplate(tmpl TemplateConfig) {
	defer a.wg.Done()

	// Render once immediately
	if err := a.renderTemplate(tmpl); err != nil {
		if a.config.Agent.Settings.ExitOnRetryFailure {
			fmt.Fprintf(os.Stderr, "Fatal error rendering template: %v\n", err)
			a.Stop()
			return
		}
		fmt.Fprintf(os.Stderr, "Error rendering template: %v\n", err)
	}

	// No periodic rendering - templates are only rendered on startup and when secrets change
}

// renderTemplate renders a single template
func (a *Agent) renderTemplate(tmpl TemplateConfig) error {
	return a.client.processTemplate(a.ctx, tmpl.Source, tmpl.Destination)
}

// runVersionChecker periodically checks for version changes
func (a *Agent) runVersionChecker() {
	defer a.wg.Done()

	interval := a.config.Agent.Settings.Cache.VersionCheckInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	fmt.Fprintf(os.Stdout, "Starting secret version checker (interval: %s)\n", interval)
	a.client.logf("Version checker started with interval: %s", interval)

	// Immediately run first check - ignore result since initial render is handled by processTemplate
	a.client.checkSecretVersions(a.ctx)

	// Initial render is handled by processTemplate, no need to render here

	for {
		select {
		case <-a.ctx.Done():
			a.client.logf("Version checker stopping due to context done")
			return
		case <-a.versionCheckStop:
			a.client.logf("Version checker stopping due to stop signal")
			return
		case <-ticker.C:
			a.client.logf("Running scheduled version check")
			secretsChanged := a.client.checkSecretVersions(a.ctx)

			// Render templates only if secrets have changed
			if secretsChanged {
				a.client.logf("Secrets were updated, rendering templates")
				a.renderAllTemplates()
			}
		}
	}
}
