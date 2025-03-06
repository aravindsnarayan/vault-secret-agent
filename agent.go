package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	config            AgentConfig
	client            *Client
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	versionCheckStop  chan struct{}        // Channel to stop version checking
	templateWatchStop chan struct{}        // Channel to stop template watching
	templateModTimes  map[string]time.Time // Map to track template modification times
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

// getConfigValueWithEnvFallback returns the value from the config if non-empty,
// otherwise returns the value from the environment variable
func getConfigValueWithEnvFallback(configValue, envName string) string {
	// If config value is empty or contains only env var placeholder, check environment
	if configValue == "" || (strings.HasPrefix(configValue, "${") && strings.HasSuffix(configValue, "}")) {
		return os.Getenv(envName)
	}
	// Otherwise return the config value (which might already have env vars expanded)
	return configValue
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

	// Create context with cancel function
	ctx, cancel := context.WithCancel(context.Background())

	// Create client
	client, err := newClient(config.Agent.Logging.Level == "debug")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("error creating client: %w", err)
	}

	// Set client fields from config, with environment variable fallbacks
	client.orgID = getConfigValueWithEnvFallback(config.Agent.HCP.OrganizationID, "HCP_ORGANIZATION_ID")
	client.projectID = getConfigValueWithEnvFallback(config.Agent.HCP.ProjectID, "HCP_PROJECT_ID")
	client.appName = getConfigValueWithEnvFallback(config.Agent.HCP.AppName, "HCP_APP_NAME")

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

	// Get client ID and secret with environment variable fallbacks
	clientID := getConfigValueWithEnvFallback(config.Agent.HCP.ClientID, "HCP_CLIENT_ID")
	clientSecret := getConfigValueWithEnvFallback(config.Agent.HCP.ClientSecret, "HCP_CLIENT_SECRET")

	// Get initial access token
	token, err := client.getAccessToken(clientID, clientSecret)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("error getting initial access token: %w", err)
	}
	client.accessToken = token

	// Initialize Agent
	agent := &Agent{
		config:            config,
		client:            client,
		ctx:               ctx,
		cancel:            cancel,
		versionCheckStop:  nil,                        // Will be initialized in Start if needed
		templateWatchStop: nil,                        // Will be initialized in Start if needed
		templateModTimes:  make(map[string]time.Time), // Initialize map for template modification times
	}

	return agent, nil
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

	// Start template file watcher
	a.templateWatchStop = make(chan struct{})
	a.wg.Add(1)
	go a.runTemplateWatcher()

	return nil
}

// Stop gracefully shuts down the agent
func (a *Agent) Stop() {
	// Stop version checker if running
	if a.versionCheckStop != nil {
		close(a.versionCheckStop)
		a.versionCheckStop = nil
	}

	// Stop template watcher if running
	if a.templateWatchStop != nil {
		close(a.templateWatchStop)
		a.templateWatchStop = nil
	}

	// Cancel context to stop all goroutines
	a.cancel()

	// Wait for all goroutines to finish
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
		now := time.Now()
		fmt.Fprintf(os.Stdout, "[%s] Re-rendering template %s after secret updates\n", now.Format(time.RFC3339), tmpl.Source)
		if err := a.renderTemplate(tmpl); err != nil {
			if a.config.Agent.Settings.ExitOnRetryFailure {
				fmt.Fprintf(os.Stderr, "[%s] Fatal error rendering template %s: %v\n", now.Format(time.RFC3339), tmpl.Source, err)
				a.Stop()
				return
			}
			fmt.Fprintf(os.Stderr, "[%s] Error rendering template %s: %v\n", now.Format(time.RFC3339), tmpl.Source, err)
		} else {
			fmt.Fprintf(os.Stdout, "[%s] Successfully re-rendered template %s to %s\n", now.Format(time.RFC3339), tmpl.Source, tmpl.Destination)
		}
	}
}

// processTemplate handles the template rendering
// It renders the template once on startup
func (a *Agent) processTemplate(tmpl TemplateConfig) {
	defer a.wg.Done()

	// Render once immediately
	now := time.Now()
	fmt.Fprintf(os.Stdout, "[%s] Initial rendering of template %s\n", now.Format(time.RFC3339), tmpl.Source)
	if err := a.renderTemplate(tmpl); err != nil {
		if a.config.Agent.Settings.ExitOnRetryFailure {
			fmt.Fprintf(os.Stderr, "[%s] Fatal error rendering template %s: %v\n", now.Format(time.RFC3339), tmpl.Source, err)
			a.Stop()
			return
		}
		fmt.Fprintf(os.Stderr, "[%s] Error rendering template %s: %v\n", now.Format(time.RFC3339), tmpl.Source, err)
	} else {
		fmt.Fprintf(os.Stdout, "[%s] Successfully rendered template %s to %s\n", now.Format(time.RFC3339), tmpl.Source, tmpl.Destination)
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

	fmt.Fprintf(os.Stdout, "[%s] Starting secret version checker (interval: %s)\n", time.Now().Format(time.RFC3339), interval)
	a.client.logf("Version checker started with interval: %s", interval)

	// Immediately run first check - ignore result since initial render is handled by processTemplate
	a.client.checkSecretVersions(a.ctx)

	// Initial render is handled by processTemplate, no need to render here

	for {
		select {
		case <-a.ctx.Done():
			fmt.Fprintf(os.Stdout, "[%s] Version checker stopping due to context cancellation\n", time.Now().Format(time.RFC3339))
			a.client.logf("Version checker stopping due to context done")
			return
		case <-a.versionCheckStop:
			fmt.Fprintf(os.Stdout, "[%s] Version checker stopping due to stop signal\n", time.Now().Format(time.RFC3339))
			a.client.logf("Version checker stopping due to stop signal")
			return
		case <-ticker.C:
			// Only log at debug level for routine checks, not to stdout
			a.client.logf("Running scheduled version check") // This goes to debug logs only

			// Check if any secrets have changed
			secretsChanged := a.client.checkSecretVersions(a.ctx)

			// Render templates only if secrets have changed
			if secretsChanged {
				now := time.Now()
				fmt.Fprintf(os.Stdout, "[%s] Secrets were updated, rendering templates\n", now.Format(time.RFC3339))
				a.client.logf("Secrets were updated, rendering templates")
				a.renderAllTemplates()
			}
		}
	}
}

// runTemplateWatcher periodically checks template files for changes
func (a *Agent) runTemplateWatcher() {
	defer a.wg.Done()

	// Log the start of the template watcher
	fmt.Fprintf(os.Stdout, "[%s] Starting template file watcher (interval: 5s)\n", time.Now().Format(time.RFC3339))

	// Create ticker for periodic checks
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Initial check for template modification times
	for _, tmpl := range a.config.Agent.Templates {
		a.checkAndUpdateTemplateModTime(tmpl)
	}

	for {
		select {
		case <-a.ctx.Done():
			fmt.Fprintf(os.Stdout, "[%s] Template watcher stopping due to context cancellation\n", time.Now().Format(time.RFC3339))
			return
		case <-a.templateWatchStop:
			fmt.Fprintf(os.Stdout, "[%s] Template watcher stopping due to stop signal\n", time.Now().Format(time.RFC3339))
			return
		case <-ticker.C:
			// Check all templates for modifications - no logging for routine checks
			for _, tmpl := range a.config.Agent.Templates {
				if a.hasTemplateChanged(tmpl) {
					now := time.Now()
					fmt.Fprintf(os.Stdout, "[%s] Template file %s has changed, re-rendering\n", now.Format(time.RFC3339), tmpl.Source)
					if err := a.renderTemplate(tmpl); err != nil {
						fmt.Fprintf(os.Stderr, "[%s] Error re-rendering template %s: %v\n", now.Format(time.RFC3339), tmpl.Source, err)
					} else {
						fmt.Fprintf(os.Stdout, "[%s] Successfully re-rendered template %s to %s\n", now.Format(time.RFC3339), tmpl.Source, tmpl.Destination)
					}
				}
			}
		}
	}
}

// hasTemplateChanged checks if a template file has been modified
func (a *Agent) hasTemplateChanged(tmpl TemplateConfig) bool {
	changed := false
	if a.checkAndUpdateTemplateModTime(tmpl) {
		changed = true
	}
	return changed
}

// checkAndUpdateTemplateModTime checks and updates the last modification time of a template file
// Returns true if the file has been modified since the last check
func (a *Agent) checkAndUpdateTemplateModTime(tmpl TemplateConfig) bool {
	info, err := os.Stat(tmpl.Source)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error checking template file %s: %v\n", tmpl.Source, err)
		return false
	}

	modTime := info.ModTime()
	lastModTime, exists := a.templateModTimes[tmpl.Source]

	// Update the stored modification time
	a.templateModTimes[tmpl.Source] = modTime

	// If this is the first check or the file has been modified
	if !exists {
		return false // First time, don't trigger a re-render
	}

	return modTime.After(lastModTime)
}
