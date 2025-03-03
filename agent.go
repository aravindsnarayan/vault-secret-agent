package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// AgentConfig represents the top-level configuration
type AgentConfig struct {
	HCPAuth struct {
		ClientID       string `yaml:"client_id"`
		ClientSecret   string `yaml:"client_secret"`
		OrganizationID string `yaml:"organization_id"`
		ProjectID      string `yaml:"project_id"`
		AppName        string `yaml:"app_name"`
	} `yaml:"hcp_auth"`

	Agent struct {
		RenderInterval time.Duration `yaml:"render_interval"`
		NoExitOnRetry  bool          `yaml:"no_exit_on_retry"`
		Retry          struct {
			MaxAttempts    int           `yaml:"max_attempts"`
			InitialBackoff time.Duration `yaml:"initial_backoff"`
			MaxBackoff     time.Duration `yaml:"max_backoff"`
			UseJitter      bool          `yaml:"use_jitter"`
		} `yaml:"retry"`
		Cache struct {
			Enabled bool          `yaml:"enabled"`
			TTL     time.Duration `yaml:"ttl"`
		} `yaml:"cache"`
	} `yaml:"agent"`

	Logging struct {
		Level       string `yaml:"level"`
		Format      string `yaml:"format"`
		MaskSecrets bool   `yaml:"mask_secrets"`
	} `yaml:"logging"`

	Templates []struct {
		Source             string      `yaml:"source"`
		Destination        string      `yaml:"destination"`
		ErrorOnMissingKeys bool        `yaml:"error_on_missing_keys"`
		CreateDir          bool        `yaml:"create_dir"`
		FilePerms          os.FileMode `yaml:"file_perms"`
	} `yaml:"templates"`
}

// Agent represents the vault-secret-agent process
type Agent struct {
	config AgentConfig
	client *Client
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
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
	client, err := newClient(config.Logging.Level == "debug")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("error creating client: %w", err)
	}

	// Set client fields from config
	client.orgID = config.HCPAuth.OrganizationID
	client.projectID = config.HCPAuth.ProjectID
	client.appName = config.HCPAuth.AppName

	// Configure client cache
	client.SetCacheConfig(CacheConfig{
		Enabled: config.Agent.Cache.Enabled,
		TTL:     config.Agent.Cache.TTL,
	})

	// Get initial access token
	token, err := client.getAccessToken(config.HCPAuth.ClientID, config.HCPAuth.ClientSecret)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("error getting initial access token: %w", err)
	}
	client.accessToken = token

	agent := &Agent{
		config: config,
		client: client,
		ctx:    ctx,
		cancel: cancel,
	}

	// Start cache cleanup in background
	go client.startCacheCleanup(ctx, time.Minute)

	return agent, nil
}

// Start begins the agent process
func (a *Agent) Start() error {
	// Validate templates
	for _, tmpl := range a.config.Templates {
		if err := a.validateTemplate(tmpl); err != nil {
			return fmt.Errorf("template validation error: %w", err)
		}
	}

	// Start template processors
	for _, tmpl := range a.config.Templates {
		a.wg.Add(1)
		go a.processTemplate(tmpl)
	}

	return nil
}

// Stop gracefully shuts down the agent
func (a *Agent) Stop() {
	a.cancel()
	a.wg.Wait()
}

// validateTemplate checks if template configuration is valid
func (a *Agent) validateTemplate(tmpl struct {
	Source             string      `yaml:"source"`
	Destination        string      `yaml:"destination"`
	ErrorOnMissingKeys bool        `yaml:"error_on_missing_keys"`
	CreateDir          bool        `yaml:"create_dir"`
	FilePerms          os.FileMode `yaml:"file_perms"`
}) error {
	// Check if source exists
	if _, err := os.Stat(tmpl.Source); err != nil {
		return fmt.Errorf("template source error: %w", err)
	}

	// Check if destination directory exists or can be created
	if tmpl.CreateDir {
		dir := filepath.Dir(tmpl.Destination)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create destination directory: %w", err)
		}
	}

	return nil
}

// processTemplate handles the continuous rendering of a template
func (a *Agent) processTemplate(tmpl struct {
	Source             string      `yaml:"source"`
	Destination        string      `yaml:"destination"`
	ErrorOnMissingKeys bool        `yaml:"error_on_missing_keys"`
	CreateDir          bool        `yaml:"create_dir"`
	FilePerms          os.FileMode `yaml:"file_perms"`
}) {
	defer a.wg.Done()

	ticker := time.NewTicker(a.config.Agent.RenderInterval)
	defer ticker.Stop()

	// Track the last modified time of the template file
	var lastModTime time.Time

	// Initial check of template file modification time
	if fileInfo, err := os.Stat(tmpl.Source); err == nil {
		lastModTime = fileInfo.ModTime()
	}

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			// Check if template file has been modified
			if fileInfo, err := os.Stat(tmpl.Source); err == nil {
				currentModTime := fileInfo.ModTime()
				if currentModTime.After(lastModTime) {
					// Template file has changed, invalidate cache
					a.invalidateTemplateCache(tmpl.Source)
					lastModTime = currentModTime
				}
			}

			// Log template processing start
			fmt.Printf("Processing template %s -> %s\n", tmpl.Source, tmpl.Destination)

			if err := a.renderTemplate(tmpl); err != nil {
				if a.config.Agent.NoExitOnRetry {
					fmt.Fprintf(os.Stderr, "Error rendering template: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "Fatal error rendering template: %v\n", err)
					a.Stop()
					return
				}
			} else {
				fmt.Printf("Successfully rendered template %s\n", tmpl.Source)
			}
		}
	}
}

// invalidateTemplateCache removes a template from the cache to force recompilation
func (a *Agent) invalidateTemplateCache(templatePath string) {
	a.client.templateMu.Lock()
	defer a.client.templateMu.Unlock()

	delete(a.client.templates, templatePath)
	fmt.Printf("Invalidated template cache for %s\n", templatePath)
}

// renderTemplate renders a single template
func (a *Agent) renderTemplate(tmpl struct {
	Source             string      `yaml:"source"`
	Destination        string      `yaml:"destination"`
	ErrorOnMissingKeys bool        `yaml:"error_on_missing_keys"`
	CreateDir          bool        `yaml:"create_dir"`
	FilePerms          os.FileMode `yaml:"file_perms"`
}) error {
	// Log start of template rendering
	fmt.Printf("Starting template rendering process for %s\n", tmpl.Source)
	return a.client.processTemplate(a.ctx, tmpl.Source, tmpl.Destination)
}

// Run starts the agent with the provided context
func (a *Agent) Run(ctx context.Context) error {
	// Merge the provided context with our internal one
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start the agent
	if err := a.Start(); err != nil {
		return err
	}

	// Wait for signal or context cancellation
	select {
	case <-runCtx.Done():
		fmt.Println("Context cancelled, shutting down...")
	case sig := <-sigCh:
		fmt.Printf("Received signal %s, shutting down...\n", sig)
	}

	// Stop the agent
	a.Stop()
	return nil
}
