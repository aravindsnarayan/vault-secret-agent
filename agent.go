package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"crypto/sha256"

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

	// Store token securely
	client.accessToken = NewSecureString(token)

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

	// Clean up sensitive data
	if a.client != nil {
		a.client.Cleanup()
	}
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

	// Keep track of last modified time and content hash
	var lastModTime time.Time
	var lastContentHash string
	var lastSecretVersions = make(map[string]int)
	var lastVersionCheck = make(map[string]time.Time)
	versionCheckInterval := 30 * time.Second // Check versions every 30 seconds

	process := func() error {
		needsUpdate := false

		// Check if source file has changed
		stat, err := os.Stat(tmpl.Source)
		if err != nil {
			return fmt.Errorf("failed to stat template file: %w", err)
		}

		content, err := os.ReadFile(tmpl.Source)
		if err != nil {
			return fmt.Errorf("failed to read template: %w", err)
		}

		currentHash := fmt.Sprintf("%x", sha256.Sum256(content))

		// Always check for template changes first
		if currentHash != lastContentHash {
			fmt.Printf("Template %s content has changed, updating...\n", tmpl.Source)
			needsUpdate = true
		} else if !lastModTime.Equal(stat.ModTime()) {
			fmt.Printf("Template %s modification time has changed, updating...\n", tmpl.Source)
			needsUpdate = true
		}

		// Extract all secret names from template
		re := regexp.MustCompile(`\{\{\s*([^}\s]+)\s*}}`)
		matches := re.FindAllStringSubmatch(string(content), -1)
		secretNames := make([]string, 0, len(matches))

		for _, match := range matches {
			secretNames = append(secretNames, match[1])
		}

		if len(secretNames) > 0 {
			now := time.Now()
			secretsToCheck := make([]string, 0, len(secretNames))

			// Always check versions for all secrets periodically
			for _, name := range secretNames {
				lastCheck, exists := lastVersionCheck[name]
				if !exists || now.Sub(lastCheck) >= versionCheckInterval {
					secretsToCheck = append(secretsToCheck, name)
					lastVersionCheck[name] = now
				}
			}

			// Check versions for secrets
			if len(secretsToCheck) > 0 {
				secrets, err := a.client.getSecretsInBatch(a.ctx, secretsToCheck)
				if err != nil {
					fmt.Printf("Warning: Failed to check secret versions: %v\n", err)
				} else {
					// Check for version changes
					for _, secret := range secrets {
						if lastVersion, exists := lastSecretVersions[secret.Name]; !exists || lastVersion != secret.Version {
							fmt.Printf("Secret %s version changed from %d to %d, fetching new value...\n",
								secret.Name, lastVersion, secret.Version)

							// Fetch this specific secret's new value
							freshSecrets, err := a.client.getSecretsInBatch(a.ctx, []string{secret.Name})
							if err != nil {
								fmt.Printf("Warning: Failed to fetch updated secret %s: %v\n", secret.Name, err)
							} else if len(freshSecrets) > 0 {
								a.client.cache.Set(secret.Name, freshSecrets[0])
								lastSecretVersions[secret.Name] = freshSecrets[0].Version
								needsUpdate = true
							}
						} else {
							// Update last known version
							lastSecretVersions[secret.Name] = secret.Version
						}
					}
				}
			}
		}

		if needsUpdate {
			// Process the template using cached values
			fmt.Printf("Processing template %s -> %s\n", tmpl.Source, tmpl.Destination)
			if err := a.client.processTemplate(a.ctx, tmpl.Source, tmpl.Destination); err != nil {
				return fmt.Errorf("failed to process template: %w", err)
			}

			// Update tracking info only after successful processing
			lastModTime = stat.ModTime()
			lastContentHash = currentHash

			fmt.Printf("Successfully updated template %s\n", tmpl.Source)
		}

		return nil
	}

	// Initial render
	if err := process(); err != nil {
		fmt.Printf("Error processing template %s: %v\n", tmpl.Source, err)
	}

	// Periodic renders
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			if err := process(); err != nil {
				if a.config.Agent.NoExitOnRetry {
					fmt.Printf("Error processing template %s: %v\n", tmpl.Source, err)
				} else {
					fmt.Printf("Fatal error processing template %s: %v\n", tmpl.Source, err)
					a.Stop()
					return
				}
			}
		}
	}
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
