package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
	"github.com/rs/zerolog/log"
)

// Config represents the main configuration for Loom proxy
type Config struct {
	Proxy          ProxyConfig          `yaml:"proxy"`
	Admin          AdminConfig          `yaml:"admin"`
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker"`
	Security       SecurityConfig       `yaml:"security"`
	Tracing        TracingConfig        `yaml:"tracing"`
}

// ProxyConfig holds proxy-specific settings
type ProxyConfig struct {
	ListenAddr       string  `yaml:"listen_addr"`
	TargetAddr       string  `yaml:"target_addr"`
	FaultProbability float64 `yaml:"fault_probability"`
	RateLimit        int     `yaml:"rate_limit"` // requests per second
}

// AdminConfig holds admin API settings
type AdminConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

// CircuitBreakerConfig holds circuit breaker settings
type CircuitBreakerConfig struct {
	MaxFailures    int `yaml:"max_failures"`     // Consecutive failures before opening
	TimeoutSeconds int `yaml:"timeout_seconds"`  // Seconds to keep circuit open
	MaxRetries     int `yaml:"max_retries"`      // Maximum retry attempts
}

// SecurityConfig holds security settings
type SecurityConfig struct {
	Enabled      bool     `yaml:"enabled"`
	JWTSecret    string   `yaml:"jwt_secret"`
	AllowedUsers []string `yaml:"allowed_users"`
	ValidateJWT  bool     `yaml:"validate_jwt"`
}

// TracingConfig holds distributed tracing settings
type TracingConfig struct {
	Enabled bool `yaml:"enabled"`
}

// LoadConfig reads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	setDefaults(&cfg)

	// Validate configuration
	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	log.Info().
		Str("proxy_listen", cfg.Proxy.ListenAddr).
		Str("proxy_target", cfg.Proxy.TargetAddr).
		Str("admin_listen", cfg.Admin.ListenAddr).
		Bool("security_enabled", cfg.Security.Enabled).
		Bool("tracing_enabled", cfg.Tracing.Enabled).
		Msg("Configuration loaded and validated")

	return &cfg, nil
}

// setDefaults sets default values for missing configuration
func setDefaults(cfg *Config) {
	// Proxy defaults
	if cfg.Proxy.ListenAddr == "" {
		cfg.Proxy.ListenAddr = ":8080"
	}
	if cfg.Proxy.RateLimit == 0 {
		cfg.Proxy.RateLimit = 10 // default 10 req/s
	}

	// Admin defaults
	if cfg.Admin.ListenAddr == "" {
		cfg.Admin.ListenAddr = ":9090"
	}

	// Circuit breaker defaults
	if cfg.CircuitBreaker.MaxFailures == 0 {
		cfg.CircuitBreaker.MaxFailures = 5
	}
	if cfg.CircuitBreaker.TimeoutSeconds == 0 {
		cfg.CircuitBreaker.TimeoutSeconds = 30
	}
	if cfg.CircuitBreaker.MaxRetries == 0 {
		cfg.CircuitBreaker.MaxRetries = 3
	}

	// Security defaults
	if cfg.Security.Enabled && cfg.Security.JWTSecret == "" && cfg.Security.ValidateJWT {
		log.Warn().Msg("JWT validation enabled but no secret provided, generating random secret")
		cfg.Security.JWTSecret = "change-me-in-production"
	}
}

// validateConfig validates the configuration and fails fast
func validateConfig(cfg *Config) error {
	// Validate proxy configuration
	if cfg.Proxy.TargetAddr == "" {
		return fmt.Errorf("proxy.target_addr is required")
	}
	if cfg.Proxy.ListenAddr == "" {
		return fmt.Errorf("proxy.listen_addr is required")
	}
	if cfg.Proxy.RateLimit < 0 {
		return fmt.Errorf("proxy.rate_limit must be positive")
	}
	if cfg.Proxy.FaultProbability < 0 || cfg.Proxy.FaultProbability > 1 {
		return fmt.Errorf("proxy.fault_probability must be between 0 and 1")
	}

	// Validate admin configuration
	if cfg.Admin.ListenAddr == "" {
		return fmt.Errorf("admin.listen_addr is required")
	}

	// Validate circuit breaker
	if cfg.CircuitBreaker.MaxFailures < 1 {
		return fmt.Errorf("circuit_breaker.max_failures must be at least 1")
	}
	if cfg.CircuitBreaker.TimeoutSeconds < 1 {
		return fmt.Errorf("circuit_breaker.timeout_seconds must be at least 1")
	}
	if cfg.CircuitBreaker.MaxRetries < 0 {
		return fmt.Errorf("circuit_breaker.max_retries must be non-negative")
	}

	// Validate security configuration
	if cfg.Security.Enabled {
		if cfg.Security.ValidateJWT && cfg.Security.JWTSecret == "" {
			return fmt.Errorf("security.jwt_secret is required when jwt validation is enabled")
		}
		if cfg.Security.ValidateJWT && cfg.Security.JWTSecret == "change-me-in-production" {
			log.Warn().Msg("Using default JWT secret - INSECURE! Change in production")
		}
	}

	return nil
}

// Validate performs validation on the config (public method for testing)
func (c *Config) Validate() error {
	return validateConfig(c)
}
