package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/client"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/repository/postgres"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/repository/redis"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/transport/grpc"
)

type AppConfig struct {
	Environment             string
	ServiceName             string
	Version                 string
	CacheTTL                time.Duration
	EnableCache             bool
	EnableEnrichmentService bool
}

type Config struct {
	App       AppConfig
	Database  postgres.Config
	Cache     redis.Config
	GRPC      grpc.GRPCServerConfig
	EnrichSvc client.EnrichmentClientConfig
}

func DefaultConfig() *Config {
	return &Config{
		App: AppConfig{
			Environment:             "development",
			ServiceName:             "ioc-core",
			Version:                 "1.0.0",
			CacheTTL:                1 * time.Hour,
			EnableCache:             true,
			EnableEnrichmentService: true,
		},
		Database: *postgres.DefaultConfig(),
		Cache:    *redis.DefaultConfig(),
		GRPC: grpc.GRPCServerConfig{
			Host: "0.0.0.0",
			Port: 50051,
		},
		EnrichSvc: *client.DefaultEnrichmentClientConfig(),
	}
}

// LoadFromEnv loads configuration from environment variables
func LoadFromEnv() (*Config, error) {
	cfg := &Config{
		App: AppConfig{
			Environment:             getEnvOrDefault("APP_ENV", "development"),
			ServiceName:             "ioc-core",
			Version:                 getEnvOrDefault("APP_VERSION", "1.0.0"),
			CacheTTL:                getEnvAsDuration("CACHE_TTL", 1*time.Hour),
			EnableCache:             getEnvAsBool("ENABLE_CACHE", true),
			EnableEnrichmentService: getEnvAsBool("ENABLE_ENRICHMENT_SVC", true),
		},
		Database: postgres.Config{
			Host:            getEnvOrDefault("DB_HOST", "localhost"),
			Port:            getEnvAsInt("DB_PORT", 5432),
			Username:        getEnvOrDefault("DB_USERNAME", "postgres"),
			Password:        getEnvOrDefault("DB_PASSWORD", "postgres"),
			Database:        getEnvOrDefault("DB_DATABASE", "ioc_enrich_db"),
			SSLMode:         getEnvOrDefault("DB_SSL_MODE", "disable"),
			MaxOpenConns:    getEnvAsInt("DB_MAX_OPEN_CONNS", 100),
			MaxIdleConns:    getEnvAsInt("DB_MAX_IDLE_CONNS", 10),
			ConnMaxLifetime: getEnvAsDuration("DB_CONN_MAX_LIFETIME", time.Hour),
			ConnMaxIdleTime: getEnvAsDuration("DB_CONN_MAX_IDLE_TIME", 30*time.Minute),
			ConnectTimeout:  getEnvAsDuration("DB_CONNECT_TIMEOUT", 10*time.Second),
		},
		Cache: redis.Config{
			Host:          getEnvOrDefault("REDIS_HOST", "localhost"),
			Port:          getEnvAsInt("REDIS_PORT", 6379),
			Password:      getEnvOrDefault("REDIS_PASSWORD", ""),
			DB:            getEnvAsInt("REDIS_DB", 0),
			PoolSize:      getEnvAsInt("REDIS_POOL_SIZE", 100),
			MinIdleConns:  getEnvAsInt("REDIS_MIN_IDLE_CONNS", 10),
			MaxRetries:    getEnvAsInt("REDIS_MAX_RETRIES", 3),
			DialTimeout:   getEnvAsDuration("REDIS_DIAL_TIMEOUT", 5*time.Second),
			ReadTimeout:   getEnvAsDuration("REDIS_READ_TIMEOUT", 3*time.Second),
			WriteTimeout:  getEnvAsDuration("REDIS_WRITE_TIMEOUT", 3*time.Second),
			PoolTimeout:   getEnvAsDuration("REDIS_POOL_TIMEOUT", 4*time.Second),
			IdleTimeout:   getEnvAsDuration("REDIS_IDLE_TIMEOUT", 5*time.Minute),
			MaxConnAge:    getEnvAsDuration("REDIS_MAX_CONN_AGE", 0),
			EnableTLS:     getEnvAsBool("REDIS_ENABLE_TLS", false),
			TLSSkipVerify: getEnvAsBool("REDIS_TLS_SKIP_VERIFY", false),
		},
		GRPC: grpc.GRPCServerConfig{
			Host: getEnvOrDefault("GRPC_HOST", "0.0.0.0"),
			Port: getEnvAsInt("GRPC_PORT", 50051),
		},
		EnrichSvc: client.EnrichmentClientConfig{
			Address:          getEnvOrDefault("ENRICH_SVC_ADDRESS", "localhost:50052"),
			Timeout:          getEnvOrDefault("ENRICH_SVC_TIMEOUT", "10s"),
			MaxRetries:       getEnvAsInt("ENRICH_SVC_MAX_RETRIES", 3),
			EnableRetry:      getEnvAsBool("ENRICH_SVC_ENABLE_RETRY", true),
			ConnectTimeout:   getEnvOrDefault("ENRICH_SVC_CONNECT_TIMEOUT", "5s"),
			KeepAlive:        getEnvOrDefault("ENRICH_SVC_KEEP_ALIVE", "10s"),
			KeepAliveTimeout: getEnvOrDefault("ENRICH_SVC_KEEP_ALIVE_TIMEOUT", "20s"),
		},
	}

	if err := cfg.Validate(); err != nil {
		return DefaultConfig(), err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.App.ServiceName == "" {
		return fmt.Errorf("service name cannot be empty")
	}
	if c.App.Environment == "" {
		return fmt.Errorf("environment cannot be empty")
	}

	if c.Database.Host == "" {
		return fmt.Errorf("database host cannot be empty")
	}
	if c.Database.Port <= 0 || c.Database.Port > 65535 {
		return fmt.Errorf("invalid database port: %d", c.Database.Port)
	}
	if c.Database.Username == "" {
		return fmt.Errorf("database username cannot be empty")
	}
	if c.Database.Database == "" {
		return fmt.Errorf("database name cannot be empty")
	}

	if c.Cache.Host == "" {
		return fmt.Errorf("redis host cannot be empty")
	}
	if c.Cache.Port <= 0 || c.Cache.Port > 65535 {
		return fmt.Errorf("invalid redis port: %d", c.Cache.Port)
	}

	if c.GRPC.Port <= 0 || c.GRPC.Port > 65535 {
		return fmt.Errorf("invalid gRPC port: %d", c.GRPC.Port)
	}
	if c.EnrichSvc.Address == "" {
		return fmt.Errorf("enrichment service address cannot be empty")
	}

	return nil
}

func (c *Config) IsDevelopment() bool {
	return c.App.Environment == "development"
}

func (c *Config) IsProduction() bool {
	return c.App.Environment == "production"
}

func (c *Config) GetDatabaseDSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=%d",
		c.Database.Host,
		c.Database.Port,
		c.Database.Username,
		c.Database.Password,
		c.Database.Database,
		c.Database.SSLMode,
		int(c.Database.ConnectTimeout.Seconds()),
	)
}

/* HELPER METHODS */
func getEnvOrDefault(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	strValue := getEnvOrDefault(key, "")
	if strValue == "" {
		return fallback
	}

	if value, err := strconv.Atoi(strValue); err == nil {
		return value
	}
	return fallback
}

func getEnvAsDuration(key string, fallback time.Duration) time.Duration {
	if strValue, exists := os.LookupEnv(key); exists {
		if value, err := time.ParseDuration(strValue); err == nil {
			return value
		}
	}
	return fallback
}

func getEnvAsBool(key string, fallback bool) bool {
	if strValue, exists := os.LookupEnv(key); exists {
		if value, err := strconv.ParseBool(strValue); err == nil {
			return value
		}
	}
	return fallback
}

func (c *Config) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Cache.Host, c.Cache.Port)
}

func (c *Config) GetGRPCAddr() string {
	return fmt.Sprintf("%s:%d", c.GRPC.Host, c.GRPC.Port)
}
