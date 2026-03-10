package redis

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	Host          string
	Port          int
	Password      string
	DB            int
	PoolSize      int
	MinIdleConns  int
	MaxRetries    int
	DialTimeout   time.Duration
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	PoolTimeout   time.Duration
	IdleTimeout   time.Duration
	MaxConnAge    time.Duration
	EnableTLS     bool
	TLSSkipVerify bool
}

func DefaultConfig() *Config {
	return &Config{
		Host:          "localhost",
		Port:          6379,
		Password:      "",
		DB:            0,
		PoolSize:      10,
		MinIdleConns:  2,
		MaxRetries:    3,
		DialTimeout:   5 * time.Second,
		ReadTimeout:   3 * time.Second,
		WriteTimeout:  3 * time.Second,
		PoolTimeout:   4 * time.Second,
		IdleTimeout:   5 * time.Minute,
		MaxConnAge:    0, // 0 = no limit
		EnableTLS:     false,
		TLSSkipVerify: false,
	}
}

type Connection struct {
	Client *redis.Client
	config *Config
	logger *logger.Logger
}

func NewConnection(config *Config, log *logger.Logger) (*Connection, error) {
	if config == nil {
		config = DefaultConfig()
	}

	opts := &redis.Options{
		Addr:            fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password:        config.Password,
		DB:              config.DB,
		PoolSize:        config.PoolSize,
		MinIdleConns:    config.MinIdleConns,
		MaxRetries:      config.MaxRetries,
		DialTimeout:     config.DialTimeout,
		ReadTimeout:     config.ReadTimeout,
		WriteTimeout:    config.WriteTimeout,
		PoolTimeout:     config.PoolTimeout,
		ConnMaxIdleTime: config.IdleTimeout,
		ConnMaxLifetime: config.MaxConnAge,
	}

	if config.EnableTLS {
		opts.TLSConfig = &tls.Config{
			InsecureSkipVerify: config.TLSSkipVerify,
		}
	}

	client := redis.NewClient(opts)
	conn := &Connection{
		Client: client,
		config: config,
		logger: log,
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), config.DialTimeout)
	defer cancel()

	if err := conn.Ping(ctx); err != nil {
		client.Close()
		log.Error("Failed to connect to Redis", err, logger.Fields{
			"host": config.Host,
			"port": config.Port,
			"db":   config.DB,
		})
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	log.Info("Redis connection established", logger.Fields{
		"host": config.Host,
		"port": config.Port,
		"db":   config.DB,
	})

	return conn, nil
}

func (c *Connection) Ping(ctx context.Context) error {
	return c.Client.Ping(ctx).Err()
}

func (c *Connection) HealthCheck(ctx context.Context) error {
	if err := c.Ping(ctx); err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	testKey := "_health_check_"
	if err := c.Client.Set(ctx, testKey, "ok", 5*time.Second).Err(); err != nil {
		return fmt.Errorf("write test failed: %w", err)
	}
	return nil
}

func (c *Connection) Close() error {
	if c.Client != nil {
		c.logger.Info("Closing Redis connection")
		return c.Client.Close()
	}
	return nil
}
