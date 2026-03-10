package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	"github.com/jmoiron/sqlx"

	_ "github.com/lib/pq"
)

type Config struct {
	Host            string
	Port            int
	Username        string
	Password        string
	Database        string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	ConnectTimeout  time.Duration
}

func DefaultConfig() *Config {
	return &Config{
		Host:            "localhost",
		Port:            5432,
		Username:        "postgres",
		Password:        "",
		Database:        "ioc_enrichment_db",
		SSLMode:         "disable",
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 10 * time.Minute,
		ConnectTimeout:  10 * time.Second,
	}
}

// Connection quản lý instance DB và chứa các metadata kết nối
type Connection struct {
	DB     *sqlx.DB
	cfg    *Config
	logger *logger.Logger
}

func buildDSN(config *Config) string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=%d",
		config.Host,
		config.Port,
		config.Username,
		config.Password,
		config.Database,
		config.SSLMode,
		int(config.ConnectTimeout.Seconds()),
	)
}

// NewConnection thiết lập và kiểm tra kết nối tới PostgreSQL
func NewConnection(cfg *Config, log *logger.Logger) (*Connection, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	dsn := buildDSN(cfg)

	// Dùng sqlx.Connect (nó tự động gọi Open và Ping)
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		log.Error("Failed to connect to PostgreSQL", err, logger.Fields{
			"host":     cfg.Host,
			"port":     cfg.Port,
			"database": cfg.Database,
		})
		return &Connection{}, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	// Cấu hình Connection Pool (Cực kỳ quan trọng để chống quá tải DB)
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)

	conn := &Connection{
		DB:     db,
		cfg:    cfg,
		logger: log,
	}

	log.Info("PostgreSQL connection established successfully", logger.Fields{
		"host":     cfg.Host,
		"port":     cfg.Port,
		"database": cfg.Database,
	})

	return conn, nil
}

// HealthCheck được dùng bởi Kubernetes/Docker để xác định trạng thái DB
func (c *Connection) HealthCheck(ctx context.Context) error {
	if err := c.DB.PingContext(ctx); err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	var result int
	if err := c.DB.GetContext(ctx, &result, "SELECT 1"); err != nil {
		return fmt.Errorf("query test failed: %w", err)
	}

	return nil
}

func (c *Connection) Close() error {
	if c.DB != nil {
		c.logger.Info("Closing PostgreSQL connection pool")
		return c.DB.Close()
	}
	return nil
}
