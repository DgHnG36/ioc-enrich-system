package client

import (
	"context"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/errors"
	enrichmentpb "github.com/DgHnG36/ioc-enrich-system/shared/go/enrichment/v1"
)

type EnrichClient interface {
	EnrichIP(ctx context.Context, ip string, sources []string) (*enrichmentpb.EnrichIPResponse, error)
	EnrichDomain(ctx context.Context, domain string, sources []string) (*enrichmentpb.EnrichDomainResponse, error)
	EnrichURL(ctx context.Context, url string, sources []string) (*enrichmentpb.EnrichURLResponse, error)
	EnrichHash(ctx context.Context, hash, hash_type string, sources []string) (*enrichmentpb.EnrichHashResponse, error)
	EnrichFilePath(ctx context.Context, file_path string, sources []string) (*enrichmentpb.EnrichFilePathResponse, error)
	EnrichIoC(ctx context.Context, ioc *domain.IoC, sources []string) (*enrichmentpb.EnrichResponse, error)
	EnrichBatchIoCs(ctx context.Context, iocs []*domain.IoC, sources []string) (*enrichmentpb.BatchEnrichResponse, error)
	StreamEnrich(ctx context.Context) (enrichmentpb.EnrichmentService_StreamEnrichClient, error)
	GetReputation(ctx context.Context, value, value_type string, sources []string) (*enrichmentpb.GetReputationResponse, error)
	CheckSourceHealth(ctx context.Context, sources []string) (*enrichmentpb.CheckSourceHealthResponse, error)
	Close() error
}

type EnrichmentClientConfig struct {
	Address          string
	Timeout          string
	MaxRetries       int
	EnableRetry      bool
	ConnectTimeout   string
	KeepAlive        string
	KeepAliveTimeout string
}

func DefaultEnrichmentClientConfig() *EnrichmentClientConfig {
	return &EnrichmentClientConfig{
		Address:          "ti-enrichment:50052",
		Timeout:          "30s",
		MaxRetries:       3,
		EnableRetry:      true,
		ConnectTimeout:   "10s",
		KeepAlive:        "30s",
		KeepAliveTimeout: "10s",
	}
}

func (c *EnrichmentClientConfig) Validate() error {
	if c.Address == "" {
		return errors.ErrInvalidConfig.Clone().WithMessage("address cannot be empty")
	}

	if c.Timeout == "" {
		c.Timeout = "30s"
	}

	if c.MaxRetries < 0 {
		c.MaxRetries = 0
	}

	if c.ConnectTimeout == "" {
		c.ConnectTimeout = "10s"
	}

	return nil
}

type EnrichmentOptions struct {
	HashType            string
	IncludeFileMetadata bool

	ForceRefresh   bool
	TimeoutSeconds int32
}

func DefaultEnrichmentOptionsConfig() *EnrichmentOptions {
	return &EnrichmentOptions{
		HashType:            "SHA256",
		IncludeFileMetadata: false,
		ForceRefresh:        false,
		TimeoutSeconds:      30,
	}
}
