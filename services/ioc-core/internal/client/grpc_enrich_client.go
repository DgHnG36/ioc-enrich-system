package client

import (
	"context"
	"strings"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/errors"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	enrichmentpb "github.com/DgHnG36/ioc-enrich-system/shared/go/enrichment/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

type grpcEnrichClient struct {
	conn       *grpc.ClientConn
	grpcClient enrichmentpb.EnrichmentServiceClient
	config     *EnrichmentClientConfig
	logger     *logger.Logger
}

func NewGRPCEnrichmentClient(cfg *EnrichmentClientConfig, log *logger.Logger) (EnrichClient, error) {
	if err := cfg.Validate(); err != nil {
		log.Error("Invalid enrichment client config", err)
		return nil, errors.WrapError(err, errors.ErrInvalidConfig.Code, "invalid enrichment client configuration")
	}

	dialTimeout, err := time.ParseDuration(cfg.ConnectTimeout)
	if err != nil {
		dialTimeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	conn, err := grpc.NewClient(
		cfg.Address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Error("Failed to connect to enrichment service", err, logger.Fields{
			"address": cfg.Address,
		})
		return nil, errors.WrapError(err, errors.CodeServiceUnavailable, "failed to connect to enrichment service")
	}

	conn.Connect()

	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			break
		}

		if !conn.WaitForStateChange(ctx, state) {
			_ = conn.Close()
			log.Error("Timeout to connect to enrichment service", err, logger.Fields{
				"address": cfg.Address,
				"timeout": dialTimeout,
			})
			return nil, errors.ErrTimeout.Clone().WithMessage("timeout connect to enrichment service")
		}
	}

	log.Info("Connected to enrichment service successfully", logger.Fields{
		"address": cfg.Address,
	})

	return &grpcEnrichClient{
		conn:       conn,
		grpcClient: enrichmentpb.NewEnrichmentServiceClient(conn),
		config:     cfg,
		logger:     log,
	}, nil
}

func (c *grpcEnrichClient) Close() error {
	if c.conn != nil {
		c.logger.Info("Closing enrichment client connection")
		return c.conn.Close()
	}
	return nil
}

/* IMPLEMENT INTERFACE */

func (c *grpcEnrichClient) EnrichIP(ctx context.Context, ip string, sources []string) (*enrichmentpb.EnrichIPResponse, error) {
	ctx = c.config.addMetadata(ctx)
	ctx, cancel := c.config.withTimeout(ctx)
	defer cancel()

	req := &enrichmentpb.EnrichIPRequest{
		Ip:             ip,
		Sources:        c.mapSources(sources),
		TimeoutSeconds: 30,
	}

	var resp *enrichmentpb.EnrichIPResponse
	err := c.config.withRetry(ctx, c.logger, func() error {
		var err error
		resp, err = c.grpcClient.EnrichIP(ctx, req)
		return err
	})

	if err != nil {
		c.logger.Error("Failed to enrich IP", err, logger.Fields{
			"ip": ip,
		})
		return nil, c.config.handleError(err)
	}
	return resp, nil
}

func (c *grpcEnrichClient) EnrichDomain(ctx context.Context, domain string, sources []string) (*enrichmentpb.EnrichDomainResponse, error) {
	ctx = c.config.addMetadata(ctx)
	ctx, cancel := c.config.withTimeout(ctx)
	defer cancel()

	req := &enrichmentpb.EnrichDomainRequest{
		Domain:         domain,
		Sources:        c.mapSources(sources),
		TimeoutSeconds: 30,
	}

	var resp *enrichmentpb.EnrichDomainResponse
	err := c.config.withRetry(ctx, c.logger, func() error {
		var err error
		resp, err = c.grpcClient.EnrichDomain(ctx, req)
		return err
	})

	if err != nil {
		c.logger.Error("Failed to enrich domain", err, logger.Fields{
			"domain": domain,
		})
		return nil, c.config.handleError(err)
	}
	return resp, nil
}

func (c *grpcEnrichClient) EnrichURL(ctx context.Context, url string, sources []string) (*enrichmentpb.EnrichURLResponse, error) {
	ctx = c.config.addMetadata(ctx)
	ctx, cancel := c.config.withTimeout(ctx)
	defer cancel()

	req := &enrichmentpb.EnrichURLRequest{
		Url:            url,
		Sources:        c.mapSources(sources),
		TimeoutSeconds: 30,
	}

	var resp *enrichmentpb.EnrichURLResponse
	err := c.config.withRetry(ctx, c.logger, func() error {
		var err error
		resp, err = c.grpcClient.EnrichURL(ctx, req)
		return err
	})

	if err != nil {
		c.logger.Error("Failed to enrich URL", err, logger.Fields{
			"url": url,
		})
		return nil, c.config.handleError(err)
	}
	return resp, nil
}

func (c *grpcEnrichClient) EnrichHash(ctx context.Context, hash, hash_type string, sources []string) (*enrichmentpb.EnrichHashResponse, error) {
	ctx = c.config.addMetadata(ctx)
	ctx, cancel := c.config.withTimeout(ctx)
	defer cancel()

	req := &enrichmentpb.EnrichHashRequest{
		Hash: hash,
		Options: &enrichmentpb.EnrichOptions{
			HasType:             hash_type,
			IncludeFileMetadata: false,
			ForceRefresh:        false,
		},
		Sources:        c.mapSources(sources),
		TimeoutSeconds: 30,
	}

	var resp *enrichmentpb.EnrichHashResponse
	err := c.config.withRetry(ctx, c.logger, func() error {
		var err error
		resp, err = c.grpcClient.EnrichHash(ctx, req)
		return err
	})

	if err != nil {
		c.logger.Error("Failed to enrich hash", err, logger.Fields{
			"hash":      hash,
			"hash_type": hash_type,
		})
		return nil, c.config.handleError(err)
	}
	return resp, nil
}

func (c *grpcEnrichClient) EnrichFilePath(ctx context.Context, file_path string, sources []string) (*enrichmentpb.EnrichFilePathResponse, error) {
	ctx = c.config.addMetadata(ctx)
	ctx, cancel := c.config.withTimeout(ctx)
	defer cancel()

	req := &enrichmentpb.EnrichFilePathRequest{
		FilePath:       file_path,
		Sources:        c.mapSources(sources),
		TimeoutSeconds: 30,
	}

	var resp *enrichmentpb.EnrichFilePathResponse
	err := c.config.withRetry(ctx, c.logger, func() error {
		var err error
		resp, err = c.grpcClient.EnrichFilePath(ctx, req)
		return err
	})

	if err != nil {
		c.logger.Error("Failed to enrich file path", err, logger.Fields{
			"file_path": file_path,
		})
		return nil, c.config.handleError(err)
	}

	return resp, nil
}

func (c *grpcEnrichClient) EnrichIoC(ctx context.Context, ioc *domain.IoC, sources []string) (*enrichmentpb.EnrichResponse, error) {
	ctx = c.config.addMetadata(ctx)
	ctx, cancel := c.config.withTimeout(ctx)
	defer cancel()

	req := &enrichmentpb.EnrichRequest{
		Value:   ioc.Value,
		Type:    ioc.Type.String(),
		Sources: c.mapSources(sources),
		Options: &enrichmentpb.EnrichOptions{
			HasType:             "",
			IncludeFileMetadata: false,
			ForceRefresh:        false,
		},
		TimeoutSeconds: 30,
	}

	var resp *enrichmentpb.EnrichResponse
	err := c.config.withRetry(ctx, c.logger, func() error {
		var err error
		resp, err = c.grpcClient.Enrich(ctx, req)
		return err
	})

	if err != nil {
		c.logger.Error("Failed to enrich IoC", err, logger.Fields{
			"ioc": ioc.Value,
		})
		return nil, c.config.handleError(err)
	}
	return resp, nil
}

func (c *grpcEnrichClient) EnrichBatchIoCs(ctx context.Context, iocs []*domain.IoC, sources []string) (*enrichmentpb.BatchEnrichResponse, error) {
	ctx = c.config.addMetadata(ctx)
	ctx, cancel := c.config.withTimeout(ctx)
	defer cancel()

	var enrichRequests []*enrichmentpb.EnrichRequest
	for _, ioc := range iocs {
		enrichRequests = append(enrichRequests, &enrichmentpb.EnrichRequest{
			Value:   ioc.Value,
			Type:    ioc.Type.String(),
			Sources: c.mapSources(sources),
			Options: &enrichmentpb.EnrichOptions{
				HasType:             "",
				IncludeFileMetadata: false,
				ForceRefresh:        false,
			},
			TimeoutSeconds: 30,
		})
	}

	req := &enrichmentpb.BatchEnrichRequest{
		Requests:       enrichRequests,
		MaxConcurrency: 10,
	}

	var resp *enrichmentpb.BatchEnrichResponse
	err := c.config.withRetry(ctx, c.logger, func() error {
		var err error
		resp, err = c.grpcClient.EnrichBatch(ctx, req)
		return err
	})

	if err != nil {
		c.logger.Error("Failed to enrich batch IoCs", err)
		return nil, c.config.handleError(err)
	}
	return resp, nil
}

func (c *grpcEnrichClient) StreamEnrich(ctx context.Context) (enrichmentpb.EnrichmentService_StreamEnrichClient, error) {
	ctx = c.config.addMetadata(ctx)
	return c.grpcClient.StreamEnrich(ctx)
}

func (c *grpcEnrichClient) GetReputation(ctx context.Context, value, value_type string, sources []string) (*enrichmentpb.GetReputationResponse, error) {
	ctx = c.config.addMetadata(ctx)
	ctx, cancel := c.config.withTimeout(ctx)
	defer cancel()

	req := &enrichmentpb.GetReputationRequest{
		Value:   value,
		Type:    value_type,
		Sources: c.mapSources(sources),
	}

	var resp *enrichmentpb.GetReputationResponse
	err := c.config.withRetry(ctx, c.logger, func() error {
		var err error
		resp, err = c.grpcClient.GetReputation(ctx, req)
		return err
	})

	if err != nil {
		c.logger.Error("Failed to get reputation", err, logger.Fields{
			"value": value,
			"type":  value_type,
		})
		return nil, c.config.handleError(err)
	}
	return resp, nil
}

func (c *grpcEnrichClient) CheckSourceHealth(ctx context.Context, sources []string) (*enrichmentpb.CheckSourceHealthResponse, error) {
	ctx = c.config.addMetadata(ctx)
	ctx, cancel := c.config.withTimeout(ctx)
	defer cancel()

	req := &enrichmentpb.CheckSourceHealthRequest{
		Sources: c.mapSources(sources),
	}

	var resp *enrichmentpb.CheckSourceHealthResponse
	err := c.config.withRetry(ctx, c.logger, func() error {
		var err error
		resp, err = c.grpcClient.CheckSourceHealth(ctx, req)
		return err
	})

	if err != nil {
		c.logger.Error("Failed to check source health", err)
		return nil, c.config.handleError(err)
	}

	return resp, nil
}

/* HELPER METHODS */
func (c *grpcEnrichClient) mapSources(sources []string) []enrichmentpb.EnrichmentSource {
	if len(sources) == 0 {
		return nil
	}

	pbSources := make([]enrichmentpb.EnrichmentSource, 0, len(sources))
	for _, source := range sources {
		switch strings.ToLower(strings.TrimSpace(source)) {
		case "virustotal":
			pbSources = append(pbSources, enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_VIRUSTOTAL)
		case "abuseipdb":
			pbSources = append(pbSources, enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_ABUSEIPDB)
		case "otx":
			pbSources = append(pbSources, enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_OTX)
		case "hybrid_analysis":
			pbSources = append(pbSources, enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_HYBRID_ANALYSIS)
		default:
			c.logger.Warn("Unknown enrichment source requested, ignoring", logger.Fields{
				"source": source,
			})
			continue
		}
	}
	return pbSources
}
