package client

import (
	"context"
	"fmt"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/errors"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

/* CONTEXT & METADATA HELPERS */

func (c *EnrichmentClientConfig) addMetadata(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx,
		"client_name", "ioc-core",
		"timestamp", time.Now().Format(time.RFC3339),
	)
}

func (c *EnrichmentClientConfig) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}

	timeout, err := time.ParseDuration(c.Timeout)
	if err != nil {
		timeout = 30 * time.Second
	}
	return context.WithTimeout(ctx, timeout)
}

func (c *EnrichmentClientConfig) withRetry(ctx context.Context, log *logger.Logger, fn func() error) error {
	if !c.EnableRetry || c.MaxRetries < 0 {
		return fn()
	}

	var err error
	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		err = fn()
		if err == nil {
			return err
		}

		if !c.isRetryableError(err) {
			return err
		}

		if attempt == c.MaxRetries {
			break
		}

		backoff := time.Duration(1<<attempt) * time.Second
		if backoff > 10*time.Second {
			backoff = 10 * time.Second
		}

		log.Warn("Retrying enrichment request", logger.Fields{
			"attempt":     attempt + 1,
			"max_retries": c.MaxRetries,
			"backoff":     backoff.String(),
			"error":       err.Error(),
		})

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return fmt.Errorf("failed after %d attempts: %w", c.MaxRetries, err)
}

func (c *EnrichmentClientConfig) isRetryableError(err error) bool {
	st, ok := status.FromError(err)

	if !ok {
		return false
	}

	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Internal:
		return true
	default:
		return false
	}
}

func (c *EnrichmentClientConfig) handleError(err error) error {
	if err == nil {
		return nil
	}

	st, ok := status.FromError(err)
	if !ok {
		return errors.WrapError(err, errors.CodeInternalError, "enrichment service error")
	}

	switch st.Code() {
	case codes.NotFound:
		return errors.ErrNotFound.WithMessage(st.Message())
	case codes.InvalidArgument:
		return errors.ErrInvalidInput.WithMessage(st.Message())
	case codes.DeadlineExceeded:
		return errors.ErrTimeout.WithMessage(st.Message())
	case codes.Unavailable:
		return errors.ErrServiceUnavailable.WithMessage(st.Message())
	case codes.ResourceExhausted:
		return errors.ErrRateLimited.WithMessage(st.Message())
	case codes.PermissionDenied, codes.Unauthenticated:
		return errors.ErrUnauthorized.WithMessage(st.Message())
	default:
		return errors.WrapError(fmt.Errorf(st.Message()), errors.CodeInternalError, "enrichment service internal error")
	}
}
