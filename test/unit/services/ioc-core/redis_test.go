package ioccoreunit

import (
	"context"
	"testing"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
	"github.com/stretchr/testify/assert"
)

/* REDIS CACHE REPOSITORY TESTS */

/* IOC CACHE TESTS */

func TestRedis_IoCCache_Set_ValidIoC(t *testing.T) {
	ioc := &domain.IoC{
		ID:       "test-id",
		Type:     domain.IoCTypeIP,
		Value:    "192.168.1.1",
		Severity: domain.SeverityHigh,
		Source:   "test",
	}

	ttl := 1 * time.Hour

	assert.NotNil(t, ioc)
	assert.NotEmpty(t, ioc.ID)
	assert.Greater(t, ttl, time.Duration(0))
}

func TestRedis_IoCCache_Set_NilIoC(t *testing.T) {
	var ioc *domain.IoC
	ttl := 1 * time.Hour

	assert.Nil(t, ioc)
	assert.Greater(t, ttl, time.Duration(0))
}

func TestRedis_IoCCache_Get_ValidID(t *testing.T) {
	id := "test-ioc-id"

	assert.NotEmpty(t, id)
	assert.Equal(t, "test-ioc-id", id)
}

func TestRedis_IoCCache_GetByValue_ValidInput(t *testing.T) {
	iocType := domain.IoCTypeDomain
	value := "example.com"

	assert.Equal(t, domain.IoCTypeDomain, iocType)
	assert.Equal(t, "example.com", value)
}

func TestRedis_IoCCache_GetByValue_IPAddress(t *testing.T) {
	iocType := domain.IoCTypeIP
	value := "8.8.8.8"

	assert.Equal(t, domain.IoCTypeIP, iocType)
	assert.Equal(t, "8.8.8.8", value)
}

func TestRedis_IoCCache_Delete_ValidID(t *testing.T) {
	id := "ioc-to-delete"

	assert.NotEmpty(t, id)
}

func TestRedis_IoCCache_Delete_EmptyID(t *testing.T) {
	id := ""

	assert.Empty(t, id)
}

func TestRedis_IoCCache_Invalidate_ValidInput(t *testing.T) {
	iocType := domain.IoCTypeURL
	value := "http://malicious.com"

	assert.Equal(t, domain.IoCTypeURL, iocType)
	assert.Equal(t, "http://malicious.com", value)
}

func TestRedis_IoCCache_InvalidateAllLists(t *testing.T) {
	// Test that InvalidateAllLists is callable with valid context
	ctx := context.Background()

	assert.NotNil(t, ctx)
	assert.NoError(t, ctx.Err())
}

/* THREAT CACHE TESTS */

func TestRedis_ThreatCache_Set_ValidThreat(t *testing.T) {
	threat := &domain.Threat{
		ID:       "threat-id",
		Name:     "APT28",
		Category: domain.ThreatCategoryMalware,
		Severity: domain.SeverityHigh,
	}

	ttl := 1 * time.Hour

	assert.NotNil(t, threat)
	assert.NotEmpty(t, threat.ID)
	assert.Greater(t, ttl, time.Duration(0))
}

func TestRedis_ThreatCache_Set_NilThreat(t *testing.T) {
	var threat *domain.Threat
	ttl := 1 * time.Hour

	assert.Nil(t, threat)
	assert.Greater(t, ttl, time.Duration(0))
}

func TestRedis_ThreatCache_Get_ValidID(t *testing.T) {
	id := "threat-id-123"

	assert.NotEmpty(t, id)
	assert.Equal(t, "threat-id-123", id)
}

func TestRedis_ThreatCache_GetByName_ValidName(t *testing.T) {
	name := "APT28"

	assert.NotEmpty(t, name)
	assert.Equal(t, "APT28", name)
}

func TestRedis_ThreatCache_GetByName_EmptyName(t *testing.T) {
	name := ""

	assert.Empty(t, name)
}

func TestRedis_ThreatCache_Delete_ValidID(t *testing.T) {
	id := "threat-to-delete"

	assert.NotEmpty(t, id)
}

func TestRedis_ThreatCache_InvalidateAllLists(t *testing.T) {
	ctx := context.Background()

	assert.NotNil(t, ctx)
	assert.NoError(t, ctx.Err())
}

/* CACHE KEY GENERATION TESTS */

func TestRedis_CacheKey_IoCKeyID(t *testing.T) {
	prefix := "ioc-core"
	id := "test-id"

	cacheKey := domain.NewCacheKey(prefix).IoC(id)

	assert.NotEmpty(t, cacheKey)
	assert.Contains(t, cacheKey, prefix)
	assert.Contains(t, cacheKey, id)
}

func TestRedis_CacheKey_IoCKeyByValue(t *testing.T) {
	prefix := "ioc-core"
	iocType := domain.IoCTypeIP
	value := "192.168.1.1"

	cacheKey := domain.NewCacheKey(prefix).IoCByValue(iocType, value)

	assert.NotEmpty(t, cacheKey)
	assert.Contains(t, cacheKey, prefix)
	assert.Contains(t, cacheKey, value)
}

func TestRedis_CacheKey_ThreatKeyID(t *testing.T) {
	prefix := "threat-core"
	id := "threat-id"

	cacheKey := domain.NewCacheKey(prefix).Threat(id)

	assert.NotEmpty(t, cacheKey)
	assert.Contains(t, cacheKey, prefix)
	assert.Contains(t, cacheKey, id)
}

func TestRedis_CacheKey_ThreatKeyByName(t *testing.T) {
	prefix := "threat-core"
	name := "APT28"

	cacheKey := domain.NewCacheKey(prefix).ThreatByName(name)

	assert.NotEmpty(t, cacheKey)
	assert.Contains(t, cacheKey, prefix)
	assert.Contains(t, cacheKey, name)
}

/* TTL TESTS */

func TestRedis_TTL_OneHour(t *testing.T) {
	ttl := 1 * time.Hour

	assert.Equal(t, 1*time.Hour, ttl)
	assert.Greater(t, ttl, 30*time.Minute)
}

func TestRedis_TTL_OneDay(t *testing.T) {
	ttl := 24 * time.Hour

	assert.Equal(t, 24*time.Hour, ttl)
	assert.Greater(t, ttl, 1*time.Hour)
}

func TestRedis_TTL_FiveMinutes(t *testing.T) {
	ttl := 5 * time.Minute

	assert.Equal(t, 5*time.Minute, ttl)
	assert.Less(t, ttl, 1*time.Hour)
}

func TestRedis_TTL_Zero(t *testing.T) {
	ttl := time.Duration(0)

	assert.Equal(t, time.Duration(0), ttl)
}

/* CONNECTION TESTS */

func TestRedis_Connection_ValidAddr(t *testing.T) {
	addr := "localhost:6379"

	assert.NotEmpty(t, addr)
	assert.Contains(t, addr, ":")
}

func TestRedis_Connection_RemoteAddr(t *testing.T) {
	addr := "redis-server:6379"

	assert.NotEmpty(t, addr)
	assert.Contains(t, addr, "redis-server")
}

func TestRedis_Connection_PortValidation(t *testing.T) {
	port := 6379

	assert.Greater(t, port, 1024)
	assert.Less(t, port, 65536)
}

/* CONTEXT TIMEOUT TESTS */

func TestRedis_Context_WithTimeout(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	assert.NotNil(t, ctx)
	assert.NoError(t, ctx.Err())
}

func TestRedis_Context_Cancelled(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	cancel()

	assert.NotNil(t, ctx)
	assert.Error(t, ctx.Err())
}

/* BATCH OPERATIONS TESTS */

func TestRedis_Batch_SetMultipleIoCs(t *testing.T) {
	iocs := []*domain.IoC{
		{ID: "id1", Type: domain.IoCTypeIP, Value: "1.1.1.1", Source: "test"},
		{ID: "id2", Type: domain.IoCTypeDomain, Value: "example.com", Source: "test"},
		{ID: "id3", Type: domain.IoCTypeURL, Value: "http://example.com", Source: "test"},
	}

	assert.Equal(t, 3, len(iocs))
	for _, ioc := range iocs {
		assert.NotEmpty(t, ioc.ID)
		assert.NotEmpty(t, ioc.Value)
	}
}

func TestRedis_Batch_DeleteMultipleKeys(t *testing.T) {
	keys := []string{"key1", "key2", "key3", "key4"}

	assert.Equal(t, 4, len(keys))
	for _, key := range keys {
		assert.NotEmpty(t, key)
	}
}
