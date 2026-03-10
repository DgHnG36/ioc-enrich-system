package iocapigatewayunit

import (
	"net/http"
	"testing"

	handler "github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/transport/grpc/handler"
	"github.com/DgHnG36/ioc-enrich-system/test/unit/services/commons"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

/* COMMAND */
func newIoCHandlerForUnitTest() *handler.IoCHandler {
	return handler.NewIoCHandler(nil, handler.NewConverter(), zap.NewNop())
}

/* COMMAND */

func TestIoCHandler_BatchUpsertIoCs_InvalidJSON(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)
	h := newIoCHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodPost, "/iocs/batch", "{")

	h.BatchUpsertIoCs(c)
	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
	resp := commons.ParseBody(t, w)
	assert.Equal(t, "Invalid request payload", resp["message"], "unexpected message: %v", resp["message"])
}

func TestIoCHandler_GetIoC_MissingIdentifier(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)
	h := newIoCHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodGet, "/iocs", "")

	h.GetIoC(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
	resp := commons.ParseBody(t, w)
	assert.Equal(t, "Either ID or Type/Value must be provided", resp["message"], "unexpected message: %v", resp["message"])
}

func TestIoCHandler_GetByValue_MissingTypeQuery(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)
	h := newIoCHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodGet, "/iocs/value/1.1.1.1", "")
	c.Params = gin.Params{{Key: "value", Value: "1.1.1.1"}}

	h.GetByValue(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
	resp := commons.ParseBody(t, w)
	assert.Equal(t, "Type query parameter is required", resp["message"], "unexpected message: %v", resp["message"])
}

func TestIoCHandler_DeleteIoCs_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newIoCHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodDelete, "/iocs/batch", "{")

	h.DeleteIoCs(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
}

func TestIoCHandler_FindIoCs_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newIoCHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodPost, "/iocs/find", "{")

	h.FindIoCs(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
}

func TestIoCHandler_GetIoCStatistics_InvalidQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newIoCHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodGet, "/iocs/stats?start_date=bad-date", "")

	h.GetIoCStatistics(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
}

func TestIoCHandler_GetExpired_InvalidQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newIoCHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodGet, "/iocs/expired?limit=abc", "")

	h.GetExpired(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
}

func TestIoCHandler_IncrementDetectionCount_InvalidURI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newIoCHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodPost, "/iocs/detect", "")

	h.IncrementDetectionCount(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
	resp := commons.ParseBody(t, w)
	assert.Equal(t, "Invalid URI parameters", resp["message"], "unexpected message: %v", resp["message"])
}

func TestIoCHandler_EnrichIoC_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newIoCHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodPost, "/iocs/enrich", "{")

	h.EnrichIoC(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
	resp := commons.ParseBody(t, w)
	assert.Equal(t, "Invalid request payload", resp["message"], "unexpected message: %v", resp["message"])
}

func TestIoCHandler_EnrichIoC_MissingIdentifier(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newIoCHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodPost, "/iocs/enrich", `{"target_sources":["virustotal"],"force_refresh":false}`)

	h.EnrichIoC(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
	resp := commons.ParseBody(t, w)
	assert.Equal(t, "Invalid request payload", resp["message"], "unexpected message: %v", resp["message"])
}

func TestIoCHandler_GetEnrichmentStatus_InvalidURI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newIoCHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodGet, "/iocs/enrich/status", "")

	h.GetEnrichmentStatus(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
}

func TestIoCHandler_GetRelatedIoCs_InvalidURI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newIoCHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodGet, "/iocs/related", "")

	h.GetRelatedIoCs(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
}
