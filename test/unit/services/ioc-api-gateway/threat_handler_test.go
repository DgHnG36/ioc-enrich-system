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
func newThreatHandlerForUnitTest() *handler.ThreatHandler {
	return handler.NewThreatHandler(nil, handler.NewConverter(), zap.NewNop())
}

/* COMMAND */

func TestThreatHandler_GetThreat_MissingIdentifier(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)
	h := newThreatHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodGet, "/threats", "")

	h.GetThreat(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
	resp := commons.ParseBody(t, w)
	assert.Equal(t, "Either ID or Name must be provided", resp["message"], "unexpected message: %v", resp["message"])
}

func TestThreatHandler_FindThreats_InvalidJSON(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)
	h := newThreatHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodPost, "/threats/find", "{")

	h.FindThreats(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
}

func TestThreatHandler_BatchUpsertThreats_InvalidJSON(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)
	h := newThreatHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodPost, "/threats/batch", "{")

	h.BatchUpsertThreats(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
}

func TestThreatHandler_DeleteThreats_InvalidJSON(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)
	h := newThreatHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodDelete, "/threats/batch", "{")

	h.DeleteThreats(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
}

func TestThreatHandler_GetThreatStatistics_InvalidQuery(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)
	h := newThreatHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodGet, "/threats/stats?start_date=invalid", "")

	h.GetThreatStatistics(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
}

func TestThreatHandler_GetThreatsByIoC_InvalidURI(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)
	h := newThreatHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodGet, "/threats/by-ioc/not-uuid", "")
	c.Params = gin.Params{{Key: "ioc_id", Value: "not-uuid"}}

	h.GetThreatsByIoC(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
}

func TestThreatHandler_GetThreatsByTTP_MissingQuery(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)
	h := newThreatHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodGet, "/threats/by-ttp", "")

	h.GetThreatsByTTP(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
}

func TestThreatHandler_CorrelateThreat_InvalidJSON(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)
	h := newThreatHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodPost, "/threats/correlate", "{")

	h.CorrelateThreat(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
}

func TestThreatHandler_LinkIoCs_InvalidThreatID(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)
	h := newThreatHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodPost, "/threats/not-uuid/link", `{"ioc_ids":["id-1"]}`)
	c.Params = gin.Params{{Key: "id", Value: "not-uuid"}}

	h.LinkIoCs(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
}

func TestThreatHandler_UnlinkIoCs_InvalidThreatID(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)
	h := newThreatHandlerForUnitTest()
	c, w := commons.NewTestContext(http.MethodPost, "/threats/not-uuid/unlink", `{"ioc_ids":["id-1"]}`)
	c.Params = gin.Params{{Key: "id", Value: "not-uuid"}}

	h.UnlinkIoCs(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected status %d, got %d", http.StatusBadRequest, w.Code)
}
