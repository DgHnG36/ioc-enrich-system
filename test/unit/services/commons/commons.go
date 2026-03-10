package commons

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func LogTestResult(t *testing.T) {
	t.Helper()
	t.Logf("START %s", t.Name())
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("FAIL %s", t.Name())
			return
		}

		t.Logf("PASS %s", t.Name())
	})
}

func NewTestContext(method, target string, body string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Content-type", "application/json")
	c.Request = req
	return c, w
}

func ParseBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out), "failed to decode json response")
	return out
}
