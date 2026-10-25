package router

import (
	"GADS/common/models"
	"GADS/hub/auth"
	"GADS/hub/devices"
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Configure the real browser gate against an isolated OIDC discovery server.
// No production IdP, MongoDB, access token, or browser session is involved.
func configureEnterpriseGridTest(t *testing.T) {
	t.Helper()
	previous := auth.Enterprise
	t.Cleanup(func() { auth.Enterprise = previous })
	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer": issuer.URL, "authorization_endpoint": issuer.URL + "/authorize",
			"token_endpoint": issuer.URL + "/token", "jwks_uri": issuer.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	t.Cleanup(issuer.Close)
	previousHTTPClient := http.DefaultClient
	http.DefaultClient = issuer.Client()
	t.Cleanup(func() { http.DefaultClient = previousHTTPClient })
	secretPath := filepath.Join(t.TempDir(), "fixture-oidc-secret")
	require.NoError(t, os.WriteFile(secretPath, []byte(strings.Repeat("x", 32)), 0600))
	t.Setenv("GADS_STAFF_ISSUER", issuer.URL)
	t.Setenv("GADS_STAFF_ORIGIN", "https://gads.example.test")
	t.Setenv("GADS_STAFF_CLIENT_ID", "fixture-client")
	t.Setenv("GADS_STAFF_OWNER_SUBJECT", "fixture-owner")
	t.Setenv("GADS_STAFF_GROUP", "fixture-group")
	t.Setenv("GADS_STAFF_SECRET_FILE", secretPath)
	require.NoError(t, auth.ConfigureEnterprise())
}

type enterpriseGridStore struct{ fakeGridStore }

func (f *enterpriseGridStore) GetClientCredentialBySecret(secret string) (models.ClientCredentials, error) {
	if secret != "fixture-grid-secret" {
		return models.ClientCredentials{}, errors.New("unknown fixture credential")
	}
	return f.credential, nil
}

func TestEnterpriseGatePreservesNativeGridAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	configureEnterpriseGridTest(t)
	previousStore := gridDB
	gridDB = &enterpriseGridStore{fakeGridStore: fakeGridStore{
		credential: models.ClientCredentials{UserID: "grid-user", Tenant: "tenant-one", IsActive: true},
		workspaces: []models.Workspace{{ID: "enterprise-grid-own", Tenant: "tenant-one"}},
	}}
	t.Cleanup(func() { gridDB = previousStore })

	var providerCalls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/session") {
			body, err := readBody(r.Body)
			if err != nil || bytes.Contains(body, []byte("fixture-grid-secret")) {
				http.Error(w, "secret forwarded", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`{"value":{"sessionId":"enterprise-grid-session","capabilities":{"platformName":"iOS"}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"value":null}`))
	}))
	t.Cleanup(provider.Close)

	for _, entry := range []struct{ udid, workspace string }{
		{"enterprise-grid-own-phone", "enterprise-grid-own"},
		{"enterprise-grid-foreign-phone", "enterprise-grid-foreign"},
	} {
		device := &devices.LocalHubDevice{
			Device: models.DBDevice{UDID: entry.udid, OS: "ios", OSVersion: "18.0.0", WorkspaceID: entry.workspace},
			Host:   strings.TrimPrefix(provider.URL, "http://"), Connected: true,
			ProviderState: "live", LastUpdatedTimestamp: time.Now().UnixMilli(),
			IsAvailableForAutomation: true, AppiumEnabled: true,
		}
		devices.HubDeviceStore.Set(entry.udid, device)
		t.Cleanup(func() { devices.HubDeviceStore.Delete(entry.udid) })
	}
	t.Cleanup(func() { devices.UnregisterSession("enterprise-grid-session") })

	router := gin.New()
	router.Use(auth.EnterpriseGate())
	registerGridRoutes(router.Group("/grid"))
	router.POST("/oauth/token", OAuth2TokenEndpoint)
	for _, path := range []string{"/devices", "/credentials", "/client-credentials", "/admin", "/grid/private", "/device/phone/tap"} {
		router.Any(path, func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"private": true}) })
	}
	request := func(method, path, body, secret string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	sessionBody := func(udid, secret string) string {
		body, err := json.Marshal(gin.H{"capabilities": gin.H{"alwaysMatch": gin.H{
			"platformName": "iOS", "appium:automationName": "XCUITest", "appium:udid": udid,
			"gads:clientSecret": secret, "gads:queueTimeout": 0,
		}}})
		require.NoError(t, err)
		return string(body)
	}

	t.Run("anonymous status reveals readiness only", func(t *testing.T) {
		w := request(http.MethodGet, "/grid/status", "", "")
		require.Equal(t, http.StatusOK, w.Code)
		var body map[string]map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		assert.NotContains(t, body["value"], "devices")
		assert.NotContains(t, w.Body.String(), "enterprise-grid-own-phone")
		assert.NotContains(t, w.Body.String(), "enterprise-grid-foreign-phone")
	})
	t.Run("bad secret is rejected by the native status handler", func(t *testing.T) {
		w := request(http.MethodGet, "/grid/status", "", "wrong-secret")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid client credentials")
	})
	t.Run("new sessions still require a valid client secret", func(t *testing.T) {
		for _, secret := range []string{"", "wrong-secret"} {
			w := request(http.MethodPost, "/grid/session", sessionBody("enterprise-grid-own-phone", secret), "")
			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Contains(t, w.Body.String(), "session not created")
		}
		assert.Zero(t, providerCalls.Load())
	})
	t.Run("valid client status remains workspace scoped", func(t *testing.T) {
		w := request(http.MethodGet, "/grid/status", "", "fixture-grid-secret")
		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "enterprise-grid-own-phone")
		assert.NotContains(t, w.Body.String(), "enterprise-grid-foreign-phone")
	})
	t.Run("a foreign workspace cannot be claimed", func(t *testing.T) {
		w := request(http.MethodPost, "/grid/session", sessionBody("enterprise-grid-foreign-phone", "fixture-grid-secret"), "")
		assert.NotEqual(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "session not created")
		assert.Zero(t, providerCalls.Load())
	})
	t.Run("unknown session commands still fail", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, http.MethodDelete} {
			w := request(method, "/grid/session/unknown-session", "", "")
			assert.Equal(t, http.StatusNotFound, w.Code)
			assert.Contains(t, w.Body.String(), "invalid session id")
		}
		assert.Zero(t, providerCalls.Load())
	})
	t.Run("an authenticated native session works without a browser cookie", func(t *testing.T) {
		w := request(http.MethodPost, "/grid/session", sessionBody("enterprise-grid-own-phone", "fixture-grid-secret"), "")
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "enterprise-grid-session")
		w = request(http.MethodGet, "/grid/session/enterprise-grid-session/source", "", "")
		assert.Equal(t, http.StatusOK, w.Code)
		w = request(http.MethodDelete, "/grid/session/enterprise-grid-session", "", "")
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, int32(3), providerCalls.Load())
	})
	t.Run("OAuth credentials still reach their native validator", func(t *testing.T) {
		w := request(http.MethodPost, "/oauth/token", `{"client_id":"fixture"}`, "")
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_request")
		w = request(http.MethodGet, "/oauth/token", "", "")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
	t.Run("private APIs remain enterprise gated", func(t *testing.T) {
		for _, path := range []string{"/devices", "/credentials", "/client-credentials", "/admin", "/grid/private", "/device/phone/tap"} {
			w := request(http.MethodGet, path, "", "fixture-grid-secret")
			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.NotContains(t, w.Body.String(), "private")
		}
	})
}
