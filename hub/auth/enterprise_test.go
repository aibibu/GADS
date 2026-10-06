package auth

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testEnterprise() *enterpriseLogin {
	return &enterpriseLogin{origin: "https://devices.example.com", ownerSubject: "owner-sub", group: "devices-owner", flows: map[string]loginFlow{}, sessions: map[string]enterpriseSession{}}
}
func TestEnterpriseFlowBrowserBindingAndReplay(t *testing.T) {
	e := testEnterprise()
	now := time.Now()
	e.flows[opaqueHash("state")] = loginFlow{binding: opaqueHash("browser"), expires: now.Add(time.Minute)}
	if _, ok := e.takeFlow("state", "foreign-browser", now); ok {
		t.Fatal("foreign browser accepted")
	}
	if _, ok := e.takeFlow("state", "browser", now); !ok {
		t.Fatal("valid flow rejected")
	}
	if _, ok := e.takeFlow("state", "browser", now); ok {
		t.Fatal("flow replay accepted")
	}
	e.flows[opaqueHash("old")] = loginFlow{binding: opaqueHash("browser"), expires: now}
	if _, ok := e.takeFlow("old", "browser", now); ok {
		t.Fatal("expired flow accepted")
	}
}
func TestEnterpriseTicketExpiryBindingAndReplay(t *testing.T) {
	e := testEnterprise()
	now := time.Now()
	e.sessions[opaqueHash("browser")] = enterpriseSession{subject: "owner-sub", ticket: "ticket", ticketExpires: now.Add(time.Minute), expires: now.Add(time.Hour)}
	if _, ok := e.consumeTicket("foreign", "ticket", now); ok {
		t.Fatal("foreign browser accepted")
	}
	if _, ok := e.consumeTicket("browser", "wrong-ticket", now); ok {
		t.Fatal("wrong ticket accepted")
	}
	if user, ok := e.consumeTicket("browser", "ticket", now); !ok || user != "staff:owner-sub" {
		t.Fatal("valid ticket failed")
	}
	if _, ok := e.consumeTicket("browser", "ticket", now); ok {
		t.Fatal("ticket replay accepted")
	}
	e.sessions[opaqueHash("expired")] = enterpriseSession{ticket: "old", ticketExpires: now, expires: now.Add(time.Hour)}
	if _, ok := e.consumeTicket("expired", "old", now); ok {
		t.Fatal("expired ticket accepted")
	}
}
func TestEnterpriseOwnerRequiresSubjectAndGroup(t *testing.T) {
	e := testEnterprise()
	for _, tt := range []struct {
		sub     string
		groups  []string
		allowed bool
	}{
		{"owner-sub", []string{"devices-owner"}, true},
		{"other-user", []string{"devices-owner"}, false},
		{"owner-sub", nil, false},
		{"", []string{"devices-owner"}, false},
	} {
		if e.allowed(tt.sub, tt.groups) != tt.allowed {
			t.Fatal("incorrect authorization")
		}
	}
}
func TestEnterpriseGateAndNativePasswordDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previous := Enterprise
	Enterprise = testEnterprise()
	defer func() { Enterprise = previous }()
	r := gin.New()
	r.Use(EnterpriseGate())
	r.GET("/available-devices", func(c *gin.Context) { c.Status(200) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/available-devices?workspaceId=private", nil)
	r.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatal("private SSE exposed")
	}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/authenticate", nil)
	c.Request.Header.Set("Origin", Enterprise.origin)
	if _, err := EnterpriseCredentials(c, AuthCreds{Username: "admin", Password: "password"}); err == nil {
		t.Fatal("native password accepted")
	}
	r.NoRoute(func(c *gin.Context) { c.Status(404) })
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Aibibu 企业账号") {
		t.Fatal("missing enterprise entry")
	}
}
