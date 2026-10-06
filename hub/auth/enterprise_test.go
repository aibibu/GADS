package auth

import (
	"GADS/common/models"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
)

func testEnterprise() *enterpriseLogin {
	return &enterpriseLogin{origin: "https://devices.example.com", ownerSubject: "owner-sub", group: "devices-owner", flows: map[string]loginFlow{}, sessions: map[string]enterpriseSession{}}
}

type enterpriseUsersStub struct {
	user     models.User
	readErr  error
	writeErr error
	written  []models.User
}

func (s *enterpriseUsersStub) GetUser(_ string) (models.User, error) {
	return s.user, s.readErr
}
func (s *enterpriseUsersStub) AddOrUpdateUser(user models.User) error {
	s.written = append(s.written, user)
	return s.writeErr
}

func TestEnterpriseUserRepeatedLoginPreservesAssignedFields(t *testing.T) {
	store := &enterpriseUsersStub{user: models.User{Username: "staff:owner-sub", Role: "admin", ID: "existing-id", WorkspaceIDs: []string{"assigned-workspace"}}}
	if err := ensureEnterpriseUser(store, "owner-sub"); err != nil {
		t.Fatal(err)
	}
	if len(store.written) != 0 || store.user.ID != "existing-id" || len(store.user.WorkspaceIDs) != 1 || store.user.WorkspaceIDs[0] != "assigned-workspace" {
		t.Fatal("repeated enterprise login rewrites existing user fields")
	}
}

func TestEnterpriseUserCreationOnlyAfterConfirmedMissingUser(t *testing.T) {
	store := &enterpriseUsersStub{readErr: mongo.ErrNoDocuments}
	if err := ensureEnterpriseUser(store, "owner-sub"); err != nil || len(store.written) != 1 {
		t.Fatal("confirmed missing enterprise user was not created")
	}
	u := store.written[0]
	if u.Username != "staff:owner-sub" || u.Role != "admin" || u.Password != "" || u.ID != "" || len(u.WorkspaceIDs) != 0 {
		t.Fatal("new enterprise user inherited unrelated fields or credentials")
	}
	readErr := errors.New("database unavailable")
	store = &enterpriseUsersStub{readErr: readErr}
	if !errors.Is(ensureEnterpriseUser(store, "owner-sub"), readErr) || len(store.written) != 0 {
		t.Fatal("failed database lookup must not overwrite or create a user")
	}
	writeErr := errors.New("write unavailable")
	store = &enterpriseUsersStub{readErr: mongo.ErrNoDocuments, writeErr: writeErr}
	if !errors.Is(ensureEnterpriseUser(store, "owner-sub"), writeErr) {
		t.Fatal("failed user creation was ignored")
	}
	for _, user := range []models.User{{Username: "staff:other-sub", Role: "admin"}, {Username: "staff:owner-sub", Role: "user"}} {
		store = &enterpriseUsersStub{user: user}
		if ensureEnterpriseUser(store, "owner-sub") == nil || len(store.written) != 0 {
			t.Fatal("existing user identity or role conflict must fail without a rewrite")
		}
	}
}

func withEnterpriseNativeAuth(t *testing.T) {
	t.Helper()
	withEmptySessions(t)
	withTestLifetimes(t, time.Hour, 8*time.Hour)
	previousCache := secretCache
	secretCache = setupTestSecretCache()
	t.Cleanup(func() { secretCache = previousCache })
}

func recordEnterpriseLogin(t *testing.T, e *enterpriseLogin, cookie, subject string) string {
	t.Helper()
	token, err := GenerateJWT("staff:"+subject, "admin", "tenant", []string{"user", "admin"}, e.origin)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.recordNativeToken(cookie, token, time.Now()); err != nil {
		t.Fatal(err)
	}
	claims, err := ValidateJWT(token, e.origin)
	if err != nil {
		t.Fatal(err)
	}
	return claims.SessionID
}

func TestEnterpriseNativeTokenMustMatchBoundBrowserAndSubject(t *testing.T) {
	withEnterpriseNativeAuth(t)
	e := testEnterprise()
	now := time.Now()
	e.sessions[opaqueHash("browser")] = enterpriseSession{subject: "owner-sub", expires: now.Add(time.Hour)}
	token, err := GenerateJWT("staff:owner-sub", "admin", "tenant", []string{"admin"}, e.origin)
	if err != nil {
		t.Fatal(err)
	}
	if e.recordNativeToken("foreign-browser", token, now) == nil {
		t.Fatal("foreign browser accepted")
	}
	if e.recordNativeToken("browser", token+"tampered", now) == nil {
		t.Fatal("invalid token signature accepted")
	}
	other, err := GenerateJWT("staff:other-sub", "admin", "tenant", []string{"admin"}, e.origin)
	if err != nil {
		t.Fatal(err)
	}
	if e.recordNativeToken("browser", other, now) == nil {
		t.Fatal("different subject accepted")
	}
	machine, err := GenerateClientCredentialsJWT("machine", "staff:owner-sub", "admin", "tenant", []string{"admin"}, e.origin)
	if err != nil {
		t.Fatal(err)
	}
	if e.recordNativeToken("browser", machine, now) == nil {
		t.Fatal("machine session accepted as a native user login")
	}
	if err := e.recordNativeToken("browser", token, now); err != nil {
		t.Fatal("valid native login rejected:", err)
	}
	if !nativeSessionMatches(e.sessions[opaqueHash("browser")].nativeSessionID, "owner-sub", now) {
		t.Fatal("native session was not bound")
	}
}

func TestEnterpriseRepeatLoginKeepsLiveSessionAndFallbackTicket(t *testing.T) {
	withEnterpriseNativeAuth(t)
	e := testEnterprise()
	now := time.Now()
	e.sessions[opaqueHash("browser")] = enterpriseSession{subject: "owner-sub", expires: now.Add(time.Hour)}
	nativeID := recordEnterpriseLogin(t, e, "browser", "owner-sub")
	newCookie := e.issueSession("owner-sub", "browser", now)
	s := e.sessions[opaqueHash(newCookie)]
	if s.nativeSessionID != nativeID || s.ticket == "" {
		t.Fatal("repeat login must retain its live native session and a fresh fallback ticket")
	}
	if _, ok := e.sessions[opaqueHash("browser")]; ok {
		t.Fatal("old browser cookie was not rotated")
	}
	if _, ok := e.consumeTicket("foreign-browser", s.ticket, now); ok {
		t.Fatal("fallback ticket accepted from another browser")
	}
	if _, ok := e.consumeTicket(newCookie, s.ticket, now); !ok {
		t.Fatal("fallback ticket must work if the UI lost its cached native token")
	}
	if _, ok := e.consumeTicket(newCookie, s.ticket, now); ok {
		t.Fatal("fallback ticket replay accepted")
	}
	replacementID := recordEnterpriseLogin(t, e, newCookie, "owner-sub")
	if replacementID == nativeID || e.sessions[opaqueHash(newCookie)].nativeSessionID != replacementID {
		t.Fatal("fallback login did not replace the recorded native session")
	}
}

func TestEnterpriseRepeatLoginRejectsUnavailableNativeSessions(t *testing.T) {
	for _, tc := range []string{"logout", "idle-expired", "absolute-expired", "different-subject", "different-native-user", "foreign-cookie", "enterprise-expired"} {
		t.Run(tc, func(t *testing.T) {
			withEnterpriseNativeAuth(t)
			e := testEnterprise()
			now := time.Now()
			e.sessions[opaqueHash("browser")] = enterpriseSession{subject: "owner-sub", expires: now.Add(time.Hour)}
			id := recordEnterpriseLogin(t, e, "browser", "owner-sub")
			subject, cookie := "owner-sub", "browser"
			switch tc {
			case "logout":
				DeleteSession(id)
			case "idle-expired":
				ageSession(t, id, 2*time.Hour, time.Hour+time.Minute)
			case "absolute-expired":
				ageSession(t, id, 9*time.Hour, time.Minute)
			case "different-subject":
				subject = "other-sub"
			case "different-native-user":
				sessionsMu.Lock()
				sessions[id].Username = "staff:other-sub"
				sessionsMu.Unlock()
			case "foreign-cookie":
				cookie = "foreign-browser"
			case "enterprise-expired":
				s := e.sessions[opaqueHash(cookie)]
				s.expires = now
				e.sessions[opaqueHash(cookie)] = s
			}
			newCookie := e.issueSession(subject, cookie, time.Now())
			s := e.sessions[opaqueHash(newCookie)]
			if s.nativeSessionID != "" || s.ticket == "" {
				t.Fatal("unavailable or mismatched session reused, or fresh login ticket missing")
			}
		})
	}
}

func TestEnterpriseReadyRequiresLiveSameIdentitySessionWithoutTouch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	withEnterpriseNativeAuth(t)
	previous := Enterprise
	e := testEnterprise()
	Enterprise = e
	t.Cleanup(func() { Enterprise = previous })
	now := time.Now()
	e.sessions[opaqueHash("browser")] = enterpriseSession{subject: "owner-sub", expires: now.Add(time.Hour)}
	r := gin.New()
	EnterpriseRoutes(r)
	ready := func(cookie string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/enterprise/ready", nil)
		req.AddCookie(&http.Cookie{Name: enterpriseCookie, Value: cookie})
		r.ServeHTTP(w, req)
		return w.Code
	}
	if ready("browser") != 401 {
		t.Fatal("consumed ticket alone is insufficient before native JWT creation succeeds")
	}
	id := recordEnterpriseLogin(t, e, "browser", "owner-sub")
	newCookie := e.issueSession("owner-sub", "browser", time.Now())
	if e.sessions[opaqueHash(newCookie)].ticket == "" || ready(newCookie) != 204 {
		t.Fatal("repeat SSO login with a live native session should be ready without another form submission")
	}
	sessionsMu.Lock()
	lastUsed := sessions[id].LastUsed
	sessionsMu.Unlock()
	if ready(newCookie) != 204 || ready("foreign-browser") != 401 {
		t.Fatal("incorrect ready result for a valid or foreign browser")
	}
	sessionsMu.Lock()
	unchanged := sessions[id].LastUsed.Equal(lastUsed)
	sessionsMu.Unlock()
	if !unchanged {
		t.Fatal("readiness polling extends the native inactivity timeout")
	}
	ageSession(t, id, 2*time.Hour, time.Hour+time.Minute)
	if ready(newCookie) != 401 {
		t.Fatal("idle-expired native session remains ready")
	}
	// A new fallback login restores readiness, but logout revokes it immediately.
	s := e.sessions[opaqueHash(newCookie)]
	if _, ok := e.consumeTicket(newCookie, s.ticket, time.Now()); !ok {
		t.Fatal("fresh fallback login ticket failed")
	}
	id = recordEnterpriseLogin(t, e, newCookie, "owner-sub")
	DeleteSession(id)
	if ready(newCookie) != 401 {
		t.Fatal("logged-out native session remains ready")
	}
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
	// An expired native JWT must be able to reach the sign-in landing page even
	// while the independent, longer enterprise cookie is still valid.
	Enterprise.sessions[opaqueHash("browser")] = enterpriseSession{subject: "owner-sub", expires: time.Now().Add(time.Hour)}
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: enterpriseCookie, Value: "browser"})
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Location") != "" {
		t.Fatal("native session expiry redirects in a loop")
	}
}
