package auth

// Aibibu's OIDC adapter leaves the separately licensed GADS UI unchanged.
// A short-lived, browser-bound ticket is submitted through its normal login form.
import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"GADS/common/db"
	"GADS/common/models"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/oauth2"
)

const enterpriseCookie = "__Host-gads-staff"
const flowCookie = "__Host-gads-flow"
const ticketUsername = "aibibu-oidc-ticket"

type loginFlow struct {
	binding, nonce, verifier string
	expires                  time.Time
}
type enterpriseSession struct {
	subject, ticket, nativeSessionID string
	expires, ticketExpires           time.Time
}
type enterpriseLogin struct {
	origin, ownerSubject, group string
	oauth                       oauth2.Config
	verifier                    *oidc.IDTokenVerifier
	mu                          sync.Mutex
	flows                       map[string]loginFlow
	sessions                    map[string]enterpriseSession
}

var Enterprise *enterpriseLogin

func randomOpaque() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("secure randomness unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func opaqueHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ConfigureEnterprise is called once before the server accepts requests.
// A partially configured integration fails startup rather than enabling passwords.
func ConfigureEnterprise() error {
	issuer := os.Getenv("GADS_STAFF_ISSUER")
	if issuer == "" {
		return nil
	}
	origin := os.Getenv("GADS_STAFF_ORIGIN")
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid staff HTTPS origin")
	}
	clientID, owner, group := os.Getenv("GADS_STAFF_CLIENT_ID"), os.Getenv("GADS_STAFF_OWNER_SUBJECT"), os.Getenv("GADS_STAFF_GROUP")
	secret, err := os.ReadFile(os.Getenv("GADS_STAFF_SECRET_FILE"))
	if err != nil || len(strings.TrimSpace(string(secret))) < 32 || clientID == "" || owner == "" || group == "" {
		return errors.New("incomplete staff OIDC configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return errors.New("staff OIDC discovery unavailable")
	}
	endpoint := provider.Endpoint()
	issuerURL, _ := url.Parse(issuer)
	for _, raw := range []string{endpoint.AuthURL, endpoint.TokenURL} {
		ep, e := url.Parse(raw)
		if e != nil || ep.Scheme != "https" || ep.Host != issuerURL.Host {
			return errors.New("untrusted staff OIDC endpoint")
		}
	}
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	Enterprise = &enterpriseLogin{origin: origin, ownerSubject: owner, group: group,
		oauth:    oauth2.Config{ClientID: clientID, ClientSecret: strings.TrimSpace(string(secret)), RedirectURL: origin + "/enterprise/callback", Endpoint: endpoint, Scopes: []string{oidc.ScopeOpenID, "profile", "email"}},
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{"RS256"}}), flows: map[string]loginFlow{}, sessions: map[string]enterpriseSession{}}
	return nil
}
func setPrivateCookie(c *gin.Context, name, value string, seconds int) {
	http.SetCookie(c.Writer, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: seconds})
}
func (e *enterpriseLogin) sweepLocked(now time.Time) {
	for key, f := range e.flows {
		if !now.Before(f.expires) {
			delete(e.flows, key)
		}
	}
	for key, s := range e.sessions {
		if !now.Before(s.expires) {
			delete(e.sessions, key)
		}
	}
}
func (e *enterpriseLogin) session(c *gin.Context) (enterpriseSession, bool) {
	cookie, err := c.Cookie(enterpriseCookie)
	if err != nil {
		return enterpriseSession{}, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sweepLocked(time.Now())
	s, ok := e.sessions[opaqueHash(cookie)]
	return s, ok
}

// Provider heartbeats use the private SSH path. The public reverse proxy denies
// /provider-update; it must never be published as an unauthenticated endpoint.
func EnterpriseGate() gin.HandlerFunc {
	return func(c *gin.Context) {
		e := Enterprise
		if e == nil {
			return
		}
		path := c.Request.URL.Path
		if path == "/provider-update" || path == "/authenticate" || strings.HasPrefix(path, "/enterprise/") {
			return
		}
		_, signedIn := e.session(c)
		if path == "/" && (!signedIn || c.Query("native_login") != "1") {
			// The enterprise cookie can outlive the native GADS inactivity session.
			// A redirect to /devices here would loop after the UI discards its JWT.
			c.Status(http.StatusOK)
			staffPage(c, "Aibibu 设备中控", "使用现有 Aibibu 企业账号登录。", e.origin+"/enterprise/login")
			c.Abort()
			return
		}
		if signedIn {
			return
		}
		// Static files carry no credentials. The SPA's private data endpoints remain gated.
		if c.Request.Method == "GET" && (strings.HasPrefix(path, "/assets/") || strings.HasPrefix(path, "/static/") || strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".svg") || path == "/favicon.ico") {
			return
		}
		if c.Request.Method == "GET" && strings.Contains(c.GetHeader("Accept"), "text/html") {
			c.Redirect(302, "/")
		} else {
			c.Status(401)
		}
		c.Abort()
	}
}
func EnterpriseRoutes(r *gin.Engine) {
	if Enterprise == nil {
		return
	}
	r.GET("/enterprise/login", enterpriseStart)
	r.GET("/enterprise/callback", enterpriseCallback)
	r.GET("/enterprise/complete", enterpriseComplete)
	r.GET("/enterprise/ready", func(c *gin.Context) {
		s, ok := Enterprise.session(c)
		if !ok || !nativeSessionMatches(s.nativeSessionID, s.subject, time.Now()) {
			c.Status(401)
			return
		}
		c.Status(204)
	})
}
func staffPage(c *gin.Context, title, message, href string) {
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Frame-Options", "DENY")
	c.Header("Content-Type", "text/html; charset=utf-8")
	t := template.Must(template.New("page").Parse(`<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}}</title><style>body{font:16px system-ui;background:#f4f7fb;color:#172339;max-width:440px;margin:14vh auto;padding:24px}main{background:white;padding:32px;border-radius:16px;box-shadow:0 12px 45px #1231}h1{font-size:26px}a{display:inline-block;background:#1769d2;color:white;padding:12px 20px;border-radius:8px;text-decoration:none}</style><main><h1>{{.Title}}</h1><p>{{.Message}}</p><a href="{{.Href}}">使用 Aibibu 企业账号登录</a><p><small><a style="background:none;color:#52647e;padding:0" href="https://gads.aibibu.com/source/">GADS 源码与 Aibibu 修改（AGPL-3.0）</a></small></p></main></html>`))
	_ = t.Execute(c.Writer, map[string]string{"Title": title, "Message": message, "Href": href})
}
func enterpriseStart(c *gin.Context) {
	e := Enterprise
	if c.Request.Host != strings.TrimPrefix(e.origin, "https://") {
		c.Redirect(302, e.origin+"/enterprise/login")
		return
	}
	state, binding, nonce, verifier := randomOpaque(), randomOpaque(), randomOpaque(), oauth2.GenerateVerifier()
	e.mu.Lock()
	e.sweepLocked(time.Now())
	if len(e.flows) >= 2048 {
		e.mu.Unlock()
		c.Status(503)
		return
	}
	e.flows[opaqueHash(state)] = loginFlow{opaqueHash(binding), nonce, verifier, time.Now().Add(5 * time.Minute)}
	e.mu.Unlock()
	setPrivateCookie(c, flowCookie, binding, 300)
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.Redirect(302, e.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)))
}
func (e *enterpriseLogin) takeFlow(state, binding string, now time.Time) (loginFlow, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sweepLocked(now)
	key := opaqueHash(state)
	f, ok := e.flows[key]
	if !ok || f.binding != opaqueHash(binding) {
		return loginFlow{}, false
	}
	delete(e.flows, key)
	return f, true
}
func (e *enterpriseLogin) allowed(subject string, groups []string) bool {
	if subject == "" || subject != e.ownerSubject {
		return false
	}
	for _, group := range groups {
		if group == e.group {
			return true
		}
	}
	return false
}
func enterpriseCallback(c *gin.Context) {
	e := Enterprise
	fail := func() {
		c.Status(403)
		staffPage(c, "企业登录未完成", "请重新登录，或联系管理员确认设备中控权限。", e.origin+"/enterprise/login")
	}
	binding, _ := c.Cookie(flowCookie)
	flow, ok := e.takeFlow(c.Query("state"), binding, time.Now())
	setPrivateCookie(c, flowCookie, "", -1)
	if !ok || c.Query("code") == "" || c.Query("error") != "" {
		fail()
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	token, err := e.oauth.Exchange(ctx, c.Query("code"), oauth2.VerifierOption(flow.verifier))
	if err != nil {
		fail()
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		fail()
		return
	}
	id, err := e.verifier.Verify(ctx, raw)
	if err != nil || id.Nonce != flow.nonce {
		fail()
		return
	}
	var claims struct {
		Groups []string `json:"groups"`
		AZP    string   `json:"azp"`
	}
	if id.Claims(&claims) != nil || (len(id.Audience) > 1 && claims.AZP != e.oauth.ClientID) || (claims.AZP != "" && claims.AZP != e.oauth.ClientID) || !e.allowed(id.Subject, claims.Groups) {
		fail()
		return
	}
	// Stable issuer/subject mapping; emails never grant a role or link an account.
	if err := ensureEnterpriseUser(db.GlobalMongoStore, id.Subject); err != nil {
		c.Status(503)
		return
	}
	previousCookie, _ := c.Cookie(enterpriseCookie)
	session := e.issueSession(id.Subject, previousCookie, time.Now())
	setPrivateCookie(c, enterpriseCookie, session, 8*3600)
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.Redirect(303, "/enterprise/complete")
}

type enterpriseUserStore interface {
	GetUser(string) (models.User, error)
	AddOrUpdateUser(models.User) error
}

// Repeated OIDC login does not replace an existing user's ID, workspace
// assignments, or other fields. A failed lookup must not become an upsert.
func ensureEnterpriseUser(store enterpriseUserStore, subject string) error {
	username := "staff:" + subject
	user, err := store.GetUser(username)
	if err == nil {
		if user.Username != username || user.Role != "admin" {
			return errors.New("existing enterprise user identity or role differs")
		}
		return nil
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return err
	}
	return store.AddOrUpdateUser(models.User{Username: username, Role: "admin"})
}

// Readiness must not keep a native login alive merely by polling it. Check the
// existing session under its own lock without sliding its inactivity window.
func nativeSessionMatches(id, subject string, now time.Time) bool {
	if id == "" || subject == "" {
		return false
	}
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	s, ok := sessions[id]
	if !ok {
		return false
	}
	if sessionExpired(s, now) {
		delete(sessions, id)
		return false
	}
	return s.ClientID == "" && s.Username == "staff:"+subject
}

// Called only after the callback has verified the new ID token and access
// group. A new browser cookie and fallback ticket are issued on every login;
// only a live native session for the same verified subject can be inherited.
func (e *enterpriseLogin) issueSession(subject, previousCookie string, now time.Time) string {
	cookie, ticket := randomOpaque(), randomOpaque()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sweepLocked(now)
	s := enterpriseSession{subject: subject, ticket: ticket, expires: now.Add(8 * time.Hour), ticketExpires: now.Add(time.Minute)}
	previousKey := opaqueHash(previousCookie)
	if previous, ok := e.sessions[previousKey]; ok {
		if previous.subject == subject && nativeSessionMatches(previous.nativeSessionID, subject, now) {
			s.nativeSessionID = previous.nativeSessionID
		}
		delete(e.sessions, previousKey)
	}
	e.sessions[opaqueHash(cookie)] = s
	return cookie
}

// Bind only the server's successfully generated and signature-verified token.
// The official UI remains responsible for its token storage and login form.
func (e *enterpriseLogin) recordNativeToken(cookie, token string, now time.Time) error {
	claims, err := ValidateJWT(token, e.origin)
	if err != nil || claims.Issuer != TokenIssuer || claims.Origin != e.origin {
		return errors.New("invalid native login token")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sweepLocked(now)
	key := opaqueHash(cookie)
	s, ok := e.sessions[key]
	if !ok || s.ticket != "" || claims.Subject != "staff:"+s.subject || claims.Username != claims.Subject || !nativeSessionMatches(claims.SessionID, s.subject, now) {
		return errors.New("native login does not match enterprise session")
	}
	s.nativeSessionID = claims.SessionID
	e.sessions[key] = s
	return nil
}

func (e *enterpriseLogin) consumeTicket(cookie, ticket string, now time.Time) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sweepLocked(now)
	key := opaqueHash(cookie)
	s, ok := e.sessions[key]
	if !ok || ticket == "" || s.ticket != ticket || !now.Before(s.ticketExpires) {
		return "", false
	}
	s.ticket = ""
	e.sessions[key] = s
	return "staff:" + s.subject, true
}
func EnterpriseCredentials(c *gin.Context, creds AuthCreds) (models.User, error) {
	if creds.Username != ticketUsername || c.GetHeader("Origin") != Enterprise.origin {
		return models.User{}, errors.New("enterprise login required")
	}
	cookie, _ := c.Cookie(enterpriseCookie)
	username, ok := Enterprise.consumeTicket(cookie, creds.Password, time.Now())
	if !ok {
		return models.User{}, errors.New("invalid login ticket")
	}
	return db.GlobalMongoStore.GetUser(username)
}
func EnterpriseLogout(c *gin.Context) {
	if Enterprise == nil {
		return
	}
	cookie, _ := c.Cookie(enterpriseCookie)
	Enterprise.mu.Lock()
	delete(Enterprise.sessions, opaqueHash(cookie))
	Enterprise.mu.Unlock()
	setPrivateCookie(c, enterpriseCookie, "", -1)
}
func enterpriseComplete(c *gin.Context) {
	e := Enterprise
	s, ok := e.session(c)
	if !ok || s.ticket == "" || !time.Now().Before(s.ticketExpires) {
		c.Redirect(302, "/")
		return
	}
	nonce := randomOpaque()
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("Content-Security-Policy", fmt.Sprintf("default-src 'none'; script-src 'nonce-%s'; style-src 'unsafe-inline'; frame-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'", nonce))
	c.Header("Content-Type", "text/html; charset=utf-8")
	t := template.Must(template.New("complete").Parse(`<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Aibibu 设备中控</title><style>body{font:16px system-ui;padding:32px}iframe{width:100%;height:75vh;border:0}</style><p id="status">企业账号已验证，正在进入设备中控…</p><iframe id="native" title="设备中控登录" src="/?native_login=1"></iframe><script nonce="{{.Nonce}}">
const ticket={{.Ticket}};let submitted=false;const frame=document.getElementById('native');const started=Date.now();
const timer=setInterval(async()=>{try{const d=frame.contentDocument;if(!d)return;const pass=d.querySelector('input[type="password"]');const user=d.querySelector('input[placeholder="your.username"]')||d.querySelector('input[type="text"]');const button=[...d.querySelectorAll('button')].find(b=>b.textContent.trim().toLowerCase()==='log in');if(!submitted&&user&&pass&&button){const set=Object.getOwnPropertyDescriptor(frame.contentWindow.HTMLInputElement.prototype,'value').set;set.call(user,'aibibu-oidc-ticket');user.dispatchEvent(new frame.contentWindow.Event('input',{bubbles:true}));set.call(pass,ticket);pass.dispatchEvent(new frame.contentWindow.Event('input',{bubbles:true}));submitted=true;button.click();}if(frame.contentWindow.location.pathname==='/devices'){const r=await fetch('/enterprise/ready');if(r.ok){clearInterval(timer);location.replace('/devices');}}if(Date.now()-started>30000){clearInterval(timer);document.getElementById('status').textContent='进入中控失败，请重新企业登录。';}}catch(e){clearInterval(timer);document.getElementById('status').textContent='进入中控失败，请重新企业登录。';}},250);
</script></html>`))
	_ = t.Execute(c.Writer, map[string]string{"Nonce": nonce, "Ticket": s.ticket})
}
