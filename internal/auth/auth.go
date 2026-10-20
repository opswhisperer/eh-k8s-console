// Package auth provides sign-in for the web UI and API.
//
// Several modes can be enabled together:
//
//   - oidc:   authorization code + PKCE against any OIDC provider; IdP groups map to roles.
//   - local:  bcrypt users from a file (mount a Secret, plain or synced by ExternalSecret).
//   - apikey: "Authorization: Bearer ehk_…" for scripts; only the SHA-256 of each key is stored.
//   - proxy:  identity headers from an authenticating proxy, trusted only from listed CIDRs.
//   - none:   no sign-in, for local development only.
//
// Browser sessions are an HMAC-signed cookie. State-changing requests that rely on the cookie
// must come from the app's own origin (CSRF protection); API-key requests carry no cookie and
// are exempt.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"sigs.k8s.io/yaml"

	"github.com/opswhisperer/eh-k8s-console/internal/config"
)

// Role ranks: viewer < operator < admin.
const (
	Viewer   = "viewer"
	Operator = "operator"
	Admin    = "admin"
)

func Rank(role string) int {
	switch role {
	case Admin:
		return 3
	case Operator:
		return 2
	case Viewer:
		return 1
	}
	return 0
}

// Identity is who made a request.
type Identity struct {
	User   string   `json:"user"`
	Name   string   `json:"name,omitempty"`
	Email  string   `json:"email,omitempty"`
	Role   string   `json:"role"`
	Via    string   `json:"via"` // oidc | local | apikey | proxy | none
	Groups []string `json:"groups,omitempty"`
	Exp    int64    `json:"exp,omitempty"`
	Iat    int64    `json:"iat,omitempty"`
	Jti    string   `json:"jti,omitempty"`
	// IDToken is kept for RP-initiated logout (not sent to the browser).
	IDToken string `json:"idt,omitempty"`
}

// Can reports whether the identity has at least role.
func (i *Identity) Can(role string) bool { return i != nil && Rank(i.Role) >= Rank(role) }

const (
	sessionCookie = "ehk_session"
	flowCookie    = "ehk_oidc"
	flowTTL       = 10 * time.Minute
)

type ctxKey struct{}

// From returns the request's identity (nil if anonymous).
func From(ctx context.Context) *Identity {
	i, _ := ctx.Value(ctxKey{}).(*Identity)
	return i
}

// WithIdentity attaches an identity to a context (tests, CLI).
func WithIdentity(ctx context.Context, i *Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, i)
}

type Auth struct {
	cfg     config.Auth
	baseURL *url.URL
	key     []byte
	secure  bool
	log     *slog.Logger

	oidc        *oidcState
	users       *fileStore[localUser]
	apiKeys     *fileStore[apiKey]
	proxy       []*net.IPNet
	proxySecret string
	limiter     *limiter
	validAfter  int64

	revokedMu sync.Mutex
	revoked   map[string]int64 // session id -> expiry, for logout
}

type localUser struct {
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
	Role         string `json:"role"`
}

type apiKey struct {
	Name string `json:"name"`
	Hash string `json:"hash"` // hex sha256 of the full key
	Role string `json:"role"`
}

// New builds the authenticator. It fails on configuration errors, never silently opens up.
func New(c *config.Config, log *slog.Logger) (*Auth, error) {
	a := &Auth{cfg: c.Auth, log: log, limiter: newLimiter(10, time.Minute), revoked: map[string]int64{}}
	if v := c.Auth.SessionsValidAfter; v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, fmt.Errorf("auth.sessionsValidAfter: %w", err)
		}
		a.validAfter = t.Unix()
	}
	if c.BaseURL != "" {
		u, err := url.Parse(c.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("baseURL: %w", err)
		}
		a.baseURL = u
		a.secure = u.Scheme == "https"
	}
	if len(c.Auth.Modes) == 0 {
		return nil, errors.New("auth.modes is empty: choose at least one of oidc, local, apikey, proxy (or none for local development)")
	}
	key, err := c.Auth.SessionSecret.Read()
	if err != nil {
		return nil, fmt.Errorf("auth.sessionSecret: %w", err)
	}
	needsSession := c.HasMode("oidc") || c.HasMode("local")
	switch {
	case len(key) >= 32:
		a.key = []byte(key)
	case needsSession && key != "":
		return nil, errors.New("auth.sessionSecret must be at least 32 characters")
	case needsSession:
		// Without a configured secret sessions still work but end when the pod restarts and
		// cannot be shared between replicas.
		a.key = make([]byte, 32)
		_, _ = rand.Read(a.key)
		log.Warn("auth.sessionSecret not set: using a random key, so sign-ins end when the pod restarts")
	}
	if c.HasMode("oidc") {
		secret, err := c.Auth.OIDC.ClientSecret.Read()
		if err != nil || secret == "" {
			return nil, fmt.Errorf("auth.oidc.clientSecret: %v", errOr(err, "empty"))
		}
		a.oidc = &oidcState{cfg: c.Auth.OIDC, secret: secret, redirect: strings.TrimRight(c.BaseURL, "/") + "/auth/callback"}
	}
	if c.HasMode("local") {
		a.users = &fileStore[localUser]{path: c.Auth.Local.UsersFile}
		if _, err := a.users.load(); err != nil {
			return nil, fmt.Errorf("auth.local.usersFile: %w", err)
		}
	}
	if c.HasMode("apikey") {
		a.apiKeys = &fileStore[apiKey]{path: c.Auth.APIKeys.File}
		if _, err := a.apiKeys.load(); err != nil {
			return nil, fmt.Errorf("auth.apiKeys.file: %w", err)
		}
	}
	if c.HasMode("proxy") {
		for _, cidr := range c.Auth.Proxy.TrustedCIDRs {
			_, n, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("auth.proxy.trustedCIDRs: %w", err)
			}
			a.proxy = append(a.proxy, n)
		}
		if c.Auth.Proxy.SharedSecret.Set() {
			v, err := c.Auth.Proxy.SharedSecret.Read()
			if err != nil || len(v) < 16 {
				return nil, fmt.Errorf("auth.proxy.sharedSecret: %v", errOr(err, "must be at least 16 characters"))
			}
			a.proxySecret = v
		} else {
			log.Warn("auth.proxy.sharedSecret is not set: any client inside trustedCIDRs can set identity headers. Set a shared secret or restrict the console with a NetworkPolicy.")
		}
	}
	return a, nil
}

func errOr(err error, s string) any {
	if err != nil {
		return err
	}
	return s
}

// Open reports whether sign-in is disabled (mode none).
func (a *Auth) Open() bool { return len(a.cfg.Modes) == 1 && a.cfg.Modes[0] == "none" }

func (a *Auth) has(m string) bool {
	for _, x := range a.cfg.Modes {
		if x == m {
			return true
		}
	}
	return false
}

// Authenticate returns the caller's identity, or nil.
//
// A request carrying any Authorization header is treated as an API client: it gets an identity
// only from a valid console API key, never from cookies or proxy headers. That way a proxy that
// routes Authorization-bearing requests around its own sign-in can't be used to forge identity
// headers.
func (a *Auth) Authenticate(r *http.Request) *Identity {
	if a.Open() {
		return &Identity{User: "anonymous", Role: Admin, Via: "none"}
	}
	if h := r.Header.Get("Authorization"); h != "" {
		if tok, ok := bearerToken(h); ok && a.apiKeys != nil {
			return a.checkAPIKey(tok)
		}
		return nil
	}
	if a.key != nil {
		if c, err := r.Cookie(sessionCookie); err == nil {
			if id := a.session(c.Value); id != nil {
				return id
			}
		}
	}
	if len(a.proxy) > 0 && a.fromTrustedProxy(r) && a.proxySecretOK(r) {
		if user := r.Header.Get(a.cfg.Proxy.UserHeader); user != "" {
			groups := splitGroups(r.Header.Get(a.cfg.Proxy.GroupsHeader))
			role := a.roleFor(groups, a.cfg.Proxy.Roles)
			if role == "" {
				return nil
			}
			return &Identity{User: user, Email: r.Header.Get(a.cfg.Proxy.EmailHeader), Role: role, Via: "proxy", Groups: groups}
		}
	}
	return nil
}

func bearerToken(h string) (string, bool) {
	scheme, tok, ok := strings.Cut(strings.TrimSpace(h), " ")
	if !ok || !strings.EqualFold(scheme, "bearer") {
		return "", false
	}
	return strings.TrimSpace(tok), true
}

func (a *Auth) proxySecretOK(r *http.Request) bool {
	if a.proxySecret == "" {
		return true
	}
	got := r.Header.Get(a.cfg.Proxy.SharedSecretHeader)
	return subtle.ConstantTimeCompare([]byte(got), []byte(a.proxySecret)) == 1
}

// session validates a session cookie: signature, expiry, the global cut-off, logout, and for
// local users that the account still exists (with its current role).
func (a *Auth) session(tok string) *Identity {
	var id Identity
	now := time.Now().Unix()
	if a.verify(tok, &id) != nil || now >= id.Exp || id.Iat < a.validAfter || id.Jti == "" {
		return nil
	}
	a.revokedMu.Lock()
	_, gone := a.revoked[id.Jti]
	a.revokedMu.Unlock()
	if gone {
		return nil
	}
	if id.Via == "local" {
		if a.users == nil {
			return nil
		}
		users, err := a.users.load()
		if err != nil {
			return nil
		}
		found := false
		for _, u := range users {
			if u.Username == id.User {
				found, id.Role = true, u.Role
				if id.Role == "" {
					id.Role = Viewer
				}
			}
		}
		if !found {
			return nil
		}
	}
	return &id
}

func (a *Auth) revoke(id *Identity) {
	if id == nil || id.Jti == "" {
		return
	}
	a.revokedMu.Lock()
	defer a.revokedMu.Unlock()
	now := time.Now().Unix()
	for j, exp := range a.revoked {
		if exp < now {
			delete(a.revoked, j)
		}
	}
	a.revoked[id.Jti] = id.Exp
}

// LoopbackHost reports whether a Host header names this machine (none mode answers only to these,
// which defeats DNS rebinding).
func LoopbackHost(host string) bool {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	h = strings.ToLower(strings.Trim(h, "[]"))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func splitGroups(h string) []string {
	var out []string
	for _, g := range strings.FieldsFunc(h, func(r rune) bool { return r == ',' || r == '|' }) {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

// roleFor picks the highest role any group maps to, else the default role.
func (a *Auth) roleFor(groups []string, m map[string]string) string {
	best := ""
	for _, g := range groups {
		if r := m[g]; Rank(r) > Rank(best) {
			best = r
		}
	}
	if best == "" {
		best = a.cfg.DefaultRole
	}
	return best
}

func (a *Auth) fromTrustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	for _, n := range a.proxy {
		if ip != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *Auth) checkAPIKey(key string) *Identity {
	if !strings.HasPrefix(key, "ehk_") {
		return nil
	}
	keys, err := a.apiKeys.load()
	if err != nil {
		a.log.Error("reading API keys", "err", err)
		return nil
	}
	sum := sha256.Sum256([]byte(key))
	got := hex.EncodeToString(sum[:])
	for _, k := range keys {
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(k.Hash)), []byte(got)) == 1 {
			role := k.Role
			if role == "" {
				role = Viewer
			}
			return &Identity{User: "apikey:" + k.Name, Role: role, Via: "apikey"}
		}
	}
	return nil
}

// NewAPIKey returns a fresh key and the hash to store.
func NewAPIKey() (key, hash string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	key = "ehk_" + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(key))
	return key, hex.EncodeToString(sum[:])
}

// HashPassword returns a bcrypt hash for the local users file.
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(b), err
}

// ---- signed cookies ----

func (a *Auth) sign(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

func (a *Auth) verify(tok string, v any) error {
	payload, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return errors.New("malformed")
	}
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(payload))
	want := m.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, want) {
		return errors.New("bad signature")
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (a *Auth) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", HttpOnly: true, Secure: a.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds()),
	})
}

func (a *Auth) startSession(w http.ResponseWriter, id *Identity) error {
	now := time.Now()
	id.Iat, id.Exp, id.Jti = now.Unix(), now.Add(a.cfg.SessionTTL.Duration).Unix(), randToken()
	tok, err := a.sign(id)
	if err != nil {
		return err
	}
	a.setCookie(w, sessionCookie, tok, a.cfg.SessionTTL.Duration)
	return nil
}

// ---- CSRF ----

// SameOrigin checks Origin (or Referer) against the request host or baseURL.
func (a *Auth) SameOrigin(r *http.Request) bool {
	src := r.Header.Get("Origin")
	if src == "" || src == "null" {
		src = r.Header.Get("Referer")
	}
	if src == "" {
		return false
	}
	u, err := url.Parse(src)
	if err != nil {
		return false
	}
	if a.baseURL != nil && strings.EqualFold(u.Host, a.baseURL.Host) {
		return true
	}
	return strings.EqualFold(u.Host, r.Host)
}

// ---- middleware ----

// Middleware attaches the identity to every request. With sign-in off (mode none) it answers only
// to loopback Host names, so a web page can't reach it through DNS rebinding.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.Open() && !LoopbackHost(r.Host) {
			writeErr(w, http.StatusMisdirectedRequest, "with sign-in off, this console answers only on localhost")
			return
		}
		if id := a.Authenticate(r); id != nil {
			r = r.WithContext(WithIdentity(r.Context(), id))
		}
		next.ServeHTTP(w, r)
	})
}

// Require wraps a handler so only identities with at least role get through. Unsafe methods
// authenticated by cookie must also pass the same-origin check.
func (a *Auth) Require(role string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := From(r.Context())
		if id == nil {
			writeErr(w, http.StatusUnauthorized, "sign in required")
			return
		}
		if !id.Can(role) {
			writeErr(w, http.StatusForbidden, fmt.Sprintf("this needs the %s role; you are %s", role, id.Role))
			return
		}
		unsafe := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
		// API-key requests carry no ambient credential; every other identity (cookie, proxy
		// headers, or none mode) must come from the console's own origin.
		if unsafe && id.Via != "apikey" && !a.SameOrigin(r) {
			writeErr(w, http.StatusForbidden, "cross-origin request refused")
			return
		}
		h(w, r)
	}
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ---- routes ----

// Routes registers /auth/* handlers.
func (a *Auth) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/config", a.handleConfig)
	mux.HandleFunc("GET /auth/me", a.handleMe)
	mux.HandleFunc("POST /auth/logout", a.handleLogout)
	if a.users != nil {
		mux.HandleFunc("POST /auth/login", a.handleLocalLogin)
	}
	if a.oidc != nil {
		mux.HandleFunc("GET /auth/oidc", a.handleOIDCStart)
		mux.HandleFunc("GET /auth/callback", a.handleOIDCCallback)
	}
}

func (a *Auth) handleConfig(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"modes": a.cfg.Modes, "open": a.Open()}
	if a.oidc != nil {
		out["oidcName"] = a.cfg.OIDC.DisplayName
	}
	writeJSON(w, out)
}

func (a *Auth) handleMe(w http.ResponseWriter, r *http.Request) {
	id := From(r.Context())
	if id == nil {
		writeErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	safe := *id
	safe.IDToken = ""
	writeJSON(w, safe)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (a *Auth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !a.SameOrigin(r) {
		writeErr(w, http.StatusForbidden, "cross-origin request refused")
		return
	}
	id := From(r.Context())
	a.revoke(id)
	a.setCookie(w, sessionCookie, "", -time.Second)
	redirect := "/"
	if id != nil && id.Via == "oidc" && a.oidc != nil {
		if end := a.oidc.endSession(r.Context()); end != "" {
			q := url.Values{"post_logout_redirect_uri": {a.redirectBase()}}
			if id.IDToken != "" {
				q.Set("id_token_hint", id.IDToken)
			}
			redirect = end + "?" + q.Encode()
		}
	}
	writeJSON(w, map[string]string{"redirect": redirect})
}

func (a *Auth) redirectBase() string {
	if a.baseURL != nil {
		return strings.TrimRight(a.baseURL.String(), "/") + "/"
	}
	return "/"
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *Auth) handleLocalLogin(w http.ResponseWriter, r *http.Request) {
	if !a.SameOrigin(r) {
		writeErr(w, http.StatusForbidden, "cross-origin request refused")
		return
	}
	if !IsJSON(r) {
		writeErr(w, http.StatusUnsupportedMediaType, "send Content-Type: application/json")
		return
	}
	var body struct{ Username, Password string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "expected JSON {username, password}")
		return
	}
	// Per client and username, so one attacker behind a shared ingress can't lock everyone out.
	if !a.limiter.allow(clientIP(r) + "|" + body.Username) {
		writeErr(w, http.StatusTooManyRequests, "too many sign-in attempts; wait a minute")
		return
	}
	users, err := a.users.load()
	if err != nil {
		a.log.Error("reading users file", "err", err)
		writeErr(w, http.StatusInternalServerError, "sign-in is misconfigured")
		return
	}
	// Compare against a dummy hash when the user is unknown, so timing does not reveal names.
	hash := dummyHash()
	var match *localUser
	for i := range users {
		if users[i].Username == body.Username {
			match, hash = &users[i], users[i].PasswordHash
		}
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)) != nil || match == nil {
		a.log.Warn("local sign-in failed", "user", body.Username, "ip", clientIP(r))
		writeErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	role := match.Role
	if role == "" {
		role = Viewer
	}
	if err := a.startSession(w, &Identity{User: match.Username, Role: role, Via: "local"}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.log.Info("signed in", "user", match.Username, "via", "local", "role", role)
	writeJSON(w, map[string]string{"ok": "signed in"})
}

var dummyHash = sync.OnceValue(func() string {
	h, _ := bcrypt.GenerateFromPassword([]byte(randToken()), 12)
	return string(h)
})

// ---- OIDC ----

type oidcState struct {
	cfg      config.OIDC
	secret   string
	redirect string

	mu       sync.Mutex
	provider *oidc.Provider
	endURL   string
}

func (o *oidcState) get(ctx context.Context) (*oidc.Provider, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return o.provider, nil
	}
	// Discovered lazily so the app starts even while the IdP is down.
	p, err := oidc.NewProvider(ctx, o.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery for %s: %w", o.cfg.Issuer, err)
	}
	var claims struct {
		EndSession string `json:"end_session_endpoint"`
	}
	_ = p.Claims(&claims)
	o.provider, o.endURL = p, claims.EndSession
	return p, nil
}

func (o *oidcState) endSession(ctx context.Context) string {
	if _, err := o.get(ctx); err != nil {
		return ""
	}
	return o.endURL
}

func (o *oidcState) oauth(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{ClientID: o.cfg.ClientID, ClientSecret: o.secret, Endpoint: p.Endpoint(), RedirectURL: o.redirect, Scopes: o.cfg.Scopes}
}

type flow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
	Exp      int64  `json:"e"`
}

func randToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// safeNext keeps post-login redirects on this site: a plain absolute path, no control characters
// (browsers drop tabs and newlines, turning "/\t/evil.com" into "//evil.com"), no scheme or host.
func safeNext(n string) string {
	if n == "" || len(n) > 2048 || !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") || strings.Contains(n, "\\") {
		return "/"
	}
	for _, c := range n {
		if c < 0x20 || c == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(n)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	return n
}

// IsJSON reports whether the request declares a JSON body. Browsers can send text/plain
// cross-site without a preflight, so requiring JSON closes that CSRF path.
func IsJSON(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

func (a *Auth) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	p, err := a.oidc.get(r.Context())
	if err != nil {
		a.log.Error("OIDC", "err", err)
		http.Error(w, "The identity provider is unreachable. Try again shortly.", http.StatusBadGateway)
		return
	}
	f := flow{State: randToken(), Nonce: randToken(), Verifier: oauth2.GenerateVerifier(), Next: safeNext(r.URL.Query().Get("next")), Exp: time.Now().Add(flowTTL).Unix()}
	tok, err := a.sign(f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.setCookie(w, flowCookie, tok, flowTTL)
	http.Redirect(w, r, a.oidc.oauth(p).AuthCodeURL(f.State, oidc.Nonce(f.Nonce), oauth2.S256ChallengeOption(f.Verifier)), http.StatusFound)
}

func (a *Auth) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string, err error) {
		a.log.Warn("OIDC sign-in failed", "reason", msg, "err", err)
		http.Error(w, "Sign-in failed: "+msg+". Go back and try again.", http.StatusUnauthorized)
	}
	c, err := r.Cookie(flowCookie)
	if err != nil {
		fail("the sign-in took too long or cookies are blocked", err)
		return
	}
	a.setCookie(w, flowCookie, "", -time.Second)
	var f flow
	if err := a.verify(c.Value, &f); err != nil || time.Now().Unix() > f.Exp {
		fail("sign-in state expired", err)
		return
	}
	if q := r.URL.Query(); q.Get("error") != "" {
		fail(q.Get("error")+" "+q.Get("error_description"), nil)
		return
	} else if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(f.State)) != 1 {
		fail("state mismatch", nil)
		return
	}
	p, err := a.oidc.get(r.Context())
	if err != nil {
		fail("identity provider unreachable", err)
		return
	}
	tok, err := a.oidc.oauth(p).Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(f.Verifier))
	if err != nil {
		fail("code exchange failed", err)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := p.Verifier(&oidc.Config{ClientID: a.cfg.OIDC.ClientID}).Verify(r.Context(), raw)
	if err != nil {
		fail("ID token invalid", err)
		return
	}
	if idt.Nonce != f.Nonce {
		fail("nonce mismatch", nil)
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		fail("unreadable claims", err)
		return
	}
	groups := claimStrings(claims[a.cfg.OIDC.GroupsClaim])
	role := a.roleFor(groups, a.cfg.OIDC.Roles)
	str := func(k string) string { s, _ := claims[k].(string); return s }
	user := str("preferred_username")
	if user == "" {
		user = str("email")
	}
	if user == "" {
		user = idt.Subject
	}
	if role == "" {
		a.log.Warn("OIDC user has no role", "user", user, "groups", groups)
		http.Error(w, "You signed in, but none of your groups grants access to this app.", http.StatusForbidden)
		return
	}
	// The ID token is kept for logout only when it fits comfortably in the cookie.
	keep := raw
	if len(keep) > 1800 {
		keep = ""
	}
	if err := a.startSession(w, &Identity{User: user, Name: str("name"), Email: str("email"), Role: role, Via: "oidc", Groups: groups, IDToken: keep}); err != nil {
		fail("session", err)
		return
	}
	a.log.Info("signed in", "user", user, "via", "oidc", "role", role)
	http.Redirect(w, r, f.Next, http.StatusFound)
}

func claimStrings(v any) []string {
	switch x := v.(type) {
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{x}
	}
	return nil
}

// ---- file-backed stores, reloaded when the mounted Secret changes ----

type fileStore[T any] struct {
	path  string
	mu    sync.Mutex
	mtime time.Time
	size  int64
	items []T
}

func (s *fileStore[T]) load() ([]T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := os.Stat(s.path)
	if err != nil {
		return nil, err
	}
	if s.items != nil && st.ModTime().Equal(s.mtime) && st.Size() == s.size {
		return s.items, nil
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var items []T
	if err := yaml.Unmarshal(b, &items); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	if items == nil {
		items = []T{}
	}
	s.items, s.mtime, s.size = items, st.ModTime(), st.Size()
	return items, nil
}

// ---- tiny per-IP rate limiter for password sign-in ----

type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, hits: map[string][]time.Time{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	recent := func(ts []time.Time) []time.Time {
		var keep []time.Time
		for _, t := range ts {
			if now.Sub(t) < l.window {
				keep = append(keep, t)
			}
		}
		return keep
	}
	keep := recent(l.hits[key])
	if len(keep) >= l.max {
		l.hits[key] = keep
		return false
	}
	if _, known := l.hits[key]; !known && len(l.hits) >= 10000 {
		// Bound memory: drop expired entries; if a spray still fills the table, refuse new keys
		// (existing clients keep their own budget) rather than resetting everyone's.
		for k, ts := range l.hits {
			if len(recent(ts)) == 0 {
				delete(l.hits, k)
			}
		}
		if len(l.hits) >= 10000 {
			return false
		}
	}
	l.hits[key] = append(keep, now)
	return true
}
