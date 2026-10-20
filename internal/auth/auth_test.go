package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/opswhisperer/eh-k8s-console/internal/config"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func baseConfig(t *testing.T, modes ...string) *config.Config {
	c := config.Default()
	c.Auth.Modes = modes
	c.Auth.SessionSecret = config.SecretRef{File: write(t, "session", strings.Repeat("s", 40))}
	return c
}

// app is a tiny server: auth routes plus endpoints needing each role.
func app(t *testing.T, a *Auth) *httptest.Server {
	mux := http.NewServeMux()
	a.Routes(mux)
	mux.HandleFunc("GET /api/view", a.Require(Viewer, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, From(r.Context()).User) }))
	mux.HandleFunc("POST /api/apply", a.Require(Admin, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "applied") }))
	return httptest.NewServer(a.Middleware(mux))
}

func do(t *testing.T, c *http.Client, method, u string, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, u, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(b)
}

func TestLocalLoginRolesAndCSRF(t *testing.T) {
	adminHash, _ := HashPassword("correct horse")
	viewHash, _ := HashPassword("viewer pw")
	c := baseConfig(t, "local")
	c.Auth.Local.UsersFile = write(t, "users.yaml", "- username: rob\n  passwordHash: "+adminHash+"\n  role: admin\n- username: val\n  passwordHash: "+viewHash+"\n  role: viewer\n")
	a, err := New(c, quiet)
	if err != nil {
		t.Fatal(err)
	}
	srv := app(t, a)
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{Jar: jar}
	origin := map[string]string{"Origin": srv.URL, "Content-Type": "application/json"}

	if res, _ := do(t, cl, "GET", srv.URL+"/api/view", "", nil); res.StatusCode != 401 {
		t.Fatalf("anonymous view = %d", res.StatusCode)
	}
	if res, _ := do(t, cl, "POST", srv.URL+"/auth/login", `{"username":"rob","password":"nope"}`, origin); res.StatusCode != 401 {
		t.Fatalf("bad password = %d", res.StatusCode)
	}
	if res, _ := do(t, cl, "POST", srv.URL+"/auth/login", `{"username":"rob","password":"correct horse"}`, map[string]string{"Origin": "https://evil.example"}); res.StatusCode != 403 {
		t.Fatalf("cross-origin login = %d", res.StatusCode)
	}
	if res, body := do(t, cl, "POST", srv.URL+"/auth/login", `{"username":"rob","password":"correct horse"}`, origin); res.StatusCode != 200 {
		t.Fatalf("login = %d %s", res.StatusCode, body)
	}
	if _, body := do(t, cl, "GET", srv.URL+"/api/view", "", nil); body != "rob" {
		t.Fatalf("view as rob = %q", body)
	}
	if res, _ := do(t, cl, "POST", srv.URL+"/api/apply", "", map[string]string{"Origin": "https://evil.example"}); res.StatusCode != 403 {
		t.Fatalf("cross-origin apply with cookie = %d, want 403", res.StatusCode)
	}
	if res, body := do(t, cl, "POST", srv.URL+"/api/apply", "", origin); res.StatusCode != 200 || body != "applied" {
		t.Fatalf("same-origin apply = %d", res.StatusCode)
	}

	jar2, _ := cookiejar.New(nil)
	cl2 := &http.Client{Jar: jar2}
	do(t, cl2, "POST", srv.URL+"/auth/login", `{"username":"val","password":"viewer pw"}`, origin)
	if res, _ := do(t, cl2, "POST", srv.URL+"/api/apply", "", origin); res.StatusCode != 403 {
		t.Fatalf("viewer apply = %d, want 403", res.StatusCode)
	}

	// A tampered cookie is rejected.
	u, _ := url.Parse(srv.URL)
	for _, ck := range jar.Cookies(u) {
		if ck.Name == sessionCookie {
			payload, sig, _ := strings.Cut(ck.Value, ".")
			forged := payload[:len(payload)-2] + "AA." + sig
			req, _ := http.NewRequest("GET", srv.URL+"/api/view", nil)
			req.AddCookie(&http.Cookie{Name: sessionCookie, Value: forged})
			res, _ := http.DefaultClient.Do(req)
			if res.StatusCode != 401 {
				t.Fatalf("forged cookie = %d", res.StatusCode)
			}
		}
	}
}

func TestAPIKeysAreExemptFromCSRFAndReloaded(t *testing.T) {
	key, hash := NewAPIKey()
	c := baseConfig(t, "apikey")
	c.Auth.APIKeys.File = write(t, "keys.yaml", "- name: ci\n  hash: "+hash+"\n  role: admin\n")
	a, err := New(c, quiet)
	if err != nil {
		t.Fatal(err)
	}
	srv := app(t, a)
	defer srv.Close()
	if res, body := do(t, http.DefaultClient, "POST", srv.URL+"/api/apply", "", map[string]string{"Authorization": "Bearer " + key}); res.StatusCode != 200 {
		t.Fatalf("api key apply = %d %s", res.StatusCode, body)
	}
	if res, _ := do(t, http.DefaultClient, "GET", srv.URL+"/api/view", "", map[string]string{"Authorization": "Bearer ehk_wrong"}); res.StatusCode != 401 {
		t.Fatalf("wrong key = %d", res.StatusCode)
	}
	// Rotating the Secret (rewriting the file) revokes the old key.
	time.Sleep(10 * time.Millisecond)
	_, other := NewAPIKey()
	os.WriteFile(c.Auth.APIKeys.File, []byte("- name: ci\n  hash: "+other+"\n  role: admin\n"), 0o600)
	if res, _ := do(t, http.DefaultClient, "GET", srv.URL+"/api/view", "", map[string]string{"Authorization": "Bearer " + key}); res.StatusCode != 401 {
		t.Fatalf("revoked key = %d", res.StatusCode)
	}
}

func TestProxyHeadersOnlyFromTrustedCIDRs(t *testing.T) {
	c := baseConfig(t, "proxy")
	c.Auth.Proxy.TrustedCIDRs = []string{"10.0.0.0/8"}
	c.Auth.Proxy.Roles = map[string]string{"eh-admins": "admin", "eh-viewers": "viewer"}
	a, err := New(c, quiet)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-User", "rob")
	req.Header.Set("X-Forwarded-Groups", "staff|eh-admins")
	req.RemoteAddr = "192.168.1.5:1234"
	if a.Authenticate(req) != nil {
		t.Fatal("headers from an untrusted address must be ignored")
	}
	req.RemoteAddr = "10.1.2.3:1234"
	id := a.Authenticate(req)
	if id == nil || id.Role != Admin || id.User != "rob" {
		t.Fatalf("trusted proxy identity = %+v", id)
	}
	req.Header.Set("X-Forwarded-Groups", "staff")
	if a.Authenticate(req) != nil {
		t.Fatal("no matching group and no default role must be refused")
	}
}

func TestConfigRefusesUnsafeSetups(t *testing.T) {
	c := config.Default()
	if _, err := New(c, quiet); err == nil {
		t.Fatal("no modes must be an error")
	}
	c.Auth.Modes = []string{"proxy"}
	if err := c.Validate(); err == nil {
		t.Fatal("proxy without trusted CIDRs must be refused")
	}
	c.Auth.Modes = []string{"none", "local"}
	if err := c.Validate(); err == nil {
		t.Fatal("none combined with other modes must be refused")
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{"/settings": "/settings", "//evil.com": "/", "https://evil.com": "/", "": "/", "/\\evil": "/"} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q", in, got)
		}
	}
}

// fakeIdP is a minimal OIDC provider: discovery, JWKS, authorize (auto-approve) and token.
type fakeIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	groups []string
	nonce  string
	verif  string
	chall  string
}

func newIdP(t *testing.T, groups ...string) *fakeIdP {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	p := &fakeIdP{key: k, groups: groups}
	mux := http.NewServeMux()
	p.srv = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/authorize", "token_endpoint": p.srv.URL + "/token",
			"jwks_uri": p.srv.URL + "/jwks", "end_session_endpoint": p.srv.URL + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		p.nonce, p.chall = q.Get("nonce"), q.Get("code_challenge")
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=abc&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		p.verif = r.PostForm.Get("code_verifier")
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
		tok, _ := jwt.Signed(signer).Claims(map[string]any{
			"iss": p.srv.URL, "aud": "console", "sub": "u1", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"nonce": p.nonce, "preferred_username": "rob", "email": "rob@example.com", "groups": p.groups,
		}).Serialize()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": tok, "expires_in": 3600})
	})
	return p
}

func oidcApp(t *testing.T, idp *fakeIdP) (*httptest.Server, *http.Client) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	srv = httptest.NewUnstartedServer(nil)
	c := baseConfig(t, "oidc")
	c.BaseURL = "http://" + srv.Listener.Addr().String()
	c.Auth.OIDC = config.OIDC{Issuer: idp.srv.URL, ClientID: "console", ClientSecret: config.SecretRef{File: write(t, "cs", "secret")},
		Scopes: []string{"openid"}, GroupsClaim: "groups", Roles: map[string]string{"eh-admins": "admin"}}
	a, err := New(c, quiet)
	if err != nil {
		t.Fatal(err)
	}
	a.Routes(mux)
	mux.HandleFunc("GET /api/view", a.Require(Viewer, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, From(r.Context()).Role) }))
	srv.Config.Handler = a.Middleware(mux)
	srv.Start()
	jar, _ := cookiejar.New(nil)
	return srv, &http.Client{Jar: jar}
}

func TestOIDCRoundTrip(t *testing.T) {
	idp := newIdP(t, "eh-admins")
	defer idp.srv.Close()
	srv, cl := oidcApp(t, idp)
	defer srv.Close()
	res, body := do(t, cl, "GET", srv.URL+"/auth/oidc?next=/api/view", "", nil)
	if res.StatusCode != 200 || body != "admin" {
		t.Fatalf("after OIDC sign-in: %d %q", res.StatusCode, body)
	}
	if idp.chall == "" || idp.verif == "" {
		t.Fatal("PKCE was not used")
	}
}

func TestOIDCUserWithoutRoleIsRefused(t *testing.T) {
	idp := newIdP(t, "someone-else")
	defer idp.srv.Close()
	srv, cl := oidcApp(t, idp)
	defer srv.Close()
	if res, _ := do(t, cl, "GET", srv.URL+"/auth/oidc", "", nil); res.StatusCode != 403 {
		t.Fatalf("status = %d, want 403", res.StatusCode)
	}
}
