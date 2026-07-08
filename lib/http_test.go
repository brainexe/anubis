package lib

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/TecharoHQ/anubis"
	"github.com/TecharoHQ/anubis/internal"
	"github.com/TecharoHQ/anubis/lib/policy"
)

func TestSetCookie(t *testing.T) {
	for _, tt := range []struct {
		name       string
		host       string
		cookieName string
		options    Options
	}{
		{
			name:       "basic",
			options:    Options{},
			host:       "",
			cookieName: anubis.CookieName,
		},
		{
			name:       "domain techaro.lol",
			options:    Options{CookieDomain: "techaro.lol"},
			host:       "",
			cookieName: anubis.CookieName,
		},
		{
			name:       "dynamic cookie domain",
			options:    Options{CookieDynamicDomain: true},
			host:       "techaro.lol",
			cookieName: anubis.CookieName,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := spawnAnubis(t, tt.options)
			rw := httptest.NewRecorder()

			srv.SetCookie(rw, CookieOpts{Value: "test", Host: tt.host})

			resp := rw.Result()
			cookies := resp.Cookies()

			ckie := cookies[0]

			if ckie.Name != tt.cookieName {
				t.Errorf("wanted cookie named %q, got cookie named %q", tt.cookieName, ckie.Name)
			}
		})
	}
}

func TestClearCookie(t *testing.T) {
	srv := spawnAnubis(t, Options{})
	rw := httptest.NewRecorder()

	srv.ClearCookie(rw, CookieOpts{Host: "localhost"})

	resp := rw.Result()

	cookies := resp.Cookies()

	if len(cookies) != 1 {
		t.Errorf("wanted 1 cookie, got %d cookies", len(cookies))
	}

	ckie := cookies[0]

	if ckie.Name != anubis.CookieName {
		t.Errorf("wanted cookie named %q, got cookie named %q", anubis.CookieName, ckie.Name)
	}

	if ckie.MaxAge != -1 {
		t.Errorf("wanted cookie max age of -1, got: %d", ckie.MaxAge)
	}
}

func TestClearCookieWithDomain(t *testing.T) {
	srv := spawnAnubis(t, Options{CookieDomain: "techaro.lol"})
	rw := httptest.NewRecorder()

	srv.ClearCookie(rw, CookieOpts{Host: "localhost"})

	resp := rw.Result()

	cookies := resp.Cookies()

	if len(cookies) != 1 {
		t.Errorf("wanted 1 cookie, got %d cookies", len(cookies))
	}

	ckie := cookies[0]

	if ckie.Name != anubis.CookieName {
		t.Errorf("wanted cookie named %q, got cookie named %q", anubis.CookieName, ckie.Name)
	}

	if ckie.MaxAge != -1 {
		t.Errorf("wanted cookie max age of -1, got: %d", ckie.MaxAge)
	}
}

func TestClearCookieWithDynamicDomain(t *testing.T) {
	srv := spawnAnubis(t, Options{CookieDynamicDomain: true})
	rw := httptest.NewRecorder()

	srv.ClearCookie(rw, CookieOpts{Host: "subdomain.xeiaso.net"})

	resp := rw.Result()

	cookies := resp.Cookies()

	if len(cookies) != 1 {
		t.Errorf("wanted 1 cookie, got %d cookies", len(cookies))
	}

	ckie := cookies[0]

	if ckie.Name != anubis.CookieName {
		t.Errorf("wanted cookie named %q, got cookie named %q", anubis.CookieName, ckie.Name)
	}

	if ckie.Domain != "xeiaso.net" {
		t.Errorf("wanted cookie domain %q, got cookie domain %q", "xeiaso.net", ckie.Domain)
	}

	if ckie.MaxAge != -1 {
		t.Errorf("wanted cookie max age of -1, got: %d", ckie.MaxAge)
	}
}

func TestRenderIndexRedirect(t *testing.T) {
	s := &Server{
		opts: Options{
			PublicUrl: "https://anubis.example.com",
		},
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")
	req.Header.Set("X-Forwarded-Uri", "/foo")

	rr := httptest.NewRecorder()
	s.RenderIndex(rr, req, policy.CheckResult{}, nil, true)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected status %d, got %d", http.StatusTemporaryRedirect, rr.Code)
	}
	location := rr.Header().Get("Location")
	parsedURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse location URL %q: %v", location, err)
	}

	scheme := "https"
	if parsedURL.Scheme != scheme {
		t.Errorf("expected scheme to be %q, got %q", scheme, parsedURL.Scheme)
	}

	host := "anubis.example.com"
	if parsedURL.Host != host {
		t.Errorf("expected url to be %q, got %q", host, parsedURL.Host)
	}

	redir := parsedURL.Query().Get("redir")
	expectedRedir := "https://example.com/foo"
	if redir != expectedRedir {
		t.Errorf("expected redir param to be %q, got %q", expectedRedir, redir)
	}
}

func TestRenderIndexUnauthorized(t *testing.T) {
	s := &Server{
		opts: Options{
			PublicUrl: "",
		},
	}
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	s.RenderIndex(rr, req, policy.CheckResult{}, nil, true)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
	if body := rr.Body.String(); body != "Authorization required" {
		t.Errorf("expected body %q, got %q", "Authorization required", body)
	}
}

func TestNoCacheOnError(t *testing.T) {
	pol := loadPolicies(t, "testdata/useragent.yaml", 0)
	srv := spawnAnubis(t, Options{Policy: pol})
	ts := httptest.NewServer(internal.RemoteXRealIP(true, "tcp", srv))
	defer ts.Close()

	for userAgent, expectedCacheControl := range map[string]string{
		"DENY":      "no-store",
		"CHALLENGE": "no-store",
		"ALLOW":     "",
	} {
		t.Run(userAgent, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("User-Agent", userAgent)

			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}

			if resp.Header.Get("Cache-Control") != expectedCacheControl {
				t.Errorf("wanted Cache-Control header %q, got %q", expectedCacheControl, resp.Header.Get("Cache-Control"))
			}
		})
	}
}

func TestRejectsHostlessRedirect(t *testing.T) {
	pol := loadPolicies(t, "testdata/useragent.yaml", 0)
	srv := spawnAnubis(t, Options{Policy: pol, RedirectDomains: []string{"allowed.example"}})
	req := httptest.NewRequest(http.MethodGet, "https://anubis.example/.within.website/?redir=%2f%2fevil.example%2fphish", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTPNext(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected hostless redirect to be rejected, got HTTP %d body %q", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Location"); got != "" {
		t.Fatalf("expected no Location header on rejected redirect, got %q", got)
	}
}

func TestRenderIndexSubrequest(t *testing.T) {
	for _, tt := range []struct {
		name         string
		opts         Options
		forwardedURI string
		wantStatus   int
		wantPrefix   string
	}{
		{
			name:         "dynamic public URL redirects to forwarded host",
			opts:         Options{PublicUrlDynamic: true},
			forwardedURI: "/page",
			wantStatus:   http.StatusTemporaryRedirect,
			wantPrefix:   "https://mitdemherzensehen.de/.within.website/",
		},
		{
			name:         "static public URL redirects to configured host",
			opts:         Options{PublicUrl: "https://anubis.example.com"},
			forwardedURI: "/page",
			wantStatus:   http.StatusTemporaryRedirect,
			wantPrefix:   "https://anubis.example.com/.within.website/",
		},
		{
			name:         "no public URL returns 401 even with forwarded headers",
			opts:         Options{},
			forwardedURI: "/page",
			wantStatus:   http.StatusUnauthorized,
		},
		{
			name:         "redirect loop returns 401 instead of redirecting",
			opts:         Options{PublicUrlDynamic: true},
			forwardedURI: "/.within.website/?redir=https%3A%2F%2Fmitdemherzensehen.de%2F",
			wantStatus:   http.StatusUnauthorized,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				opts:   tt.opts,
				logger: slog.Default(),
				policy: &policy.ParsedConfig{},
			}
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", "mitdemherzensehen.de")
			req.Header.Set("X-Forwarded-Uri", tt.forwardedURI)

			rr := httptest.NewRecorder()
			s.RenderIndex(rr, req, policy.CheckResult{}, nil, true)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			location := rr.Header().Get("Location")
			if tt.wantPrefix == "" && location != "" {
				t.Errorf("expected no Location header, got: %s", location)
			}
			if tt.wantPrefix != "" && !strings.HasPrefix(location, tt.wantPrefix) {
				t.Errorf("expected redirect to start with %q, got: %s", tt.wantPrefix, location)
			}
		})
	}
}

func TestConstructRedirectURLDynamic(t *testing.T) {
	for _, tt := range []struct {
		name          string
		opts          Options
		forwardedHost string
		forwardedURI  string
		wantErr       error
		wantErrAny    bool
		wantPrefix    string
		wantRedir     string
	}{
		{
			name: "derives base URL and redir param from forwarded headers",
			opts: Options{
				PublicUrlDynamic: true,
				RedirectDomains:  []string{"mitdemherzensehen.de", "example.com"},
			},
			forwardedHost: "mitdemherzensehen.de",
			forwardedURI:  "/protected/page",
			wantPrefix:    "https://mitdemherzensehen.de/.within.website/",
			wantRedir:     "https://mitdemherzensehen.de/protected/page",
		},
		{
			name: "dynamic overrides static public URL",
			opts: Options{
				PublicUrl:        "https://static.anubis.example.com",
				PublicUrlDynamic: true,
				RedirectDomains:  []string{"dynamic.example.com"},
			},
			forwardedHost: "dynamic.example.com",
			forwardedURI:  "/page",
			wantPrefix:    "https://dynamic.example.com/.within.website/",
		},
		{
			name: "static public URL used when dynamic is off",
			opts: Options{
				PublicUrl:       "https://static.anubis.example.com",
				RedirectDomains: []string{"dynamic.example.com"},
			},
			forwardedHost: "dynamic.example.com",
			forwardedURI:  "/page",
			wantPrefix:    "https://static.anubis.example.com/.within.website/",
		},
		{
			name: "forwarded host not in redirect domains is rejected",
			opts: Options{
				PublicUrlDynamic: true,
				RedirectDomains:  []string{"mitdemherzensehen.de"},
			},
			forwardedHost: "evil.example.com",
			forwardedURI:  "/page",
			wantErrAny:    true,
		},
		{
			name:          "challenge page URI returns ErrRedirectLoop",
			opts:          Options{PublicUrlDynamic: true},
			forwardedHost: "example.com",
			forwardedURI:  "/.within.website/?redir=https%3A%2F%2Fexample.com%2F",
			wantErr:       ErrRedirectLoop,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				opts:   tt.opts,
				logger: slog.Default(),
				policy: &policy.ParsedConfig{},
			}
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", tt.forwardedHost)
			req.Header.Set("X-Forwarded-Uri", tt.forwardedURI)

			redirectURL, err := s.constructRedirectURL(req)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got: %v", tt.wantErr, err)
				}
				return
			}
			if tt.wantErrAny {
				if err == nil {
					t.Fatalf("expected an error, got redirect URL: %s", redirectURL)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !strings.HasPrefix(redirectURL, tt.wantPrefix) {
				t.Errorf("expected redirect to start with %q, got: %s", tt.wantPrefix, redirectURL)
			}

			if tt.wantRedir != "" {
				parsed, err := url.Parse(redirectURL)
				if err != nil {
					t.Fatalf("failed to parse redirect URL: %v", err)
				}
				if redir := parsed.Query().Get("redir"); redir != tt.wantRedir {
					t.Errorf("expected redir param to be %q, got %q", tt.wantRedir, redir)
				}
			}
		})
	}
}
