// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

func TestIdentityToken(t *testing.T) {
	forbiddenReasons := make(map[string]string) // error description to test case
	for _, tc := range []struct {
		name         string
		change       func(*IDPServer, *http.Request, *apitype.WhoIsResponse)
		status       int
		wantLifetime int // Seconds; zero means the default 300 seconds.
		wantUserID   tailcfg.UserID
		wantEmail    string
		wantUsername string
		wantGroups   []string
	}{
		{name: "tagged node", status: 200},
		{name: "missing stable ID", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) { who.Node.StableID = "" }, status: 200},
		{name: "key expires soon", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			who.Node.KeyExpiry = time.Now().Add(time.Minute)
		}, status: 200, wantLifetime: 60},
		{name: "key expires later", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			who.Node.KeyExpiry = time.Now().Add(time.Hour)
		}, status: 200},
		{name: "expired key", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			who.Node.KeyExpiry = time.Now().Add(-time.Second)
		}, status: 401},
		{name: "key expires now", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			who.Node.KeyExpiry = time.Now()
		}, status: 401},
		{name: "node marked expired", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			who.Node.Expired = true
		}, status: 401},
		{name: "disabled", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) { s.enableIDToken = false }, status: 404},
		{name: "invalid peer address", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) { r.RemoteAddr = "invalid" }, status: 403},
		{name: "missing audience", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) { r.Body = http.NoBody }, status: 400},
		{name: "blank audience", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			r.Body = io.NopCloser(strings.NewReader("audience=+"))
		}, status: 400},
		{name: "first audience", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			r.Body = io.NopCloser(strings.NewReader("audience=https://service.example&audience=ignored"))
		}, status: 200},
		{name: "body precedes query", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) { r.URL.RawQuery = "audience=ignored" }, status: 200},
		{name: "invalid form", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			r.Body = io.NopCloser(strings.NewReader("audience=%ZZ"))
		}, status: 400},
		{name: "oversized form", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			r.Body = io.NopCloser(strings.NewReader("audience=" + strings.Repeat("a", 4096)))
		}, status: 400},
		{name: "user node", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			who.Node.Tags = nil
			who.Node.User = 123
		}, status: 200, wantUserID: 123, wantEmail: "alice@example.com", wantUsername: "alice", wantGroups: []string{"group:eng", "engineering@example.com"}},
		{name: "user node without profile", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			who.Node.Tags = nil
			who.UserProfile = nil
		}, status: 200, wantUserID: 999},
		{name: "user node with empty profile", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			who.Node.Tags = nil
			who.UserProfile = &tailcfg.UserProfile{}
		}, status: 200, wantUserID: 999},
		{name: "user node with github login", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			who.Node.Tags = nil
			who.UserProfile.LoginName = "alice@github"
		}, status: 200, wantUserID: 999, wantEmail: "alice@github.test.ts.net", wantUsername: "alice", wantGroups: []string{"group:eng", "engineering@example.com"}},
		{name: "query-only audience", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			r.Body = http.NoBody
			r.URL.RawQuery = "audience=https://service.example"
		}, status: 200},
		{name: "missing identity", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) { who.Node.ID = 0 }, status: 401},
		{name: "missing header", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			r.Header.Del("Tsidp-Identity-Token")
		}, status: 403},
		{name: "browser", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) { r.Header.Set("Origin", s.serverURL) }, status: 403},
		{name: "funnel", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			r.Header.Set("Tailscale-Funnel-Request", "true")
		}, status: 403},
		{name: "local tailscaled", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) { s.localTSMode = true }, status: 403},
		{name: "spoofed forwarding", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			r.RemoteAddr = "127.0.0.1:1234"
			r.Header.Set("X-Forwarded-For", "100.64.0.1:1234")
		}, status: 403},
		{name: "GET query audience", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			r.Method = http.MethodGet
			r.Body = http.NoBody
			r.Header.Del("Content-Type")
			r.URL.RawQuery = "audience=https%3A%2F%2Fservice.example"
		}, status: 200},
		{name: "GET ignores body audience", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			r.Method = http.MethodGet
		}, status: 400},
		{name: "GET invalid query", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			r.Method = http.MethodGet
			r.Body = http.NoBody
			r.URL.RawQuery = "audience=%ZZ"
		}, status: 400},
		{name: "HEAD", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) { r.Method = http.MethodHead }, status: 405},
		{name: "OPTIONS", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) { r.Method = "OPTIONS" }, status: 405},
		{name: "lookup failure", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			s.lc = newTestWhoIsClient(t, nil, true)
		}, status: 401},
		{name: "user node with different username", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			who.Node.Tags = nil
			who.UserProfile.LoginName = "bob@example.com"
		}, status: 200, wantUserID: 999, wantEmail: "bob@example.com", wantUsername: "bob", wantGroups: []string{"group:eng", "engineering@example.com"}},
		{name: "key expires within current second", change: func(s *IDPServer, r *http.Request, who *apitype.WhoIsResponse) {
			who.Node.KeyExpiry = time.Now().Add(100 * time.Millisecond)
		}, status: 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// Keep time fixed at a fractional second to exercise JWT second precision.
				time.Sleep(250 * time.Millisecond)
				issuedAt := time.Now().Unix()

				who := &apitype.WhoIsResponse{Node: &tailcfg.Node{ID: 42, StableID: "n123", Name: "ci.example.ts.net.", User: 999, Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}, Tags: []string{"tag:ci"}}}
				who.UserProfile = &tailcfg.UserProfile{LoginName: "alice@example.com", Groups: []string{"group:eng", "engineering@example.com"}}
				who.CapMap = tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityTsIDP: marshalCapRules([]capRule{{IdentityTokenAudiences: []string{"https://service.example"}}}),
				}
				s := setupTestServer(t, newTestWhoIsClient(t, who, false))
				s.enableIDToken = true
				s.hostname = "test.ts.net"
				r := httptest.NewRequest("POST", "/identity-token", strings.NewReader("audience=https://service.example"))
				r.RemoteAddr = "100.64.0.1:1234"
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("Accept", "application/json")
				r.Header.Set("Tsidp-Identity-Token", "true")
				if tc.change != nil {
					tc.change(s, r, who)
				}
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				if w.Code != tc.status {
					t.Fatalf("status = %d, want %d: %s", w.Code, tc.status, w.Body.String())
				}
				if w.Header().Get("Access-Control-Allow-Origin") != "" {
					t.Fatal("CORS enabled")
				}
				if w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("missing no-store")
				}
				if tc.status == http.StatusMethodNotAllowed && w.Header().Get("Allow") != "GET, POST" {
					t.Fatalf("Allow = %q, want GET, POST", w.Header().Get("Allow"))
				}
				if tc.status == 403 {
					var response struct {
						Error       string `json:"error"`
						Description string `json:"error_description"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
						t.Fatal(err)
					}
					if response.Error != ecAccessDenied {
						t.Errorf("error = %q, want %q", response.Error, ecAccessDenied)
					}
					if strings.TrimSpace(response.Description) == "" {
						t.Fatal("missing error description")
					}
					if previous, ok := forbiddenReasons[response.Description]; ok {
						t.Errorf("same forbidden reason as %q: %q", previous, response.Description)
					}
					forbiddenReasons[response.Description] = tc.name
				}
				if tc.status != 200 {
					return
				}
				var response struct {
					IDToken   string `json:"id_token"`
					ExpiresIn int    `json:"expires_in"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				token, err := jwt.ParseSigned(response.IDToken)
				if err != nil {
					t.Fatal(err)
				}
				var claims struct {
					jwt.Claims
					NodeID            tailcfg.NodeID       `json:"nid"`
					NodeName          string               `json:"node"`
					Tailnet           string               `json:"tailnet"`
					Addresses         []netip.Prefix       `json:"addresses"`
					UserID            tailcfg.UserID       `json:"uid"`
					Email             string               `json:"email"`
					PreferredUsername string               `json:"preferred_username"`
					StableNodeID      tailcfg.StableNodeID `json:"stable_node_id"`
					Tags              []string             `json:"tags"`
				}
				if err := token.Claims(oidcTestingPublicKey(t), &claims); err != nil {
					t.Fatal(err)
				}
				if err := claims.Validate(jwt.Expected{Issuer: s.serverURL, Subject: "node:42", Audience: jwt.Audience{"https://service.example"}, Time: time.Now()}); err != nil {
					t.Fatal(err)
				}
				wantLifetime := tc.wantLifetime
				if wantLifetime == 0 {
					wantLifetime = 300
				}
				if claims.IssuedAt == nil || int64(*claims.IssuedAt) != issuedAt {
					t.Fatalf("iat = %v, want %d", claims.IssuedAt, issuedAt)
				}
				wantExpiry := issuedAt + int64(wantLifetime)
				if claims.Expiry == nil || int64(*claims.Expiry) != wantExpiry || response.ExpiresIn != wantLifetime {
					t.Fatalf("exp = %v, expires_in = %d; want %d, %d", claims.Expiry, response.ExpiresIn, wantExpiry, wantLifetime)
				}

				if claims.StableNodeID != who.Node.StableID {
					t.Errorf("stable_node_id = %q, want %q", claims.StableNodeID, who.Node.StableID)
				}
				if claims.NodeID != who.Node.ID || claims.NodeName != who.Node.Name || claims.Tailnet != "example.ts.net." || !reflect.DeepEqual(claims.Addresses, who.Node.Addresses) || !reflect.DeepEqual(claims.Tags, who.Node.Tags) {
					t.Fatalf("unexpected node claims: %+v", claims)
				}
				if claims.UserID != tc.wantUserID {
					t.Fatalf("uid = %v, want %v", claims.UserID, tc.wantUserID)
				}

				var rawClaims map[string]json.RawMessage
				if err := token.Claims(oidcTestingPublicKey(t), &rawClaims); err != nil {
					t.Fatal(err)
				}
				if _, ok := rawClaims["stable_node_id"]; ok != (who.Node.StableID != "") {
					t.Error("unexpected stable_node_id claim presence")
				}

				if claims.Email != tc.wantEmail {
					t.Errorf("email = %q, want %q", claims.Email, tc.wantEmail)
				}
				if _, ok := rawClaims["email"]; ok != (tc.wantEmail != "") {
					t.Error("unexpected email claim presence")
				}

				if claims.PreferredUsername != tc.wantUsername {
					t.Errorf("preferred_username = %q, want %q", claims.PreferredUsername, tc.wantUsername)
				}
				if _, ok := rawClaims["preferred_username"]; ok != (tc.wantUsername != "") {
					t.Error("unexpected preferred_username claim presence")
				}
				if len(tc.wantGroups) == 0 {
					if _, ok := rawClaims["groups"]; ok {
						t.Error("unexpected groups claim")
					}
				} else {
					var groups []string
					if err := json.Unmarshal(rawClaims["groups"], &groups); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(groups, tc.wantGroups) {
						t.Errorf("groups = %v, want %v", groups, tc.wantGroups)
					}
				}
				if claims.ID == "" {
					t.Fatal("missing jti")
				}
				if len(s.accessToken) != 0 || len(s.refreshToken) != 0 {
					t.Fatal("unexpected OAuth tokens")
				}
			})
		})
	}
}

func TestIdentityTokenAudienceGrants(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rules  string
		status int
	}{
		{"missing capability", "", 403},
		{"missing audiences", `{}`, 403},
		{"empty audiences", `{"identityTokenAudiences":[]}`, 403},
		{"null audiences", `{"identityTokenAudiences":null}`, 403},
		{"different audience", `{"identityTokenAudiences":["https://other.example"]}`, 403},
		{"no prefix matching", `{"identityTokenAudiences":["https://service.example/path"]}`, 403},
		{"no case folding", `{"identityTokenAudiences":["https://SERVICE.example"]}`, 403},
		{"wildcard", `{"identityTokenAudiences":["*"]}`, 200},
		{"wildcard with exact audience", `{"identityTokenAudiences":["https://other.example","*"]}`, 200},
		{"wildcard in another grant", `{"identityTokenAudiences":["https://other.example"]},{"identityTokenAudiences":["*"]}`, 200},
		{"no domain glob", `{"identityTokenAudiences":["https://*.example"]}`, 403},
		{"no suffix glob", `{"identityTokenAudiences":["https://service.*"]}`, 403},
		{"sts permission alone", `{"users":["*"],"resources":["*"]}`, 403},
		{"exact match", `{"identityTokenAudiences":["https://service.example"]}`, 200},
		{"multiple audiences", `{"identityTokenAudiences":["https://other.example","https://service.example"]}`, 200},
		{"multiple grants", `{"identityTokenAudiences":["https://other.example"]},{"identityTokenAudiences":["https://service.example"]}`, 200},
		{"independent of sts users", `{"users":["someone@example.com"],"identityTokenAudiences":["https://service.example"]}`, 200},
		{"invalid audience type", `{"identityTokenAudiences":true}`, 500},
		{"invalid grant after allow", `{"identityTokenAudiences":["https://service.example"]},{"identityTokenAudiences":true}`, 500},
		{"invalid grant after wildcard", `{"identityTokenAudiences":["*"]},{"identityTokenAudiences":true}`, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			who := &apitype.WhoIsResponse{Node: &tailcfg.Node{ID: 42, Tags: []string{"tag:ci"}}}
			if tc.rules != "" {
				var rules []tailcfg.RawMessage
				if err := json.Unmarshal([]byte("["+tc.rules+"]"), &rules); err != nil {
					t.Fatal(err)
				}
				who.CapMap = tailcfg.PeerCapMap{tailcfg.PeerCapabilityTsIDP: rules}
			}
			s := setupTestServer(t, newTestWhoIsClient(t, who, false))
			s.enableIDToken = true
			r := httptest.NewRequest("POST", "/identity-token", strings.NewReader("audience=https://service.example"))
			r.RemoteAddr = "100.64.0.1:1234"
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Tsidp-Identity-Token", "true")
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if tc.status != http.StatusOK {
				var response struct {
					IDToken string `json:"id_token"`
					Error   string `json:"error"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if response.IDToken != "" || response.Error == "" {
					t.Fatalf("expected error without token, got %s", w.Body.String())
				}
				return
			}
			var response struct {
				IDToken string `json:"id_token"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			token, err := jwt.ParseSigned(response.IDToken)
			if err != nil {
				t.Fatal(err)
			}
			var claims jwt.Claims
			if err := token.Claims(oidcTestingPublicKey(t), &claims); err != nil {
				t.Fatal(err)
			}
			if len(claims.Audience) != 1 || claims.Audience[0] != "https://service.example" {
				t.Fatalf("audience = %v, want [https://service.example]", claims.Audience)
			}
		})
	}
}
