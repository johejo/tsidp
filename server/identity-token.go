// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// GET or POST /identity-token issues a signed token identifying the connecting Tailscale
// node, without client registration or an authorization-code flow.
// GET accepts audience in the query string; POST also accepts form data.

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/util/rands"
)

// serveIdentityToken authenticates the peer node. Any process able to connect
// from an allowed node can request a token.
func (s *IDPServer) serveIdentityToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if !s.enableIDToken {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "GET or POST required", nil)
		return
	}
	// Requiring a non-safelisted header prevents cross-origin browser requests.
	// This endpoint intentionally does not enable CORS.
	if r.Header.Get("Tsidp-Identity-Token") != "true" {
		writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied, "Tsidp-Identity-Token: true header required", nil)
		return
	}
	if r.Header.Get("Origin") != "" {
		writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied, "browser requests with an Origin header are not supported", nil)
		return
	}
	// Keep identity lookup bound to a direct tsnet peer. Proxied connections and
	// forwarded headers cannot establish the originating node's identity.
	if s.localTSMode {
		writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied, "identity tokens are not supported with --use-local-tailscaled", nil)
		return
	}
	if isFunnelRequest(r) {
		writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied, "identity tokens are not available over Funnel", nil)
		return
	}
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied, "invalid peer address", err)
		return
	}
	if !tsaddr.IsTailscaleIP(peer.Addr()) {
		writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied, "peer address must be a Tailscale IP", nil)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "invalid form", err)
		return
	}
	audience := r.FormValue("audience")
	if strings.TrimSpace(audience) == "" {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "audience is required", nil)
		return
	}
	if s.lc == nil {
		writeHTTPError(w, r, http.StatusServiceUnavailable, ecServerError, "identity lookup unavailable", nil)
		return
	}
	who, err := s.lc.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil || who == nil || who.Node == nil || who.Node.ID == 0 {
		writeHTTPError(w, r, http.StatusUnauthorized, ecAccessDenied, "could not identify node", err)
		return
	}
	rules, err := tailcfg.UnmarshalCapJSON[capRule](who.CapMap, tailcfg.PeerCapabilityTsIDP)
	if err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed unmarshaling app cap rule", err)
		return
	}
	// Machine-token issuance is a separate permission from STS token exchange:
	// existing users/resources grants must not implicitly enable this endpoint.
	allowed := false
	for _, rule := range rules {
		if slices.Contains(rule.IdentityTokenAudiences, audience) || slices.Contains(rule.IdentityTokenAudiences, "*") {
			allowed = true
			break
		}
	}
	if !allowed {
		writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied, "audience is not allowed", nil)
		return
	}
	signer, err := s.oidcSigner()
	if err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "could not get signer", err)
		return
	}
	now := time.Now()
	n := who.Node.View()
	expiry := now.Add(TokenDuration)
	if keyExpiry := n.KeyExpiry(); !keyExpiry.IsZero() && keyExpiry.Before(expiry) {
		expiry = keyExpiry
	}
	// JWT NumericDate has second precision. Do not issue a token whose
	// serialized expiration has already passed, even for a nearly expired key.
	expiry = expiry.Truncate(time.Second)
	if n.Expired() || !expiry.After(now) {
		writeHTTPError(w, r, http.StatusUnauthorized, ecAccessDenied, "node key has expired or is about to expire", nil)
		return
	}
	claims := jwt.Claims{
		Issuer:    s.serverURL,
		Subject:   fmt.Sprintf("node:%d", who.Node.ID),
		Audience:  jwt.Audience{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-NotValidBeforeClockSkew)),
		Expiry:    jwt.NewNumericDate(expiry),
		ID:        rands.HexString(32),
	}
	_, tailnet, _ := strings.Cut(n.Name(), ".")
	tsClaims := tailscaleClaims{
		Claims:    claims,
		Key:       n.Key(),
		Addresses: n.Addresses(),
		NodeID:    n.ID(),
		NodeName:  n.Name(),
		Tailnet:   tailnet,
	}
	// Owner claims do not identify the user or process making the request.
	var groups []string
	if !n.IsTagged() {
		tsClaims.UserID = n.User()
		if profile := who.UserProfile; profile != nil {
			tsClaims.Email = s.realishEmail(profile.LoginName)
			if username, _, ok := strings.Cut(profile.LoginName, "@"); ok {
				tsClaims.PreferredUsername = username
			}
			// Missing groups do not imply that the owner belongs to no groups.
			groups = profile.Groups
		}
	}
	// Exclude capability extraClaims to prevent overriding the node identity.
	machineClaims := struct {
		tailscaleClaims
		StableNodeID tailcfg.StableNodeID `json:"stable_node_id,omitempty"`
		Tags         []string             `json:"tags,omitempty"`
		Groups       []string             `json:"groups,omitempty"`
	}{tsClaims, n.StableID(), n.Tags().AsSlice(), groups}
	token, err := jwt.Signed(signer).Claims(machineClaims).CompactSerialize()
	if err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "could not sign identity token", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		IDToken   string `json:"id_token"`
		ExpiresIn int    `json:"expires_in"`
	}{token, int(*claims.Expiry - *claims.IssuedAt)})
}
