package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/oauth2"
)

func (a *App) githubConfigured() bool {
	return os.Getenv("GITHUB_CLIENT_ID") != "" && os.Getenv("GITHUB_CLIENT_SECRET") != ""
}
func (a *App) oidcConfigured() bool {
	return os.Getenv("OIDC_ISSUER") != "" && os.Getenv("OIDC_CLIENT_ID") != "" && os.Getenv("OIDC_CLIENT_SECRET") != ""
}
func (a *App) ldapConfigured() bool {
	u, err := url.Parse(os.Getenv("LDAP_URL"))
	return err == nil && (u.Scheme == "ldap" || u.Scheme == "ldaps") && u.Host != "" && os.Getenv("LDAP_BASE_DN") != ""
}

func (a *App) flowCookie(w http.ResponseWriter, kind string, parts ...string) {
	http.SetCookie(w, &http.Cookie{Name: "auth_flow_" + kind, Value: strings.Join(parts, "."), Path: "/auth/" + kind + "/callback", MaxAge: 600, Expires: time.Now().Add(10 * time.Minute), HttpOnly: true, Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode})
}
func (a *App) takeFlow(w http.ResponseWriter, r *http.Request, kind string, n int) ([]string, error) {
	c, err := r.Cookie("auth_flow_" + kind)
	http.SetCookie(w, &http.Cookie{Name: "auth_flow_" + kind, Path: "/auth/" + kind + "/callback", MaxAge: -1, HttpOnly: true, Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode})
	if err != nil {
		return nil, err
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != n {
		return nil, errors.New("invalid oauth state cookie")
	}
	if subtle.ConstantTimeCompare([]byte(parts[0]), []byte(r.URL.Query().Get("state"))) != 1 {
		return nil, errors.New("oauth state mismatch")
	}
	if r.URL.Query().Get("code") == "" || r.URL.Query().Get("error") != "" {
		return nil, errors.New("provider rejected authentication")
	}
	return parts, nil
}
func (a *App) githubStart(w http.ResponseWriter, r *http.Request) {
	gh, _, _ := a.authModes()
	if !gh {
		http.Redirect(w, r, "/login?error=disabled", 303)
		return
	}
	state := randomID(24)
	verifier := randomID(32)
	challenge := sha256.Sum256([]byte(verifier))
	a.flowCookie(w, "github", state, verifier)
	v := url.Values{"client_id": {os.Getenv("GITHUB_CLIENT_ID")}, "redirect_uri": {a.baseURL + "/auth/github/callback"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}}
	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+v.Encode(), http.StatusFound)
}
func (a *App) githubCallback(w http.ResponseWriter, r *http.Request) {
	gh, _, _ := a.authModes()
	if !gh {
		http.Redirect(w, r, "/login?error=disabled", 303)
		return
	}
	parts, err := a.takeFlow(w, r, "github", 2)
	if err != nil {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	values := url.Values{"client_id": {os.Getenv("GITHUB_CLIENT_ID")}, "client_secret": {os.Getenv("GITHUB_CLIENT_SECRET")}, "code": {r.URL.Query().Get("code")}, "redirect_uri": {a.baseURL + "/auth/github/callback"}, "code_verifier": {parts[1]}}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://github.com/login/oauth/access_token", strings.NewReader(values.Encode()))
	if err != nil {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := a.httpClient.Do(req)
	if err != nil {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	defer res.Body.Close()
	var token struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 8192)).Decode(&token) != nil || token.AccessToken == "" || token.Error != "" {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	req, err = http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	res2, err := a.httpClient.Do(req)
	if err != nil {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	defer res2.Body.Close()
	var profile struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	if res2.StatusCode != 200 || json.NewDecoder(io.LimitReader(res2.Body, 8192)).Decode(&profile) != nil || profile.ID <= 0 {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	userID, err := a.externalUser("github", fmt.Sprint(profile.ID), "gh_"+profile.Login)
	if err != nil || a.startSession(w, userID) != nil {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	http.Redirect(w, r, "/admin", 303)
}
func (a *App) oidcConfig(ctx context.Context) (*oidc.Provider, *oauth2.Config, error) {
	provider, err := oidc.NewProvider(ctx, os.Getenv("OIDC_ISSUER"))
	if err != nil {
		return nil, nil, err
	}
	cfg := &oauth2.Config{ClientID: os.Getenv("OIDC_CLIENT_ID"), ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"), RedirectURL: a.baseURL + "/auth/oidc/callback", Endpoint: provider.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
	return provider, cfg, nil
}
func (a *App) providerContext(ctx context.Context) context.Context {
	// oidc and oauth2 use the configured HTTP client, with TLS verification.
	return oidc.ClientContext(context.WithValue(ctx, oauth2.HTTPClient, a.httpClient), a.httpClient)
}
func (a *App) oidcStart(w http.ResponseWriter, r *http.Request) {
	_, enabled, _ := a.authModes()
	if !enabled {
		http.Redirect(w, r, "/login?error=disabled", 303)
		return
	}
	ctx, cancel := context.WithTimeout(a.providerContext(r.Context()), 10*time.Second)
	defer cancel()
	_, cfg, err := a.oidcConfig(ctx)
	if err != nil {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	state, nonce, verifier := randomID(24), randomID(24), randomID(32)
	a.flowCookie(w, "oidc", state, nonce, verifier)
	http.Redirect(w, r, cfg.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}
func (a *App) oidcCallback(w http.ResponseWriter, r *http.Request) {
	_, enabled, _ := a.authModes()
	if !enabled {
		http.Redirect(w, r, "/login?error=disabled", 303)
		return
	}
	parts, err := a.takeFlow(w, r, "oidc", 3)
	if err != nil {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	ctx, cancel := context.WithTimeout(a.providerContext(r.Context()), 12*time.Second)
	defer cancel()
	provider, cfg, err := a.oidcConfig(ctx)
	if err != nil {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	token, err := cfg.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(parts[2]))
	if err != nil {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	verified, err := provider.Verifier(&oidc.Config{ClientID: os.Getenv("OIDC_CLIENT_ID")}).Verify(ctx, raw)
	if err != nil || subtle.ConstantTimeCompare([]byte(verified.Nonce), []byte(parts[1])) != 1 {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	var claims struct {
		Preferred string `json:"preferred_username"`
		Name      string `json:"name"`
	}
	if verified.Claims(&claims) != nil {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	subject := os.Getenv("OIDC_ISSUER") + "|" + verified.Subject
	preferred := claims.Preferred
	if preferred == "" {
		preferred = claims.Name
	}
	preferred = strings.ReplaceAll(strings.ReplaceAll(preferred, " ", "_"), "@", "_")
	if len(preferred) > 28 {
		preferred = preferred[:28]
	}
	userID, err := a.externalUser("oidc", subject, "oidc_"+preferred)
	if err != nil || a.startSession(w, userID) != nil {
		http.Redirect(w, r, "/login?error=oauth", 303)
		return
	}
	http.Redirect(w, r, "/admin", 303)
}

// Authenticate using an encrypted channel; never allow plaintext LDAP binds.
// The service bind performs a search, followed by a bind as the actual user.
func (a *App) authenticateLDAP(username, password string) (string, error) {
	if password == "" || !validUsername.MatchString(username) {
		return "", errors.New("invalid username or password")
	}
	rawURL := os.Getenv("LDAP_URL")
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsed.Hostname()}
	if parsed.Scheme != "ldap" && parsed.Scheme != "ldaps" {
		return "", errors.New("invalid LDAP scheme")
	}
	conn, err := ldap.DialURL(rawURL, ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetTimeout(8 * time.Second)
	if parsed.Scheme == "ldap" {
		if err = conn.StartTLS(tlsConfig); err != nil {
			return "", err
		}
	}
	if bindDN := os.Getenv("LDAP_BIND_DN"); bindDN != "" {
		if err = conn.Bind(bindDN, os.Getenv("LDAP_BIND_PASSWORD")); err != nil {
			return "", err
		}
	}
	filter := env("LDAP_USER_FILTER", "(uid=%s)")
	if strings.Count(filter, "%s") != 1 {
		return "", errors.New("LDAP_USER_FILTER must have one %s")
	}
	query := strings.Replace(filter, "%s", ldap.EscapeFilter(username), 1)
	request := ldap.NewSearchRequest(os.Getenv("LDAP_BASE_DN"), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 8, false, query, []string{"dn"}, nil)
	result, err := conn.Search(request)
	if err != nil || len(result.Entries) != 1 {
		return "", errors.New("LDAP user not found or ambiguous")
	}
	dn := result.Entries[0].DN
	if err = conn.Bind(dn, password); err != nil {
		return "", err
	}
	return strings.ToLower(dn), nil
}
