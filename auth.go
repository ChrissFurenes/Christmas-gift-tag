package main

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var validUsername = regexp.MustCompile(`^[A-Za-z0-9_.-]{3,40}$`)

func (a *App) secureCookies() bool { return strings.HasPrefix(a.baseURL, "https://") }

// validOrigin checks that a browser POST originated from the address used for
// this request. BASE_URL is the canonical address for links and OAuth callbacks,
// not necessarily the address used to access the app locally.
//
// When an HTTPS reverse proxy terminates TLS, requests reach Go over HTTP.
// In that case BASE_URL establishes the expected HTTPS scheme *only* when its
// hostname matches the incoming Host header. Do not trust arbitrary forwarded
// protocol headers supplied by clients.
func (a *App) validOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	o, err := url.Parse(origin)
	if err != nil || (o.Scheme != "http" && o.Scheme != "https") ||
		o.Host == "" || o.User != nil || o.Opaque != "" ||
		o.Path != "" || o.RawQuery != "" || o.Fragment != "" {
		log.Printf("origin rejected: Origin=%q request Host=%q (invalid origin)", origin, r.Host)
		return false
	}
	if !strings.EqualFold(o.Host, r.Host) {
		log.Printf("origin rejected: Origin=%q request Host=%q (host mismatch)", origin, r.Host)
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if b, err := url.Parse(a.baseURL); err == nil &&
		strings.EqualFold(b.Host, r.Host) && b.Scheme == "https" {
		// HTTPS was terminated by the reverse proxy on the canonical host.
		scheme = "https"
	}
	if o.Scheme != scheme {
		log.Printf("origin rejected: Origin=%q request Host=%q (expected scheme %q)", origin, r.Host, scheme)
		return false
	}
	return true
}
func (a *App) currentUser(r *http.Request) (User, string, bool) {
	cookie, err := r.Cookie("gift_session")
	if err != nil {
		return User{}, "", false
	}
	var u User
	var admin, enabled int
	var expires int64
	var csrf string
	err = a.db.QueryRow(`SELECT u.id,u.username,u.display_name,u.provider,u.is_admin,u.enabled,s.csrf,s.expires_at
  FROM sessions s INNER JOIN users u ON s.user_id=u.id WHERE s.token_hash=?`, shaToken(cookie.Value)).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Provider, &admin, &enabled, &csrf, &expires)
	if err != nil || enabled == 0 || expires <= time.Now().Unix() {
		return User{}, "", false
	}
	u.IsAdmin = admin != 0
	u.Enabled = true
	return u, csrf, true
}
func (a *App) requireUser(w http.ResponseWriter, r *http.Request) (User, string, bool) {
	u, csrf, ok := a.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return User{}, "", false
	}
	return u, csrf, true
}
func (a *App) requireUserPost(w http.ResponseWriter, r *http.Request) (User, string, bool) {
	u, csrf, ok := a.requireUser(w, r)
	if !ok {
		return User{}, "", false
	}
	if !a.validOrigin(r) {
		http.Error(w, "Ugyldig opprinnelse", 403)
		return User{}, "", false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Ugyldig skjema", 400)
		return User{}, "", false
	}
	if subtle.ConstantTimeCompare([]byte(csrf), []byte(r.PostForm.Get("csrf"))) != 1 {
		http.Error(w, "Ugyldig sikkerhetstoken", 403)
		return User{}, "", false
	}
	return u, csrf, true
}
func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) (User, string, bool) {
	u, csrf, ok := a.requireUser(w, r)
	if !ok {
		return User{}, "", false
	}
	if !u.IsAdmin {
		http.Error(w, "Ikke tilgang", 403)
		return User{}, "", false
	}
	return u, csrf, true
}
func (a *App) requireAdminPost(w http.ResponseWriter, r *http.Request) (User, string, bool) {
	u, csrf, ok := a.requireUserPost(w, r)
	if !ok {
		return User{}, "", false
	}
	if !u.IsAdmin {
		http.Error(w, "Ikke tilgang", 403)
		return User{}, "", false
	}
	return u, csrf, true
}
func (a *App) startSession(w http.ResponseWriter, userID string) error {
	secret := randomID(32)
	expires := time.Now().Add(7 * 24 * time.Hour).Unix()
	if _, err := a.db.Exec(`DELETE FROM sessions WHERE expires_at<?`, time.Now().Unix()); err != nil {
		return err
	}
	_, err := a.db.Exec(`INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)`, shaToken(secret), userID, randomID(24), expires)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: "gift_session", Value: secret, Path: "/", MaxAge: 7 * 86400, Expires: time.Unix(expires, 0), HttpOnly: true, Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode})
	return nil
}
func (a *App) authModes() (github, oidc, ldap bool) {
	return a.setting("github_enabled") && a.githubConfigured(), a.setting("oidc_enabled") && a.oidcConfigured(), a.setting("ldap_enabled") && a.ldapConfigured()
}
func (a *App) setting(key string) bool {
	var val string
	if err := a.db.QueryRow("SELECT value FROM settings WHERE key=?", key).Scan(&val); err != nil {
		return false
	}
	return val == "1"
}

// If explicitly supplied, LOCAL_SIGNUP_ENABLED in .env overrides the UI toggle.
// If unset, the historical admin setting remains in control.
func (a *App) localSignupEnabled() bool {
	raw, exists := os.LookupEnv("LOCAL_SIGNUP_ENABLED")
	if exists && strings.TrimSpace(raw) != "" {
		enabled, err := strconv.ParseBool(strings.TrimSpace(raw))
		return err == nil && enabled // fail closed for invalid values
	}
	return a.setting("local_signup_enabled")
}
func localSignupEnvManaged() bool {
	return strings.TrimSpace(os.Getenv("LOCAL_SIGNUP_ENABLED")) != ""
}
func (a *App) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.currentUser(r); ok {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	github, oidc, ldap := a.authModes()
	errText := ""
	switch r.URL.Query().Get("error") {
	case "oauth":
		errText = "Ekstern innlogging feilet. Prøv igjen."
	case "disabled":
		errText = "Innloggingstjenesten er ikke aktivert."
	}
	render(w, "login.html", Page{GitHubEnabled: github, OIDCEnabled: oidc, LDAPEnabled: ldap, LocalSignupEnabled: a.localSignupEnabled(), Error: errText})
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if !a.validOrigin(r) {
		http.Error(w, "Ugyldig opprinnelse", 403)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Ugyldig skjema", 400)
		return
	}
	username := strings.TrimSpace(r.PostForm.Get("username"))
	password := r.PostForm.Get("password")
	key := a.rateLimitKey(r, "login:"+strings.ToLower(username))
	if !a.canTryPassword(key) {
		http.Error(w, "For mange forsøk. Prøv igjen om 15 minutter.", 429)
		return
	}
	var userID, encoded string
	var enabled int
	err := a.db.QueryRow("SELECT id,password_hash,enabled FROM users WHERE username=? AND provider='local'", username).Scan(&userID, &encoded, &enabled)
	success := err == nil && enabled == 1 && checkGiftPassword(password, encoded)
	// LDAP accounts are provisioned separately. Never map them to local accounts by name.
	if !success && a.setting("ldap_enabled") && a.ldapConfigured() && validUsername.MatchString(username) && password != "" {
		subject, ldapErr := a.authenticateLDAP(username, password)
		if ldapErr == nil {
			userID, err = a.externalUser("ldap", subject, "ldap_"+username)
			success = err == nil
		}
	}
	a.recordAttempt(key, success)
	if !success {
		github, oidc, ldap := a.authModes()
		w.WriteHeader(401)
		render(w, "login.html", Page{GitHubEnabled: github, OIDCEnabled: oidc, LDAPEnabled: ldap, LocalSignupEnabled: a.localSignupEnabled(), Error: "Ugyldig brukernavn eller passord"})
		return
	}
	if err := a.startSession(w, userID); err != nil {
		http.Error(w, "Kunne ikke opprette økt", 500)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.requireUserPost(w, r); !ok {
		return
	}
	if cookie, err := r.Cookie("gift_session"); err == nil {
		_, _ = a.db.Exec("DELETE FROM sessions WHERE token_hash=?", shaToken(cookie.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: "gift_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func (a *App) usersPage(w http.ResponseWriter, r *http.Request) {
	u, csrf, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	p := Page{User: u, CSRF: csrf, GitHubConfigured: a.githubConfigured(), OIDCConfigured: a.oidcConfigured(), LDAPConfigured: a.ldapConfigured()}
	p.GitHubEnabled = a.setting("github_enabled")
	p.OIDCEnabled = a.setting("oidc_enabled")
	p.LDAPEnabled = a.setting("ldap_enabled")
	p.LocalSignupEnabled = a.localSignupEnabled()
	p.LocalSignupEnvManaged = localSignupEnvManaged()
	rows, err := a.db.Query(`SELECT u.id,u.username,u.provider,u.is_admin,u.enabled,
   (SELECT COUNT(*) FROM gifts g WHERE g.owner_id=u.id) FROM users u ORDER BY u.is_admin DESC, u.username`)
	if err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var user User
		var admin, enabled int
		if err := rows.Scan(&user.ID, &user.Username, &user.Provider, &admin, &enabled, &user.LabelCount); err != nil {
			http.Error(w, "Databasefeil", 500)
			return
		}
		user.IsAdmin = admin != 0
		user.Enabled = enabled != 0
		p.Users = append(p.Users, user)
	}
	if rows.Err() != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	if r.URL.Query().Get("saved") == "1" {
		p.Success = "Innstillingene er lagret."
	}
	render(w, "users.html", p)
}
func (a *App) createUser(w http.ResponseWriter, r *http.Request) {
	_, _, ok := a.requireAdminPost(w, r)
	if !ok {
		return
	}
	username := strings.TrimSpace(r.PostForm.Get("username"))
	displayName := strings.TrimSpace(r.PostForm.Get("display_name"))
	if displayName == "" {
		displayName = username
	}
	password := r.PostForm.Get("password")
	if len(displayName) > 120 || !validUsername.MatchString(username) || len(password) < 12 || len(password) > 256 {
		http.Error(w, "Brukernavn må ha 3–40 tegn; passord minst 12 tegn", 400)
		return
	}
	hash, err := hashGiftPassword(password)
	if err != nil {
		http.Error(w, "Kunne ikke lagre passord", 500)
		return
	}
	_, err = a.db.Exec(`INSERT INTO users(id,username,display_name,password_hash,provider,provider_subject,created_at) VALUES(?,?,?,?,'local',?,?)`, randomID(16), username, displayName, hash, randomID(8), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		http.Error(w, "Brukernavnet er kanskje opptatt", 409)
		return
	}
	http.Redirect(w, r, "/admin/users", 303)
}
func (a *App) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	u, _, ok := a.requireUserPost(w, r)
	if !ok {
		return
	}
	if u.Provider != "local" {
		http.Error(w, "Passord må endres hos innloggingstjenesten", 400)
		return
	}
	oldPass, newPass := r.PostForm.Get("current_password"), r.PostForm.Get("new_password")
	if len(newPass) < 12 || len(newPass) > 256 {
		http.Error(w, "Nytt passord må ha minst 12 tegn", 400)
		return
	}
	var encoded string
	if err := a.db.QueryRow("SELECT password_hash FROM users WHERE id=?", u.ID).Scan(&encoded); err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	if !checkGiftPassword(oldPass, encoded) {
		http.Error(w, "Feil nåværende passord", 403)
		return
	}
	hash, err := hashGiftPassword(newPass)
	if err != nil {
		http.Error(w, "Kunne ikke lagre passord", 500)
		return
	}
	tx, err := a.db.Begin()
	if err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	defer tx.Rollback()
	if _, err = tx.Exec("UPDATE users SET password_hash=? WHERE id=?", hash, u.ID); err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	if _, err = tx.Exec("DELETE FROM sessions WHERE user_id=?", u.ID); err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "gift_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/login", 303)
}
func (a *App) toggleUser(w http.ResponseWriter, r *http.Request) {
	admin, _, ok := a.requireAdminPost(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if admin.ID == id {
		http.Error(w, "Du kan ikke deaktivere din egen konto", 400)
		return
	}
	var isAdmin int
	var enabled int
	if err := a.db.QueryRow("SELECT is_admin,enabled FROM users WHERE id=?", id).Scan(&isAdmin, &enabled); err != nil {
		http.NotFound(w, r)
		return
	}
	if isAdmin != 0 {
		http.Error(w, "Kan ikke endre en administratorkonto", 403)
		return
	}
	_, err := a.db.Exec("UPDATE users SET enabled=? WHERE id=?", 1-enabled, id)
	if err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	if enabled == 1 {
		_, _ = a.db.Exec("DELETE FROM sessions WHERE user_id=?", id)
	}
	http.Redirect(w, r, "/admin/users", 303)
}
func (a *App) userInfo(id string) (User, error) {
	var u User
	var admin, enabled int
	err := a.db.QueryRow(`SELECT u.id,u.username,u.display_name,u.provider,u.is_admin,u.enabled,(SELECT COUNT(*) FROM gifts WHERE owner_id=u.id) FROM users u WHERE u.id=?`, id).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Provider, &admin, &enabled, &u.LabelCount)
	u.IsAdmin = admin != 0
	u.Enabled = enabled != 0
	return u, err
}
func (a *App) userDeletePage(w http.ResponseWriter, r *http.Request) {
	admin, csrf, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	u, err := a.userInfo(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if u.IsAdmin || admin.ID == u.ID {
		http.Error(w, "En administrator kan ikke slettes her", 403)
		return
	}
	render(w, "delete-user.html", Page{User: admin, Gift: Gift{ID: u.ID}, DeleteUsername: u.Username, DeleteCount: u.LabelCount, CSRF: csrf})
}
func (a *App) deleteUser(w http.ResponseWriter, r *http.Request) {
	admin, _, ok := a.requireAdminPost(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if admin.ID == id {
		http.Error(w, "Kan ikke slette deg selv", 403)
		return
	}
	tx, err := a.db.Begin()
	if err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	defer tx.Rollback()
	var username string
	var adminFlag, count int
	if err := tx.QueryRow("SELECT username,is_admin FROM users WHERE id=?", id).Scan(&username, &adminFlag); err != nil {
		http.NotFound(w, r)
		return
	}
	if adminFlag != 0 {
		http.Error(w, "Kan ikke slette administratorkontoer", 403)
		return
	}
	if err := tx.QueryRow("SELECT COUNT(*) FROM gifts WHERE owner_id=?", id).Scan(&count); err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	expected, err := strconv.Atoi(r.PostForm.Get("expected_count"))
	if err != nil || expected != count || r.PostForm.Get("confirm_username") != username || r.PostForm.Get("confirm_delete") != "on" {
		http.Error(w, fmt.Sprintf("Bekreft sletting og antall etiketter (%d). Åpne bekreftelsessiden på nytt dersom antallet har endret seg.", count), 409)
		return
	}
	if _, err = tx.Exec("DELETE FROM gifts WHERE owner_id=?", id); err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	if _, err = tx.Exec("DELETE FROM sessions WHERE user_id=?", id); err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	if _, err = tx.Exec("DELETE FROM users WHERE id=?", id); err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	http.Redirect(w, r, "/admin/users", 303)
}
func (a *App) saveSettings(w http.ResponseWriter, r *http.Request) {
	_, _, ok := a.requireAdminPost(w, r)
	if !ok {
		return
	}
	values := map[string]bool{"github_enabled": a.githubConfigured(), "oidc_enabled": a.oidcConfigured(), "ldap_enabled": a.ldapConfigured()}
	if !localSignupEnvManaged() {
		values["local_signup_enabled"] = true
	}
	for k, configured := range values {
		v := "0"
		if configured && r.PostForm.Get(k) == "on" {
			v = "1"
		}
		if _, err := a.db.Exec("UPDATE settings SET value=? WHERE key=?", v, k); err != nil {
			http.Error(w, "Databasefeil", 500)
			return
		}
	}
	http.Redirect(w, r, "/admin/users?saved=1", 303)
}

// Uses the immutable external provider ID (not email or display name) as the
// account identity. An external login never inherits an existing local user.
func (a *App) externalUser(provider, subject, preferred string) (string, error) {
	if subject == "" {
		return "", errors.New("missing external subject")
	}
	var id string
	var enabled int
	err := a.db.QueryRow("SELECT id,enabled FROM users WHERE provider=? AND provider_subject=?", provider, subject).Scan(&id, &enabled)
	if err == nil {
		if enabled == 0 {
			return "", errors.New("account disabled")
		}
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if !validUsername.MatchString(preferred) {
		preferred = provider + "_user"
	}
	id = randomID(16)
	_, err = a.db.Exec(`INSERT INTO users(id,username,display_name,provider,provider_subject,created_at) VALUES(?,?,?,?,?,?)`, id, preferred, preferred, provider, subject, time.Now().UTC().Format(time.RFC3339))
	if err == nil {
		return id, nil
	}
	// If the name is in use, create a unique display name; never link by name.
	preferred = provider + "_" + id[:12]
	_, err = a.db.Exec(`INSERT INTO users(id,username,display_name,provider,provider_subject,created_at) VALUES(?,?,?,?,?,?)`, id, preferred, preferred, provider, subject, time.Now().UTC().Format(time.RFC3339))
	if err == nil {
		return id, nil
	}
	// Concurrent OAuth requests for the same identity might race.
	var checkEnabled int
	if err2 := a.db.QueryRow("SELECT id,enabled FROM users WHERE provider=? AND provider_subject=?", provider, subject).Scan(&id, &checkEnabled); err2 == nil && checkEnabled == 1 {
		return id, nil
	}
	return "", err
}

func (a *App) changeDisplayName(w http.ResponseWriter, r *http.Request) {
	u, _, ok := a.requireUserPost(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("display_name"))
	if name == "" || len(name) > 120 {
		http.Error(w, "Navn må inneholde 1–120 tegn", 400)
		return
	}
	if _, err := a.db.Exec("UPDATE users SET display_name=? WHERE id=?", name, u.ID); err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	http.Redirect(w, r, "/admin", 303)
}
func (a *App) registerPage(w http.ResponseWriter, r *http.Request) {
	if !a.localSignupEnabled() {
		http.Redirect(w, r, "/login", 303)
		return
	}
	if _, _, ok := a.currentUser(r); ok {
		http.Redirect(w, r, "/admin", 303)
		return
	}
	render(w, "register.html", Page{})
}
func (a *App) register(w http.ResponseWriter, r *http.Request) {
	if !a.localSignupEnabled() {
		http.Error(w, "Registrering er ikke aktivert", 403)
		return
	}
	if !a.validOrigin(r) {
		http.Error(w, "Ugyldig opprinnelse", 403)
		return
	}
	key := a.rateLimitKey(r, "local-registration")
	if !a.canTryPassword(key) {
		http.Error(w, "For mange registreringsforsøk", 429)
		return
	}
	a.recordAttempt(key, false) // Limit both successful and unsuccessful attempts per IP.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Ugyldig skjema", 400)
		return
	}
	username := strings.TrimSpace(r.PostForm.Get("username"))
	displayName := strings.TrimSpace(r.PostForm.Get("display_name"))
	if displayName == "" {
		displayName = username
	}
	password := r.PostForm.Get("password")
	if len(displayName) > 120 || !validUsername.MatchString(username) || len(password) < 12 || len(password) > 256 || password != r.PostForm.Get("password_confirm") {
		w.WriteHeader(400)
		render(w, "register.html", Page{Error: "Ugyldig brukernavn eller passord (minst 12 tegn); passordene må være like."})
		return
	}
	hash, err := hashGiftPassword(password)
	if err != nil {
		http.Error(w, "Kunne ikke lagre passord", 500)
		return
	}
	id := randomID(16)
	_, err = a.db.Exec(`INSERT INTO users(id,username,display_name,password_hash,provider,provider_subject,created_at) VALUES(?,?,?,?,'local',?,?)`, id, username, displayName, hash, randomID(8), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		w.WriteHeader(409)
		render(w, "register.html", Page{Error: "Brukernavnet er opptatt."})
		return
	}
	if err := a.startSession(w, id); err != nil {
		http.Error(w, "Kunne ikke starte økt", 500)
		return
	}
	http.Redirect(w, r, "/admin", 303)
}
