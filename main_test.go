package main

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testApp(t *testing.T) *App {
	t.Helper()
	t.Setenv("TICKET_SECRET", "test-sufficiently-secret-key-for-gift-tickets")
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if err := initDB(db, "safe-admin-password-123"); err != nil {
		t.Fatal(err)
	}
	return &App{db: db, baseURL: "http://localhost:8080", attempts: map[string]attempt{}}
}
func mustExec(t *testing.T, a *App, q string, args ...any) {
	t.Helper()
	if _, err := a.db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}
func insertUser(t *testing.T, a *App, id, name string) {
	t.Helper()
	mustExec(t, a, "INSERT INTO users(id,username,provider,provider_subject,created_at) VALUES(?,?,?,?,?)", id, name, "local", id, "2026-11-13")
}
func sessionFor(t *testing.T, a *App, userID string) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	if err := a.startSession(w, userID); err != nil {
		t.Fatal(err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "gift_session" {
			return c
		}
	}
	t.Fatal("session cookie not set")
	return nil
}
func csrfFor(t *testing.T, a *App, c *http.Cookie) string {
	t.Helper()
	var csrf string
	if err := a.db.QueryRow("SELECT csrf FROM sessions WHERE token_hash=?", shaToken(c.Value)).Scan(&csrf); err != nil {
		t.Fatal(err)
	}
	return csrf
}
func perform(a *App, method, path string, form url.Values, c *http.Cookie) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form == nil {
		body = strings.NewReader("")
	} else {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, path, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	return w
}
func userForm(a *App, c *http.Cookie, values url.Values) url.Values {
	if values == nil {
		values = url.Values{}
	}
	var csrf string
	_ = a.db.QueryRow("SELECT csrf FROM sessions WHERE token_hash=?", shaToken(c.Value)).Scan(&csrf)
	values.Set("csrf", csrf)
	return values
}
func giftPage(t *testing.T, a *App, id string, c *http.Cookie) string {
	t.Helper()
	w := perform(a, "GET", "/gift/"+id, nil, c)
	if w.Code != 200 {
		t.Fatalf("gift page status=%d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("gift page must be private no-store")
	}
	return w.Body.String()
}
func TestRulesMatrix(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name                                        string
		withDate, past, pass, after, before, manual bool
		allow, needPass                             bool
	}{
		{"manual locked", false, false, false, false, false, false, false, false},
		{"manual unlocked", false, false, false, false, false, true, true, false},
		{"password without date", false, false, true, false, false, false, true, true},
		{"date alone future", true, false, false, false, false, false, false, false},
		{"date alone passed", true, true, false, false, false, false, true, false},
		{"date pass locked future", true, false, true, true, false, false, false, false},
		{"date pass before", true, false, true, true, true, false, true, true},
		{"date pass after required", true, true, true, true, false, false, true, true},
		{"date pass after not required", true, true, true, false, true, false, true, false},
		{"manual date with required pass", true, false, true, true, false, true, true, true},
		{"manual date optional pass", true, false, true, false, false, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := Gift{HasOpensAt: tc.withDate, HasPassword: tc.pass, RequirePasswordAfter: tc.after, AllowPasswordBefore: tc.before, ForcedOpen: tc.manual}
			if tc.withDate {
				g.OpensAt = now.Add(time.Hour)
				if tc.past {
					g.OpensAt = now.Add(-time.Hour)
				}
			}
			allowed, needed := accessRules(g, now)
			if allowed != tc.allow || needed != tc.needPass {
				t.Fatalf("got allowed=%t pass=%t; want allowed=%t pass=%t", allowed, needed, tc.allow, tc.needPass)
			}
		})
	}
}
func TestOwnerIsolationAndPreview(t *testing.T) {
	a := testApp(t)
	insertUser(t, a, "user-2", "second")
	mustExec(t, a, `INSERT INTO gifts(id,owner_id,recipient,sender,message,opens_at,private_note) VALUES('secret','user-2','Mottaker 987','Avsender 654','Hilsen 321','','PRIVAT 999')`)
	admin := sessionFor(t, a, "bootstrap-admin")
	dash := perform(a, "GET", "/admin", nil, admin)
	if dash.Code != 200 || strings.Contains(dash.Body.String(), "Mottaker 987") || strings.Contains(dash.Body.String(), "PRIVAT 999") {
		t.Fatal("admin could list other user's gift")
	}
	for _, endpoint := range []string{"/admin/gifts/secret/edit", "/admin/gifts/secret/preview", "/admin/gifts/secret/preview?mode=locked"} {
		res := perform(a, "GET", endpoint, nil, admin)
		if res.Code != 404 {
			t.Fatalf("admin accessed %s: %d", endpoint, res.Code)
		}
	}
	for _, endpoint := range []string{"/admin/gifts/secret/delete", "/admin/gifts/secret/open", "/admin/gifts/secret/lock", "/admin/gifts/secret/edit"} {
		res := perform(a, "POST", endpoint, userForm(a, admin, url.Values{"recipient": {"TEST"}, "sender": {"TEST"}}), admin)
		if res.Code != 404 {
			t.Fatalf("admin modified %s: %d", endpoint, res.Code)
		}
	}
	owner := sessionFor(t, a, "user-2")
	res := perform(a, "GET", "/admin/gifts/secret/preview", nil, owner)
	if res.Code != 200 || !strings.Contains(res.Body.String(), "Mottaker 987") || strings.Contains(res.Body.String(), "PRIVAT 999") {
		t.Fatal("preview should show opened gift but not private note")
	}
	locked := perform(a, "GET", "/admin/gifts/secret/preview?mode=locked", nil, owner)
	if strings.Contains(locked.Body.String(), "Mottaker 987") || strings.Contains(locked.Body.String(), "Avsender 654") || strings.Contains(locked.Body.String(), "PRIVAT 999") {
		t.Fatal("locked preview leaked private fields")
	}
	if strings.Contains(giftPage(t, a, "secret", nil), "Mottaker 987") {
		t.Fatal("recipient visible to public before opening")
	}
}
func TestCreateEditWithDateFlags(t *testing.T) {
	a := testApp(t)
	c := sessionFor(t, a, "bootstrap-admin")
	res := perform(a, "POST", "/admin/gifts", userForm(a, c, url.Values{
		"recipient": {"Til"}, "sender": {"Fra"}, "opens_at": {"2026-12-24T17:00"}, "password": {"testpass"}, "private_note": {"Hidden note"}, "require_password_after": {"on"}, "allow_password_before": {"on"},
	}), c)
	if res.Code != 303 {
		t.Fatalf("create failed: %d %s", res.Code, res.Body.String())
	}
	var id string
	if err := a.db.QueryRow("SELECT id FROM gifts LIMIT 1").Scan(&id); err != nil {
		t.Fatal(err)
	}
	g, err := a.getGift(id)
	if err != nil {
		t.Fatal(err)
	}
	if !g.HasOpensAt || !g.HasPassword || !g.RequirePasswordAfter || !g.AllowPasswordBefore || g.PrivateNote != "Hidden note" {
		t.Fatalf("flags not stored: %+v", g)
	}
	if strings.Contains(giftPage(t, a, id, nil), "Til") || strings.Contains(giftPage(t, a, id, nil), "Hidden note") {
		t.Fatal("gift leaks private fields")
	}
	res = perform(a, "POST", "/admin/gifts/"+id+"/edit", userForm(a, c, url.Values{
		"recipient": {"Til"}, "sender": {"Fra"}, "opens_at": {"2026-12-24T17:00"}, "require_password_after": {"on"},
	}), c)
	if res.Code != 303 {
		t.Fatalf("edit failed: %d", res.Code)
	}
	g, _ = a.getGift(id)
	if !g.RequirePasswordAfter || g.AllowPasswordBefore || !checkGiftPassword("testpass", g.PasswordHash) {
		t.Fatal("edit did not preserve password / update flags")
	}
	res = perform(a, "POST", "/admin/gifts/"+id+"/edit", userForm(a, c, url.Values{
		"recipient": {"Til"}, "sender": {"Fra"}, "remove_password": {"on"},
	}), c)
	if res.Code != 303 {
		t.Fatal("remove password failed")
	}
	g, _ = a.getGift(id)
	if g.HasPassword || g.RequirePasswordAfter || g.AllowPasswordBefore {
		t.Fatal("removing password should clear flags")
	}
}
func TestDeleteWarnsAndChecksCount(t *testing.T) {
	a := testApp(t)
	insertUser(t, a, "other", "other-person")
	mustExec(t, a, `INSERT INTO gifts(id,owner_id,recipient,sender,message,opens_at) VALUES('old-gift','other','secret-other','x','','')`)
	admin := sessionFor(t, a, "bootstrap-admin")
	page := perform(a, "GET", "/admin/users/other/delete", nil, admin)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "1 eksisterende etiketter") || strings.Contains(page.Body.String(), "secret-other") {
		t.Fatalf("delete warning incorrect: %d", page.Code)
	}
	bad := perform(a, "POST", "/admin/users/other/delete", userForm(a, admin, url.Values{"expected_count": {"0"}, "confirm_username": {"other-person"}, "confirm_delete": {"on"}}), admin)
	if bad.Code != 409 {
		t.Fatalf("stale label count should reject deletion: %d", bad.Code)
	}
	good := perform(a, "POST", "/admin/users/other/delete", userForm(a, admin, url.Values{"expected_count": {"1"}, "confirm_username": {"other-person"}, "confirm_delete": {"on"}}), admin)
	if good.Code != 303 {
		t.Fatalf("deletion failed: %d %s", good.Code, good.Body.String())
	}
	var count int
	_ = a.db.QueryRow("SELECT COUNT(*) FROM users WHERE id='other'").Scan(&count)
	if count != 0 {
		t.Fatal("user still exists")
	}
	_ = a.db.QueryRow("SELECT COUNT(*) FROM gifts WHERE owner_id='other'").Scan(&count)
	if count != 0 {
		t.Fatal("orphaned labels")
	}
}
func TestLegacyDatabaseMigration(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE gifts(id TEXT PRIMARY KEY,recipient TEXT NOT NULL,sender TEXT NOT NULL,message TEXT NOT NULL,opens_at TEXT NOT NULL,forced_open INTEGER NOT NULL DEFAULT 0,peeks INTEGER NOT NULL DEFAULT 0,private_note TEXT NOT NULL DEFAULT '',password_hash TEXT NOT NULL DEFAULT '');INSERT INTO gifts(id,recipient,sender,message,opens_at,private_note,password_hash) VALUES('legacy','Historic','From','Msg','2026-12-24T12:00:00Z','Private','x');`)
	if err != nil {
		t.Fatal(err)
	}
	if err := initDB(db, "safe-admin-password-123"); err != nil {
		t.Fatal(err)
	}
	a := &App{db: db, baseURL: "http://localhost"}
	g, err := a.getGift("legacy")
	if err != nil {
		t.Fatal(err)
	}
	if g.OwnerID != "bootstrap-admin" || !g.RequirePasswordAfter || g.AllowPasswordBefore || g.Recipient != "Historic" || g.PrivateNote != "Private" {
		t.Fatalf("migration lost data or changed old opening rules: %+v", g)
	}
	if err = initDB(db, "safe-admin-password-123"); err != nil {
		t.Fatal("migration not idempotent", err)
	}
}
func TestAdminCannotChangeAnotherUsersPassword(t *testing.T) {
	a := testApp(t)
	insertUser(t, a, "other", "other")
	admin := sessionFor(t, a, "bootstrap-admin")
	for _, path := range []string{"/admin/users/other/password", "/admin/users/other/gifts"} {
		res := perform(a, "POST", path, userForm(a, admin, url.Values{"password": {"new-password123"}}), admin)
		if res.Code != 404 {
			t.Fatalf("unexpected privileged route %s", path)
		}
	}
}

func TestTemplatesRender(t *testing.T) {
	p := Page{User: User{ID: "u", Username: "user", Provider: "local", Enabled: true}, Gift: Gift{ID: "g", Recipient: "Alice", Sender: "Bob", PrivateNote: "Private", OpensAtLabel: "24.12.2026"}, CSRF: "csrf", URL: "https://example.com", DeleteUsername: "alice", DeleteCount: 2}
	for _, name := range []string{"admin.html", "edit.html", "gift.html", "login.html", "users.html", "delete-user.html", "register.html"} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := templates.ExecuteTemplate(&out, name, p); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "<!doctype html>") {
				t.Fatal("template missing HTML document")
			}
		})
	}
}
func TestRegistrationRequiresAdminToggle(t *testing.T) {
	a := testApp(t)
	if res := perform(a, "GET", "/register", nil, nil); res.Code != 303 {
		t.Fatalf("registration should be off: %d", res.Code)
	}
	if res := perform(a, "POST", "/register", url.Values{"username": {"visitor"}, "password": {"long-enough-password"}, "password_confirm": {"long-enough-password"}}, nil); res.Code != 403 {
		t.Fatalf("POST registration should be off: %d", res.Code)
	}
	mustExec(t, a, "UPDATE settings SET value='1' WHERE key='local_signup_enabled'")
	if res := perform(a, "GET", "/register", nil, nil); res.Code != 200 {
		t.Fatalf("registration not enabled: %d", res.Code)
	}
	res := perform(a, "POST", "/register", url.Values{"username": {"visitor"}, "password": {"long-enough-password"}, "password_confirm": {"long-enough-password"}}, nil)
	if res.Code != 303 {
		t.Fatalf("registration failed: %d %s", res.Code, res.Body.String())
	}
	var id string
	var isAdmin int
	if err := a.db.QueryRow("SELECT id,is_admin FROM users WHERE username='visitor'").Scan(&id, &isAdmin); err != nil {
		t.Fatal(err)
	}
	if isAdmin != 0 {
		t.Fatal("self signup must not grant admin")
	}
	var sessionCookie *http.Cookie
	for _, cookie := range res.Result().Cookies() {
		if cookie.Name == "gift_session" {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("registration failed to log in new user")
	}
	if page := perform(a, "GET", "/admin", nil, sessionCookie); page.Code != 200 {
		t.Fatalf("new user's dashboard inaccessible: %d", page.Code)
	}
	if page := perform(a, "GET", "/admin/users", nil, sessionCookie); page.Code != 403 {
		t.Fatal("self registered user accessed admin console")
	}
}
func TestDisableUserRevokesDashboard(t *testing.T) {
	a := testApp(t)
	insertUser(t, a, "member", "member")
	c := sessionFor(t, a, "member")
	if status := perform(a, "GET", "/admin", nil, c).Code; status != 200 {
		t.Fatalf("expected valid session, got %d", status)
	}
	mustExec(t, a, "UPDATE users SET enabled=0 WHERE id='member'")
	if status := perform(a, "GET", "/admin", nil, c).Code; status != 303 {
		t.Fatalf("disabled account can still access dashboard: %d", status)
	}
}

// Browser Origin must match the actual request address, not always BASE_URL.
func TestValidOrigin(t *testing.T) {
	a := &App{baseURL: "https://gifts.example.org"}
	for _, tc := range []struct {
		name, requestURL, origin string
		want                     bool
	}{
		{"localhost access", "http://localhost:8080/login", "http://localhost:8080", true},
		{"127 local access", "http://127.0.0.1:8080/login", "http://127.0.0.1:8080", true},
		{"wrong host", "http://localhost:8080/login", "http://evil.example", false},
		{"different port", "http://localhost:8080/login", "http://localhost:9090", false},
		{"wrong scheme", "http://localhost:8080/login", "https://localhost:8080", false},
		{"null origin", "http://localhost:8080/login", "null", false},
		{"malformed", "http://localhost:8080/login", "https://", false},
		{"path in origin", "http://localhost:8080/login", "http://localhost:8080/attacker", false},
		{"no origin", "http://localhost:8080/login", "", true},
		{"canonical https behind proxy", "http://gifts.example.org/login", "https://gifts.example.org", true},
		{"canonical http rejected behind proxy", "http://gifts.example.org/login", "http://gifts.example.org", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, tc.requestURL, nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if got := a.validOrigin(r); got != tc.want {
				t.Fatalf("validOrigin=%v, want %v", got, tc.want)
			}
		})
	}
	t.Run("direct https", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "https://example.net/login", nil)
		r.Header.Set("Origin", "https://example.net")
		if !a.validOrigin(r) {
			t.Fatal("HTTPS direct request should be allowed")
		}
	})
}

func TestLoginOriginUsesRequestHost(t *testing.T) {
	a := testApp(t)
	a.baseURL = "https://gifts.example.org"
	for _, host := range []string{"localhost", "127.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			form := url.Values{"username": {"admin"}, "password": {"safe-admin-password-123"}}
			addr := "http://" + host + ":8080"
			r := httptest.NewRequest(http.MethodPost, addr+"/login", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", addr)
			w := httptest.NewRecorder()
			a.routes().ServeHTTP(w, r)
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin" {
				t.Fatalf("login failed with %v: status=%d, body=%s", addr, w.Code, w.Body.String())
			}
		})
	}
}

// HTML form POSTs must not be forced to send Origin: null by our own policy.
// Unlike no-referrer, same-origin retains a usable Origin for same-origin forms,
// without sending a Referer to external websites.
func TestSecurityHeadersKeepSameOriginFormsWorking(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://localhost:8080/login", nil)
	w := httptest.NewRecorder()
	securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, r)
	if got := w.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("Referrer-Policy=%q, want same-origin", got)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options=%q", got)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'self'") {
		t.Fatal("CSP form-action self must be preserved")
	}
}

func TestDefaultChristmasDate(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Oslo")
	if err != nil {
		t.Fatal(err)
	}
	got := defaultGiftDate(time.Date(2026, 11, 13, 18, 0, 0, 0, loc), loc)
	if got != "2026-12-24T17:00" {
		t.Fatalf("unexpected Christmas default %q", got)
	}
}

func TestLocalSignupEnvOverridesToggle(t *testing.T) {
	a := testApp(t)
	mustExec(t, a, "UPDATE settings SET value='1' WHERE key='local_signup_enabled'")
	t.Setenv("LOCAL_SIGNUP_ENABLED", "false")
	if a.localSignupEnabled() {
		t.Fatal("env false should disable registration")
	}
	if got := perform(a, "GET", "/register", nil, nil); got.Code != 303 {
		t.Fatalf("registration enabled despite env false: %d", got.Code)
	}
	t.Setenv("LOCAL_SIGNUP_ENABLED", "true")
	if !a.localSignupEnabled() {
		t.Fatal("env true should allow registration")
	}
	t.Setenv("LOCAL_SIGNUP_ENABLED", "not-a-bool")
	if a.localSignupEnabled() {
		t.Fatal("invalid env must fail closed")
	}
	t.Setenv("LOCAL_SIGNUP_ENABLED", "")
	if !a.localSignupEnabled() {
		t.Fatal("empty env should fall back to admin toggle")
	}
}

func TestGiftPasswordEncryptionAndOwnerIsolation(t *testing.T) {
	a := testApp(t)
	admin := sessionFor(t, a, "bootstrap-admin")
	res := perform(a, "POST", "/admin/gifts", userForm(a, admin, url.Values{
		"recipient": {"Maren"}, "sender": {"Chris"}, "password": {"julehemmelig"},
	}), admin)
	if res.Code != 303 {
		t.Fatalf("create: %d %s", res.Code, res.Body.String())
	}
	var id string
	if err := a.db.QueryRow("SELECT id FROM gifts LIMIT 1").Scan(&id); err != nil {
		t.Fatal(err)
	}
	g, err := a.getGift(id)
	if err != nil {
		t.Fatal(err)
	}
	if g.PasswordCiphertext == "" || strings.Contains(g.PasswordCiphertext, "julehemmelig") {
		t.Fatal("password not encrypted at rest")
	}
	if !checkGiftPassword("julehemmelig", g.PasswordHash) {
		t.Fatal("hash lost")
	}
	plain, err := decryptGiftPassword(g.PasswordCiphertext)
	if err != nil || plain != "julehemmelig" {
		t.Fatalf("cannot decrypt: %q %v", plain, err)
	}
	if strings.Contains(perform(a, "GET", "/admin", nil, admin).Body.String(), "julehemmelig") {
		t.Fatal("password leaked into dashboard HTML")
	}
	if strings.Contains(giftPage(t, a, id, nil), "julehemmelig") {
		t.Fatal("password leaked to public page")
	}
	owner := perform(a, "GET", "/admin/gifts/"+id+"/password", nil, admin)
	if owner.Code != 200 || !strings.Contains(owner.Body.String(), "julehemmelig") {
		t.Fatalf("owner reveal: %d %s", owner.Code, owner.Body.String())
	}
	if owner.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("password response cacheable")
	}
	insertUser(t, a, "not-owner", "different")
	other := sessionFor(t, a, "not-owner")
	if got := perform(a, "GET", "/admin/gifts/"+id+"/password", nil, other); got.Code != 404 {
		t.Fatalf("other user can access password: %d", got.Code)
	}
	if got := perform(a, "GET", "/admin/gifts/"+id+"/password", nil, nil); got.Code != 303 {
		t.Fatalf("anonymous access: %d", got.Code)
	}
	// A pre-upgrade password hash cannot be reversed.
	mustExec(t, a, "UPDATE gifts SET password_ciphertext='' WHERE id=?", id)
	if got := perform(a, "GET", "/admin/gifts/"+id+"/password", nil, admin); got.Code != 409 {
		t.Fatalf("old hash should require reset, got %d", got.Code)
	}
}

func TestAccountDisplayNameAndCreateDefault(t *testing.T) {
	a := testApp(t)
	admin := sessionFor(t, a, "bootstrap-admin")
	n := perform(a, "POST", "/account/name", userForm(a, admin, url.Values{"display_name": {"Julenissen"}}), admin)
	if n.Code != 303 {
		t.Fatalf("name update: %d", n.Code)
	}
	page := perform(a, "GET", "/admin", nil, admin)
	if page.Code != 200 || !strings.Contains(page.Body.String(), `value="Julenissen"`) {
		t.Fatal("default sender should match display name")
	}
	if !strings.Contains(page.Body.String(), `data-clear-date`) || !strings.Contains(page.Body.String(), `data-label-search`) {
		t.Fatal("dashboard should include date removal and search")
	}
	if !strings.Contains(page.Body.String(), `2026-12-24`) && time.Now().In(a.location()).Year() == 2026 {
		t.Fatal("default date missing")
	}
}

func TestMigrationFromV42AddsEncryptedPasswordAndDisplayName(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE UNIQUE, password_hash TEXT NOT NULL DEFAULT '', is_admin INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, provider TEXT NOT NULL DEFAULT 'local', provider_subject TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT '', UNIQUE(provider,provider_subject));
	CREATE TABLE gifts (id TEXT PRIMARY KEY,recipient TEXT NOT NULL,sender TEXT NOT NULL,message TEXT NOT NULL,opens_at TEXT NOT NULL,forced_open INTEGER NOT NULL DEFAULT 0,peeks INTEGER NOT NULL DEFAULT 0,private_note TEXT NOT NULL DEFAULT '',password_hash TEXT NOT NULL DEFAULT '',owner_id TEXT NOT NULL DEFAULT '',require_password_after INTEGER NOT NULL DEFAULT 1,allow_password_before INTEGER NOT NULL DEFAULT 0);
	INSERT INTO users(id,username,is_admin) VALUES('old-admin','santa',1);
	INSERT INTO gifts(id,owner_id,recipient,sender,message,opens_at) VALUES('old-gift','old-admin','A','B','','');`)
	if err != nil {
		t.Fatal(err)
	}
	if err := initDB(db, "safe-admin-password-123"); err != nil {
		t.Fatal(err)
	}
	var display, encrypted string
	if err := db.QueryRow("SELECT display_name FROM users WHERE id='old-admin'").Scan(&display); err != nil || display != "santa" {
		t.Fatalf("name migration failed %q: %v", display, err)
	}
	if err := db.QueryRow("SELECT password_ciphertext FROM gifts WHERE id='old-gift'").Scan(&encrypted); err != nil || encrypted != "" {
		t.Fatalf("gift migration failed %q: %v", encrypted, err)
	}
	if err := initDB(db, "safe-admin-password-123"); err != nil {
		t.Fatal("migration not idempotent", err)
	}
}

func TestPrintingOnlyOwnGifts(t *testing.T) {
	a := testApp(t)
	insertUser(t, a, "user-2", "second")
	mustExec(t, a, `INSERT INTO gifts(id,owner_id,recipient,sender,message,opens_at,private_note) VALUES('gift-admin','bootstrap-admin','Eierens mottaker','Admin','','','EIERNOTAT')`)
	mustExec(t, a, `INSERT INTO gifts(id,owner_id,recipient,sender,message,opens_at,private_note) VALUES('gift-other','user-2','Annen mottaker','En annen avsender','HEMMELIG MELDING','','SKJULT NOTAT')`)
	admin := sessionFor(t, a, "bootstrap-admin")
	other := sessionFor(t, a, "user-2")
	path := "/admin/gifts/print"

	// Admin is not an omnipotent printer. Even a forged form cannot list a gift
	// owned by another account.
	for _, session := range []*http.Cookie{admin, other} {
		forbiddenID := "gift-other"
		if session == other {
			forbiddenID = "gift-admin"
		}
		w := perform(a, "POST", path, userForm(a, session, url.Values{"gift_ids": {forbiddenID}}), session)
		if w.Code != http.StatusNotFound {
			t.Fatalf("foreign gift print returned %d; expected 404", w.Code)
		}
		if strings.Contains(w.Body.String(), "mottaker") || strings.Contains(w.Body.String(), "NOTAT") {
			t.Fatalf("foreign print leaked gift contents: %s", w.Body.String())
		}
	}

	// A mixed forged selection must fail entirely, not print a partial list.
	mixed := perform(a, "POST", path, userForm(a, admin, url.Values{"gift_ids": {"gift-admin", "gift-other"}}), admin)
	if mixed.Code != 404 || strings.Contains(mixed.Body.String(), "Eierens mottaker") {
		t.Fatalf("mixed ownership leaked a gift: %d %s", mixed.Code, mixed.Body.String())
	}

	own := perform(a, "POST", path, userForm(a, other, url.Values{"gift_ids": {"gift-other", "gift-other"}}), other)
	body := own.Body.String()
	if own.Code != 200 || !strings.Contains(body, "Annen mottaker") || !strings.Contains(body, "En annen avsender") {
		t.Fatalf("own print failed: %d %s", own.Code, body)
	}
	if strings.Count(body, `class="print-label"`) != 1 {
		t.Fatal("duplicate IDs must not produce duplicate labels")
	}
	if strings.Contains(body, "Eierens mottaker") || strings.Contains(body, "SKJULT NOTAT") || strings.Contains(body, "HEMMELIG MELDING") {
		t.Fatal("print includes private note, secret message, or another user's gift")
	}
	if strings.Contains(body, `class="label-names"`) {
		t.Fatal("names should not appear on the default QR label")
	}
	if own.Header().Get("Cache-Control") != "no-store, private" {
		t.Fatal("private print response should be non-cacheable")
	}

	withDetails := perform(a, "POST", path, userForm(a, other, url.Values{
		"gift_ids": {"gift-other"}, "show_names": {"on"}, "show_notes": {"on"},
	}), other)
	if withDetails.Code != 200 || !strings.Contains(withDetails.Body.String(), `class="label-names"`) || !strings.Contains(withDetails.Body.String(), "SKJULT NOTAT") {
		t.Fatalf("explicitly chosen print options failed: %d", withDetails.Code)
	}
}

func TestPrintSecurityAndUI(t *testing.T) {
	a := testApp(t)
	mustExec(t, a, `INSERT INTO gifts(id,owner_id,recipient,sender,message,opens_at) VALUES('own','bootstrap-admin','Alice','Bob','','')`)
	admin := sessionFor(t, a, "bootstrap-admin")
	page := perform(a, "GET", "/admin", nil, admin)
	for _, required := range []string{`id="print-selected-form"`, `name="gift_ids"`, `data-select-visible`, `data-print-submit`, `name="show_names"`, `name="show_notes"`} {
		if !strings.Contains(page.Body.String(), required) {
			t.Fatalf("dashboard missing print control %s", required)
		}
	}
	if got := perform(a, "GET", "/admin/gifts/print", nil, admin); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("printing should require POST: %d", got.Code)
	}
	if got := perform(a, "POST", "/admin/gifts/print", url.Values{"gift_ids": {"own"}}, nil); got.Code != http.StatusSeeOther {
		t.Fatalf("anonymous printing allowed: %d", got.Code)
	}
	if got := perform(a, "POST", "/admin/gifts/print", url.Values{"gift_ids": {"own"}}, admin); got.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF accepted: %d", got.Code)
	}
	if got := perform(a, "POST", "/admin/gifts/print", userForm(a, admin, url.Values{}), admin); got.Code != http.StatusBadRequest {
		t.Fatalf("empty selection accepted: %d", got.Code)
	}
	many := make([]string, maxPrintGifts+1)
	for i := range many {
		many[i] = "own"
	}
	if got := perform(a, "POST", "/admin/gifts/print", userForm(a, admin, url.Values{"gift_ids": many}), admin); got.Code != http.StatusBadRequest {
		t.Fatalf("oversized selection accepted: %d", got.Code)
	}
}

func TestQRCodeImageRestrictedToOwner(t *testing.T) {
	a := testApp(t)
	insertUser(t, a, "other", "other")
	mustExec(t, a, `INSERT INTO gifts(id,owner_id,recipient,sender,message,opens_at) VALUES('gift-x','other','Annas gave','Ola','','')`)
	admin := sessionFor(t, a, "bootstrap-admin")
	other := sessionFor(t, a, "other")
	for _, tc := range []struct {
		name   string
		cookie *http.Cookie
		status int
	}{
		{"owner", other, http.StatusOK},
		{"admin-not-owner", admin, http.StatusNotFound},
		{"anonymous", nil, http.StatusSeeOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := perform(a, "GET", "/admin/gifts/gift-x/qr.png", nil, tc.cookie)
			if w.Code != tc.status {
				t.Fatalf("QR request returned %d, want %d", w.Code, tc.status)
			}
			if tc.status == 200 && (w.Header().Get("Content-Type") != "image/png" || w.Header().Get("Cache-Control") != "no-store, private") {
				t.Fatalf("QR response had wrong headers: %v", w.Header())
			}
		})
	}
	if w := perform(a, "GET", "/gift/gift-x/qr.png", nil, nil); w.Code == 200 {
		t.Fatal("public QR endpoint must not expose printable QR images")
	}
}
