package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
	_ "modernc.org/sqlite"
)

//go:embed templates/*.html
var templatesFS embed.FS
var templates = template.Must(template.ParseFS(templatesFS, "templates/*.html"))

const passwordRounds = 150000

type attempt struct {
	Count int
	Until time.Time
}
type App struct {
	db         *sql.DB
	baseURL    string
	mu         sync.Mutex
	attempts   map[string]attempt
	httpClient *http.Client
}
type User struct {
	ID, Username, DisplayName, Provider string
	IsAdmin, Enabled                    bool
	LabelCount                          int
}
type Gift struct {
	ID, OwnerID, Recipient, Sender, Message, PrivateNote, PasswordHash, PasswordCiphertext string
	OpensAt                                                                                time.Time
	OpensAtInput, OpensAtLabel                                                             string
	HasOpensAt, HasPassword, ForcedOpen, RequirePasswordAfter, AllowPasswordBefore         bool
	Peeks                                                                                  int
}
type Page struct {
	User                                                             User
	Gift                                                             Gift
	Gifts                                                            []Gift
	Users                                                            []User
	URL, Error, Success, CSRF, Note, DeleteUsername, DefaultGiftDate string
	Unlocked, ShowPassword, Preview, PreviewLocked                   bool
	GitHubEnabled, OIDCEnabled, LDAPEnabled                          bool
	LocalSignupEnabled, LocalSignupEnvManaged                        bool
	GitHubConfigured, OIDCConfigured, LDAPConfigured                 bool
	DeleteCount                                                      int
}

func env(k, fallback string) string {
	if s := os.Getenv(k); s != "" {
		return s
	}
	return fallback
}
func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func shaToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func main() {
	adminPassword := os.Getenv("ADMIN_PASSWORD")
	if len(adminPassword) < 12 {
		log.Fatal("ADMIN_PASSWORD må være minst 12 tegn (brukes til oppstart av admin-konto)")
	}
	db, err := sql.Open("sqlite", env("DATABASE_PATH", "./gifts.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := initDB(db, adminPassword); err != nil {
		log.Fatal(err)
	}
	a := &App{db: db, baseURL: strings.TrimRight(env("BASE_URL", "http://localhost:8080"), "/"), attempts: make(map[string]attempt), httpClient: &http.Client{Timeout: 10 * time.Second}}
	mux := a.routes()
	srv := &http.Server{Addr: env("LISTEN_ADDR", ":8080"), Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("listening on %s", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}

func initDB(db *sql.DB, adminPassword string) error {
	if _, err := db.Exec(`PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;
  CREATE TABLE IF NOT EXISTS users (
   id TEXT PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE UNIQUE,
   password_hash TEXT NOT NULL DEFAULT '', is_admin INTEGER NOT NULL DEFAULT 0,
   enabled INTEGER NOT NULL DEFAULT 1,
   provider TEXT NOT NULL DEFAULT 'local', provider_subject TEXT NOT NULL DEFAULT '',
   created_at TEXT NOT NULL DEFAULT '', display_name TEXT NOT NULL DEFAULT '', UNIQUE(provider,provider_subject)
  );
  CREATE TABLE IF NOT EXISTS sessions (
   token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
   csrf TEXT NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS gifts (
   id TEXT PRIMARY KEY, recipient TEXT NOT NULL, sender TEXT NOT NULL,
   message TEXT NOT NULL, opens_at TEXT NOT NULL,
   forced_open INTEGER NOT NULL DEFAULT 0, peeks INTEGER NOT NULL DEFAULT 0,
   private_note TEXT NOT NULL DEFAULT '', password_hash TEXT NOT NULL DEFAULT '', password_ciphertext TEXT NOT NULL DEFAULT '',
   owner_id TEXT NOT NULL DEFAULT '',
   require_password_after INTEGER NOT NULL DEFAULT 1,
   allow_password_before INTEGER NOT NULL DEFAULT 0
  );`); err != nil {
		return err
	}
	// Keep old gifts intact. Existing labels belong to the original administrator.
	// Display names are optional for older accounts; migrate from username.
	userCols, err := tableColumns(db, "users")
	if err != nil {
		return err
	}
	if !userCols["display_name"] {
		if _, err := db.Exec("ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	if _, err := db.Exec("UPDATE users SET display_name=username WHERE display_name=''"); err != nil {
		return err
	}
	cols, err := tableColumns(db, "gifts")
	if err != nil {
		return err
	}
	for _, f := range []struct{ name, ddl string }{
		{"private_note", "TEXT NOT NULL DEFAULT ''"}, {"password_hash", "TEXT NOT NULL DEFAULT ''"}, {"password_ciphertext", "TEXT NOT NULL DEFAULT ''"},
		{"owner_id", "TEXT NOT NULL DEFAULT ''"}, {"require_password_after", "INTEGER NOT NULL DEFAULT 1"},
		{"allow_password_before", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if !cols[f.name] {
			if _, err := db.Exec("ALTER TABLE gifts ADD COLUMN " + f.name + " " + f.ddl); err != nil {
				return err
			}
		}
	}
	var admins int
	if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE is_admin=1").Scan(&admins); err != nil {
		return err
	}
	if admins == 0 {
		hash, err := hashGiftPassword(adminPassword)
		if err != nil {
			return err
		}
		if _, err = db.Exec(`INSERT INTO users(id,username,display_name,password_hash,is_admin,created_at) VALUES(?,?,?,?,1,?)`, "bootstrap-admin", "admin", "admin", hash, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	// Assignment only if ownership hasn't yet been set.
	var adminID string
	if err := db.QueryRow("SELECT id FROM users WHERE is_admin=1 ORDER BY rowid LIMIT 1").Scan(&adminID); err != nil {
		return err
	}
	if _, err := db.Exec("UPDATE gifts SET owner_id=? WHERE owner_id=''", adminID); err != nil {
		return err
	}
	for _, key := range []string{"github_enabled", "oidc_enabled", "ldap_enabled", "local_signup_enabled"} {
		if _, err := db.Exec("INSERT OR IGNORE INTO settings(key,value) VALUES(?, '0')", key); err != nil {
			return err
		}
	}
	return nil
}
func tableColumns(db *sql.DB, name string) (map[string]bool, error) {
	rows, err := db.Query("PRAGMA table_info(" + name + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var field, kind string
		var def sql.NullString
		if err := rows.Scan(&cid, &field, &kind, &notnull, &def, &pk); err != nil {
			return nil, err
		}
		cols[field] = true
	}
	return cols, rows.Err()
}
func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("GET /", a.home)
	mux.HandleFunc("GET /login", a.loginPage)
	mux.HandleFunc("GET /register", a.registerPage)
	mux.HandleFunc("POST /register", a.register)
	mux.HandleFunc("POST /login", a.login)
	mux.HandleFunc("POST /logout", a.logout)
	mux.HandleFunc("GET /admin/login", a.loginPage) // old bookmark
	mux.HandleFunc("POST /admin/login", a.login)
	mux.HandleFunc("POST /admin/logout", a.logout)
	mux.HandleFunc("GET /admin", a.dashboard)
	mux.HandleFunc("GET /dashboard", a.dashboard)
	mux.HandleFunc("POST /admin/gifts", a.createGift)
	mux.HandleFunc("GET /admin/gifts/{id}/edit", a.editPage)
	mux.HandleFunc("POST /admin/gifts/{id}/edit", a.editGift)
	mux.HandleFunc("GET /admin/gifts/{id}/preview", a.previewGift)
	mux.HandleFunc("GET /admin/gifts/{id}/password", a.revealGiftPassword)
	mux.HandleFunc("POST /admin/gifts/{id}/open", a.openGift)
	mux.HandleFunc("POST /admin/gifts/{id}/lock", a.lockGift)
	mux.HandleFunc("POST /admin/gifts/{id}/delete", a.deleteGift)
	mux.HandleFunc("GET /admin/users", a.usersPage)
	mux.HandleFunc("POST /admin/users", a.createUser)
	mux.HandleFunc("POST /account/password", a.changeOwnPassword)
	mux.HandleFunc("POST /account/name", a.changeDisplayName)
	mux.HandleFunc("POST /admin/users/{id}/enabled", a.toggleUser)
	mux.HandleFunc("GET /admin/users/{id}/delete", a.userDeletePage)
	mux.HandleFunc("POST /admin/users/{id}/delete", a.deleteUser)
	mux.HandleFunc("POST /admin/settings", a.saveSettings)
	mux.HandleFunc("GET /gift/{id}", a.showGift)
	mux.HandleFunc("POST /gift/{id}/unlock", a.unlockGift)
	mux.HandleFunc("GET /gift/{id}/qr.png", a.qr)
	mux.HandleFunc("GET /auth/github", a.githubStart)
	mux.HandleFunc("GET /auth/github/callback", a.githubCallback)
	mux.HandleFunc("GET /auth/oidc", a.oidcStart)
	mux.HandleFunc("GET /auth/oidc/callback", a.oidcCallback)
	return mux
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
func render(w http.ResponseWriter, name string, p Page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := templates.ExecuteTemplate(w, name, p); err != nil {
		log.Printf("template %s: %v", name, err)
	}
}
func (a *App) home(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
func (a *App) location() *time.Location {
	loc, err := time.LoadLocation(env("TIMEZONE", "Europe/Oslo"))
	if err != nil {
		return time.UTC
	}
	return loc
}

const giftColumns = "id,owner_id,recipient,sender,message,opens_at,forced_open,peeks,private_note,password_hash,require_password_after,allow_password_before,password_ciphertext"

func (a *App) scanGift(scan func(...any) error) (Gift, error) {
	var g Gift
	var at string
	var forced, after, before int
	if err := scan(&g.ID, &g.OwnerID, &g.Recipient, &g.Sender, &g.Message, &at, &forced, &g.Peeks, &g.PrivateNote, &g.PasswordHash, &after, &before, &g.PasswordCiphertext); err != nil {
		return Gift{}, err
	}
	g.ForcedOpen = forced != 0
	g.RequirePasswordAfter = after != 0
	g.AllowPasswordBefore = before != 0
	g.HasPassword = g.PasswordHash != ""
	if at != "" {
		date, err := time.Parse(time.RFC3339, at)
		if err != nil {
			return Gift{}, err
		}
		g.OpensAt = date
		g.HasOpensAt = true
		g.OpensAtInput = date.In(a.location()).Format("2006-01-02T15:04")
		g.OpensAtLabel = date.In(a.location()).Format("02.01.2006 kl. 15:04")
	}
	return g, nil
}
func (a *App) getGift(id string) (Gift, error) {
	return a.scanGift(a.db.QueryRow("SELECT "+giftColumns+" FROM gifts WHERE id=?", id).Scan)
}
func (a *App) getOwnedGift(id, owner string) (Gift, error) {
	return a.scanGift(a.db.QueryRow("SELECT "+giftColumns+" FROM gifts WHERE id=? AND owner_id=?", id, owner).Scan)
}

// accessRules determines whether time/manual controls allow access, and whether
// a password is required at the present moment. Manual override skips the clock
// but does not erase an explicitly required password.
func accessRules(g Gift, now time.Time) (eligible, requiresPassword bool) {
	if g.ForcedOpen {
		return true, g.HasPassword && (!g.HasOpensAt || g.RequirePasswordAfter)
	}
	if g.HasOpensAt {
		if now.Before(g.OpensAt) {
			if g.HasPassword && g.AllowPasswordBefore {
				return true, true
			}
			return false, false
		}
		return true, g.HasPassword && g.RequirePasswordAfter
	}
	if g.HasPassword {
		return true, true
	}
	return false, false
}
func (a *App) giftCookieName(g Gift) string { return "gift_access_" + g.ID }
func (a *App) signedGiftTicket(g Gift, expires int64) string {
	secret := env("TICKET_SECRET", "")
	// Persistent secret is required for stable tickets after restarts; if absent,
	// derive from the server admin bootstrap secret. These cookies carry no PII.
	if secret == "" {
		secret = env("ADMIN_PASSWORD", "")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%s\x00%s\x00%d", g.ID, g.PasswordHash, expires)
	return strconv.FormatInt(expires, 10) + "." + hex.EncodeToString(mac.Sum(nil))
}
func (a *App) hasGiftAccess(r *http.Request, g Gift) bool {
	c, err := r.Cookie(a.giftCookieName(g))
	if err != nil {
		return false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 {
		return false
	}
	expires, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || expires <= time.Now().Unix() {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(a.signedGiftTicket(g, expires))) == 1
}
func (a *App) showGift(w http.ResponseWriter, r *http.Request) {
	g, err := a.getGift(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	eligible, passwordNeeded := accessRules(g, time.Now())
	unlocked := eligible && (!passwordNeeded || a.hasGiftAccess(r, g))
	if !unlocked {
		_, _ = a.db.Exec("UPDATE gifts SET peeks=peeks+1 WHERE id=?", g.ID)
	}
	pub := Gift{ID: g.ID, HasOpensAt: g.HasOpensAt, OpensAtLabel: g.OpensAtLabel}
	if unlocked {
		pub = Gift{ID: g.ID, Recipient: g.Recipient, Sender: g.Sender, Message: g.Message}
	}
	errText := ""
	if r.URL.Query().Get("error") == "password" {
		errText = "Feil passord. Prøv igjen."
	}
	render(w, "gift.html", Page{Gift: pub, Unlocked: unlocked, ShowPassword: eligible && passwordNeeded && !unlocked, Error: errText})
}
func (a *App) rateLimitKey(r *http.Request, id string) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return id + "|" + host
}
func (a *App) canTryPassword(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.attempts[key]
	if !ok || time.Now().After(entry.Until) {
		delete(a.attempts, key)
		return true
	}
	return entry.Count < 5
}
func (a *App) recordAttempt(key string, valid bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if valid {
		delete(a.attempts, key)
		return
	}
	entry := a.attempts[key]
	if time.Now().After(entry.Until) {
		entry = attempt{Until: time.Now().Add(15 * time.Minute)}
	}
	entry.Count++
	a.attempts[key] = entry
}
func (a *App) unlockGift(w http.ResponseWriter, r *http.Request) {
	if !a.validOrigin(r) {
		http.Error(w, "Ugyldig opprinnelse", http.StatusForbidden)
		return
	}
	g, err := a.getGift(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	eligible, needsPassword := accessRules(g, time.Now())
	if !eligible || !needsPassword {
		http.Redirect(w, r, "/gift/"+url.PathEscape(g.ID), http.StatusSeeOther)
		return
	}
	key := a.rateLimitKey(r, g.ID)
	if !a.canTryPassword(key) {
		http.Error(w, "For mange passordforsøk. Prøv igjen senere.", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Ugyldig skjema", 400)
		return
	}
	valid := checkGiftPassword(r.PostForm.Get("password"), g.PasswordHash)
	a.recordAttempt(key, valid)
	if !valid {
		http.Redirect(w, r, "/gift/"+url.PathEscape(g.ID)+"?error=password", http.StatusSeeOther)
		return
	}
	expires := time.Now().Add(24 * time.Hour).Unix()
	http.SetCookie(w, &http.Cookie{Name: a.giftCookieName(g), Value: a.signedGiftTicket(g, expires), Path: "/gift/" + g.ID, MaxAge: 86400, Secure: a.secureCookies(), HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/gift/"+url.PathEscape(g.ID), http.StatusSeeOther)
}
func (a *App) qr(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.getGift(id); err != nil {
		http.NotFound(w, r)
		return
	}
	png, err := qrcode.Encode(a.baseURL+"/gift/"+url.PathEscape(id), qrcode.Medium, 512)
	if err != nil {
		http.Error(w, "QR-feil", 500)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public,max-age=3600")
	_, _ = w.Write(png)
}

// giftPasswordKey intentionally uses a separate key namespace from ticket signing.
// Set GIFT_PASSWORD_KEY permanently in .env before creating any new password.
// To keep upgrades working without a new setting, older env secrets are a fallback.
func giftPasswordKey() ([]byte, error) {
	secret := os.Getenv("GIFT_PASSWORD_KEY")
	if secret == "" {
		secret = os.Getenv("TICKET_SECRET")
	}
	if secret == "" {
		secret = os.Getenv("ADMIN_PASSWORD")
	}
	if len(secret) < 12 {
		return nil, errors.New("GIFT_PASSWORD_KEY, TICKET_SECRET eller ADMIN_PASSWORD må være konfigurert")
	}
	sum := sha256.Sum256([]byte("christmas-gift-tag/password-encryption/v1\x00" + secret))
	return sum[:], nil
}
func encryptGiftPassword(password string) (string, error) {
	if password == "" {
		return "", nil
	}
	key, err := giftPasswordKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	encrypted := aead.Seal(nil, nonce, []byte(password), nil)
	return "v1." + base64.RawURLEncoding.EncodeToString(append(nonce, encrypted...)), nil
}
func decryptGiftPassword(encrypted string) (string, error) {
	if !strings.HasPrefix(encrypted, "v1.") {
		return "", errors.New("unknown ciphertext format")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encrypted, "v1."))
	if err != nil {
		return "", err
	}
	key, err := giftPasswordKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < aead.NonceSize()+aead.Overhead() {
		return "", errors.New("invalid ciphertext")
	}
	plain, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (a *App) revealGiftPassword(w http.ResponseWriter, r *http.Request) {
	u, _, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	g, err := a.getOwnedGift(r.PathValue("id"), u.ID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !g.HasPassword {
		http.Error(w, "Denne etiketten har ikke gavepassord", http.StatusNotFound)
		return
	}
	if g.PasswordCiphertext == "" {
		http.Error(w, "Eldre passord er lagret som hash og kan ikke vises. Rediger etiketten og sett et nytt gavepassord.", http.StatusConflict)
		return
	}
	password, err := decryptGiftPassword(g.PasswordCiphertext)
	if err != nil {
		http.Error(w, "Passordet kunne ikke dekrypteres. Kontroller GIFT_PASSWORD_KEY.", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(struct {
		Password string `json:"password"`
	}{Password: password})
}
func defaultGiftDate(now time.Time, loc *time.Location) string {
	local := now.In(loc)
	return time.Date(local.Year(), time.December, 24, 17, 0, 0, 0, loc).Format("2006-01-02T15:04")
}

func parseGiftDate(raw string, loc *time.Location) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	t, err := time.ParseInLocation("2006-01-02T15:04", raw, loc)
	if err != nil {
		return "", err
	}
	return t.UTC().Format(time.RFC3339), nil
}
func derivePassword(password string, salt []byte, rounds int) []byte {
	mac := hmac.New(sha256.New, []byte(password))
	_, _ = mac.Write(salt)
	_, _ = mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	key := append([]byte(nil), u...)
	for i := 1; i < rounds; i++ {
		mac.Reset()
		_, _ = mac.Write(u)
		u = mac.Sum(nil)
		for j := range key {
			key[j] ^= u[j]
		}
	}
	return key
}
func hashGiftPassword(password string) (string, error) {
	if password == "" {
		return "", nil
	}
	if len(password) > 256 {
		return "", errors.New("passord for langt")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", passwordRounds, base64.RawURLEncoding.EncodeToString(salt), base64.RawURLEncoding.EncodeToString(derivePassword(password, salt, passwordRounds))), nil
}
func checkGiftPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	rounds, err := strconv.Atoi(parts[1])
	if err != nil || rounds < 10000 || rounds > 1000000 {
		return false
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(salt) != 16 {
		return false
	}
	want, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(want) != 32 || len(password) > 256 {
		return false
	}
	return subtle.ConstantTimeCompare(derivePassword(password, salt, rounds), want) == 1
}

type formGift struct {
	recipient, sender, message, privateNote, opensAt, password string
	after, before                                              bool
}

func (a *App) readGiftForm(w http.ResponseWriter, r *http.Request) (formGift, bool) {
	f := formGift{recipient: strings.TrimSpace(r.PostForm.Get("recipient")), sender: strings.TrimSpace(r.PostForm.Get("sender")), message: strings.TrimSpace(r.PostForm.Get("message")), privateNote: strings.TrimSpace(r.PostForm.Get("private_note")), password: r.PostForm.Get("password")}
	var err error
	f.opensAt, err = parseGiftDate(r.PostForm.Get("opens_at"), a.location())
	f.after = f.opensAt != "" && r.PostForm.Get("require_password_after") == "on"
	f.before = f.opensAt != "" && r.PostForm.Get("allow_password_before") == "on"
	if err != nil || f.recipient == "" || f.sender == "" || len(f.recipient) > 120 || len(f.sender) > 120 || len(f.message) > 4000 || len(f.privateNote) > 4000 || len(f.password) > 256 {
		http.Error(w, "Ugyldige gaveopplysninger", 400)
		return formGift{}, false
	}
	return f, true
}
func bit(v bool) int {
	if v {
		return 1
	}
	return 0
}
func (a *App) dashboard(w http.ResponseWriter, r *http.Request) {
	u, csrf, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	rows, err := a.db.Query("SELECT "+giftColumns+" FROM gifts WHERE owner_id=? ORDER BY rowid DESC", u.ID)
	if err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	defer rows.Close()
	p := Page{URL: a.baseURL, CSRF: csrf, User: u, DefaultGiftDate: defaultGiftDate(time.Now(), a.location())}
	for rows.Next() {
		g, err := a.scanGift(rows.Scan)
		if err != nil {
			http.Error(w, "Databasefeil", 500)
			return
		}
		p.Gifts = append(p.Gifts, g)
	}
	if rows.Err() != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	render(w, "admin.html", p)
}
func (a *App) createGift(w http.ResponseWriter, r *http.Request) {
	u, _, ok := a.requireUserPost(w, r)
	if !ok {
		return
	}
	f, ok := a.readGiftForm(w, r)
	if !ok {
		return
	}
	if f.password == "" {
		f.after = false
		f.before = false
	}
	hash, err := hashGiftPassword(f.password)
	if err != nil {
		http.Error(w, "Kunne ikke lagre passord", 500)
		return
	}
	encrypted, err := encryptGiftPassword(f.password)
	if err != nil {
		http.Error(w, "Kunne ikke kryptere gavepassord. Kontroller GIFT_PASSWORD_KEY.", 500)
		return
	}
	_, err = a.db.Exec(`INSERT INTO gifts (id,owner_id,recipient,sender,message,opens_at,private_note,password_hash,require_password_after,allow_password_before,password_ciphertext)
  VALUES(?,?,?,?,?,?,?,?,?,?,?)`, randomID(16), u.ID, f.recipient, f.sender, f.message, f.opensAt, f.privateNote, hash, bit(f.after), bit(f.before), encrypted)
	if err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
func (a *App) editPage(w http.ResponseWriter, r *http.Request) {
	u, csrf, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	g, err := a.getOwnedGift(r.PathValue("id"), u.ID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	render(w, "edit.html", Page{User: u, Gift: g, CSRF: csrf, DefaultGiftDate: defaultGiftDate(time.Now(), a.location())})
}
func (a *App) editGift(w http.ResponseWriter, r *http.Request) {
	u, _, ok := a.requireUserPost(w, r)
	if !ok {
		return
	}
	g, err := a.getOwnedGift(r.PathValue("id"), u.ID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f, ok := a.readGiftForm(w, r)
	if !ok {
		return
	}
	hash := g.PasswordHash
	encrypted := g.PasswordCiphertext
	if r.PostForm.Get("remove_password") == "on" {
		hash = ""
		encrypted = ""
	}
	if f.password != "" {
		hash, err = hashGiftPassword(f.password)
		if err != nil {
			http.Error(w, "Kunne ikke lagre passord", 500)
			return
		}
		encrypted, err = encryptGiftPassword(f.password)
		if err != nil {
			http.Error(w, "Kunne ikke kryptere gavepassord. Kontroller GIFT_PASSWORD_KEY.", 500)
			return
		}
	}
	if hash == "" {
		f.after = false
		f.before = false
	}
	_, err = a.db.Exec(`UPDATE gifts SET recipient=?,sender=?,message=?,opens_at=?,private_note=?,password_hash=?,require_password_after=?,allow_password_before=?,password_ciphertext=? WHERE id=? AND owner_id=?`, f.recipient, f.sender, f.message, f.opensAt, f.privateNote, hash, bit(f.after), bit(f.before), encrypted, g.ID, u.ID)
	if err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
func (a *App) previewGift(w http.ResponseWriter, r *http.Request) {
	u, _, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	g, err := a.getOwnedGift(r.PathValue("id"), u.ID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	locked := r.URL.Query().Get("mode") == "locked"
	// Locked preview includes no sensitive HTML fields or notes.
	if locked {
		g = Gift{ID: g.ID, HasOpensAt: g.HasOpensAt, OpensAtLabel: g.OpensAtLabel}
	}
	render(w, "gift.html", Page{Gift: g, Unlocked: !locked, Preview: true, PreviewLocked: locked})
}
func (a *App) setForcedOpen(w http.ResponseWriter, r *http.Request, open bool) {
	u, _, ok := a.requireUserPost(w, r)
	if !ok {
		return
	}
	res, err := a.db.Exec("UPDATE gifts SET forced_open=? WHERE id=? AND owner_id=?", bit(open), r.PathValue("id"), u.ID)
	if err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
func (a *App) openGift(w http.ResponseWriter, r *http.Request) { a.setForcedOpen(w, r, true) }
func (a *App) lockGift(w http.ResponseWriter, r *http.Request) { a.setForcedOpen(w, r, false) }
func (a *App) deleteGift(w http.ResponseWriter, r *http.Request) {
	u, _, ok := a.requireUserPost(w, r)
	if !ok {
		return
	}
	res, err := a.db.Exec("DELETE FROM gifts WHERE id=? AND owner_id=?", r.PathValue("id"), u.ID)
	if err != nil {
		http.Error(w, "Databasefeil", 500)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
