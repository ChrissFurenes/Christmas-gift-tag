package main

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
	_ "modernc.org/sqlite"
)

//go:embed templates/*.html
var templatesFS embed.FS

var templates = template.Must(template.ParseFS(templatesFS, "templates/*.html"))

type App struct {
	db                             *sql.DB
	baseURL, password, cookieToken string
}
type Gift struct {
	ID, Recipient, Sender, Message string
	OpensAt                        time.Time
	ForcedOpen                     bool
	Peeks                          int
}
type Page struct {
	Gift            Gift
	Gifts           []Gift
	URL, Error, Now string
	Unlocked        bool
	Admin           bool
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(b)
}
func main() {
	password := os.Getenv("ADMIN_PASSWORD")
	if len(password) < 12 {
		log.Fatal("ADMIN_PASSWORD must be set to at least 12 characters")
	}
	db, err := sql.Open("sqlite", env("DATABASE_PATH", "./gifts.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS gifts (id TEXT PRIMARY KEY, recipient TEXT NOT NULL, sender TEXT NOT NULL, message TEXT NOT NULL, opens_at TEXT NOT NULL, forced_open INTEGER NOT NULL DEFAULT 0, peeks INTEGER NOT NULL DEFAULT 0);`); err != nil {
		log.Fatal(err)
	}
	app := &App{db: db, baseURL: strings.TrimRight(env("BASE_URL", "http://localhost:8080"), "/"), password: password, cookieToken: randomID(32)}
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("GET /", app.home)
	mux.HandleFunc("GET /gift/{id}", app.showGift)
	mux.HandleFunc("GET /gift/{id}/qr.png", app.qr)
	mux.HandleFunc("GET /admin/login", app.loginPage)
	mux.HandleFunc("POST /admin/login", app.login)
	mux.HandleFunc("POST /admin/logout", app.logout)
	mux.HandleFunc("GET /admin", app.admin)
	mux.HandleFunc("POST /admin/gifts", app.createGift)
	mux.HandleFunc("POST /admin/gifts/{id}/open", app.openGift)
	mux.HandleFunc("POST /admin/gifts/{id}/delete", app.deleteGift)
	srv := &http.Server{Addr: env("LISTEN_ADDR", ":8080"), Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("listening on %s", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
func render(w http.ResponseWriter, name string, p Page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name, p); err != nil {
		log.Printf("template: %v", err)
	}
}
func (a *App) home(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
func (a *App) authorized(r *http.Request) bool {
	c, err := r.Cookie("gift_admin")
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(a.cookieToken)) == 1
}
func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !a.authorized(r) {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return false
	}
	return true
}
func (a *App) loginPage(w http.ResponseWriter, r *http.Request) { render(w, "login.html", Page{}) }
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.FormValue("password")), []byte(a.password)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		render(w, "login.html", Page{Error: "Feil passord"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "gift_admin", Value: a.cookieToken, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(a.baseURL, "https://"), SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if !a.authorized(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "gift_admin", Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}
func (a *App) getGift(id string) (Gift, error) {
	var g Gift
	var opensAt string
	var opened int
	err := a.db.QueryRow("SELECT id,recipient,sender,message,opens_at,forced_open,peeks FROM gifts WHERE id=?", id).Scan(&g.ID, &g.Recipient, &g.Sender, &g.Message, &opensAt, &opened, &g.Peeks)
	g.OpensAt, _ = time.Parse(time.RFC3339, opensAt)
	g.ForcedOpen = opened != 0
	return g, err
}
func (a *App) showGift(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	g, err := a.getGift(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	unlocked := g.ForcedOpen || !time.Now().Before(g.OpensAt)
	if !unlocked {
		_, _ = a.db.Exec("UPDATE gifts SET peeks=peeks+1 WHERE id=?", id)
	}
	w.Header().Set("Cache-Control", "no-store")
	render(w, "gift.html", Page{Gift: g, Unlocked: unlocked, Now: time.Now().Format("02.01.2006 15:04")})
}
func (a *App) qr(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.getGift(id); err != nil {
		http.NotFound(w, r)
		return
	}
	png, err := qrcode.Encode(a.baseURL+"/gift/"+url.PathEscape(id), qrcode.Medium, 512)
	if err != nil {
		http.Error(w, "QR generation failed", 500)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(png)
}
func (a *App) admin(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	rows, err := a.db.Query("SELECT id,recipient,sender,message,opens_at,forced_open,peeks FROM gifts ORDER BY opens_at DESC")
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	defer rows.Close()
	p := Page{Admin: true, URL: a.baseURL}
	for rows.Next() {
		var g Gift
		var at string
		var opened int
		if err := rows.Scan(&g.ID, &g.Recipient, &g.Sender, &g.Message, &at, &opened, &g.Peeks); err != nil {
			http.Error(w, "Database error", 500)
			return
		}
		g.OpensAt, _ = time.Parse(time.RFC3339, at)
		g.ForcedOpen = opened != 0
		p.Gifts = append(p.Gifts, g)
	}
	render(w, "admin.html", p)
}
func (a *App) createGift(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	recipient := strings.TrimSpace(r.FormValue("recipient"))
	sender := strings.TrimSpace(r.FormValue("sender"))
	msg := strings.TrimSpace(r.FormValue("message"))
	raw := r.FormValue("opens_at")
	local, err := time.LoadLocation(env("TIMEZONE", "Europe/Oslo"))
	if err != nil {
		http.Error(w, "Invalid timezone", 500)
		return
	}
	at, err := time.ParseInLocation("2006-01-02T15:04", raw, local)
	if err != nil || recipient == "" || sender == "" || msg == "" || len(recipient) > 120 || len(sender) > 120 || len(msg) > 4000 {
		http.Error(w, "Invalid gift data", 400)
		return
	}
	_, err = a.db.Exec("INSERT INTO gifts (id,recipient,sender,message,opens_at) VALUES (?,?,?,?,?)", randomID(16), recipient, sender, msg, at.UTC().Format(time.RFC3339))
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
func (a *App) openGift(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	_, err := a.db.Exec("UPDATE gifts SET forced_open=1 WHERE id=?", r.PathValue("id"))
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
func (a *App) deleteGift(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	_, err := a.db.Exec("DELETE FROM gifts WHERE id=?", r.PathValue("id"))
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
