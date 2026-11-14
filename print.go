package main

import (
	"log"
	"net/http"
	"strings"
)

// Print selections always come from an authenticated owner's POST request.
// Never trust selected IDs from the browser, even for administrators.
const maxPrintGifts = 60

type printGift struct {
	Gift   Gift
	Number int
	Code   string
}

type printPage struct {
	User      User
	Pages     [][]printGift
	Items     []printGift
	Count     int
	ShowNames bool
	ShowNotes bool
}

func shortGiftCode(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func (a *App) printSelectedGifts(w http.ResponseWriter, r *http.Request) {
	// Bound the number of submitted form fields before parsing.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	u, _, ok := a.requireUserPost(w, r)
	if !ok {
		return
	}

	ids := r.PostForm["gift_ids"]
	if len(ids) == 0 || len(ids) > maxPrintGifts {
		http.Error(w, "Velg mellom 1 og 60 etiketter for utskrift.", http.StatusBadRequest)
		return
	}
	page := printPage{User: u, ShowNames: r.PostForm.Get("show_names") == "on", ShowNotes: r.PostForm.Get("show_notes") == "on"}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		// Duplicate IDs do not produce duplicate labels. Extremely long IDs
		// should never result in an unbounded database query.
		if id == "" || len(id) > 128 || strings.TrimSpace(id) != id {
			http.Error(w, "Ugyldig etikett.", http.StatusBadRequest)
			return
		}
		if seen[id] {
			continue
		}
		seen[id] = true

		// Deliberately use owner_id = current user even for administrators.
		gift, err := a.getOwnedGift(id, u.ID)
		if err != nil {
			// Never print a partial selection or reveal whether another
			// user's ID exists.
			http.NotFound(w, r)
			return
		}
		item := printGift{Gift: gift, Number: len(page.Items) + 1, Code: shortGiftCode(gift.ID)}
		page.Items = append(page.Items, item)
	}
	page.Count = len(page.Items)
	for i := 0; i < len(page.Items); i += 6 {
		end := i + 6
		if end > len(page.Items) {
			end = len(page.Items)
		}
		page.Pages = append(page.Pages, page.Items[i:end])
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, private")
	if err := templates.ExecuteTemplate(w, "print.html", page); err != nil {
		log.Printf("printing template: %v", err)
	}
}
