package main

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log"
	"net/http"
	"time"
)

type Store struct {
	db *sql.DB
}

func (store Store) FindUser(ctx context.Context, id string) error {
	_, err := store.db.QueryContext(ctx, "SELECT id FROM users WHERE id = ?", id)
	if err != nil {
		return err
	}
	return nil
}

func userHandler(store Store, client *http.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := store.FindUser(ctx, r.PathValue("id")); err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test/status", nil)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			http.Error(w, "upstream read failed", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func main() {
	client := &http.Client{Timeout: 3 * time.Second}
	store := Store{}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/users/{id}", userHandler(store, client))

	server := &http.Server{
		Addr:              ":3000",
		Handler:           mux,
		ReadHeaderTimeout: time.Second,
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("server stopped: %v", err)
	}
}
