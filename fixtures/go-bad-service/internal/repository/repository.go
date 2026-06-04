package repository

import (
	"context"
	"database/sql"
	"net/http"
)

func FindUser(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query("select id from users where name = '" + name + "'")
}

func SaveAndNotify(ctx context.Context, db *sql.DB, url string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	_, err = http.Get(url)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
