package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
	"github.com/pressly/goose/v3"
	"github.com/rs/zerolog/log"
)

type SortDirection string

const (
	DESC SortDirection = "DESC"
	ASC  SortDirection = "ASC"
)

func NewDB(ctx context.Context, dbURL string) (*pgxpool.Pool, error) {
	dbpool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to database")
	}

	if err = dbpool.Ping(ctx); err != nil {
		log.Err(err).
			Msg("Unable to ping database")
		return nil, err
	}

	return dbpool, nil
}

func GetDBURL() string {
	var (
		host     = os.Getenv("DB_HOST")
		port     = os.Getenv("DB_PORT")
		user     = os.Getenv("DB_USER")
		password = os.Getenv("DB_PASSWORD")
		dbName   = os.Getenv("DB_NAME")
		sslMode  = os.Getenv("DB_SSL_MODE")
	)
	dbAddr := fmt.Sprintf("%s:%s", host, port)
	if sslMode == "" {
		sslMode = "disable"
	}
	databaseURL := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s", user, password, dbAddr, dbName, sslMode)
	return databaseURL
}

func RunMigrations(ctx context.Context, dbURL string, migrationsPath string) error {
	migrationConn, err := sql.Open("pgx", dbURL)
	if err != nil {
		return err
	}
	defer migrationConn.Close()

	return goose.RunContext(ctx, "up", migrationConn, migrationsPath)
}
