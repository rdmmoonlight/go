package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
)

const migrateSQL = `
CREATE SCHEMA IF NOT EXISTS auth;
CREATE TABLE IF NOT EXISTS auth.users (
	id            uuid        PRIMARY KEY,
	name          text        NOT NULL,
	email         text        NOT NULL,
	password_hash text,
	created_at    timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT users_email_lower CHECK (email = lower(email))
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_key ON auth.users (email);

-- Profil (Fase 7): padanan UserName, PhoneNumber, Bio, dan AvatarUrl pada ApplicationUser sumber.
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS user_name    text;
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS phone_number text;
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS bio          text;
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS avatar_url   text;
CREATE UNIQUE INDEX IF NOT EXISTS users_user_name_key ON auth.users (lower(user_name)) WHERE user_name IS NOT NULL;
`

const userColumns = `id, name, email, password_hash, user_name, phone_number, bio, avatar_url`

type rowScanner interface{ Scan(dest ...any) error }

func scanUser(row rowScanner) (*User, error) {
	u := &User{}
	var hash, userName, phone, bio, avatar sql.NullString
	if err := row.Scan(&u.ID, &u.Name, &u.Email, &hash, &userName, &phone, &bio, &avatar); err != nil {
		return nil, err
	}
	u.PasswordHash, u.UserName, u.PhoneNumber, u.Bio, u.AvatarURL = hash.String, userName.String, phone.String, bio.String, avatar.String
	return u, nil
}

// nullIfEmpty menyimpan string kosong sebagai NULL.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

type Postgres struct {
	db *sql.DB
}

// OpenPostgres membuka koneksi, menunggu database siap (Neon dapat
// membutuhkan beberapa detik saat cold start), lalu menjalankan migrasi.
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	if dsn == "" {
		return nil, errors.New("DATABASE_URL kosong")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("buka database: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)

	var lastErr error
	for attempt := 1; attempt <= 6; attempt++ {
		pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		lastErr = db.PingContext(pingCtx)
		cancel()
		if lastErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			_ = db.Close()
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt) * time.Second):
		}
	}
	if lastErr != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database tidak dapat dihubungi: %w", lastErr)
	}

	if _, err := db.ExecContext(ctx, migrateSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrasi skema auth: %w", err)
	}
	return &Postgres{db: db}, nil
}

func (p *Postgres) Close() error { return p.db.Close() }

// Ping dipakai untuk pemeriksaan kesiapan.
func (p *Postgres) Ping(ctx context.Context) error { return p.db.PingContext(ctx) }

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (p *Postgres) Create(ctx context.Context, name, email, passwordHash string) (*User, error) {
	u := &User{ID: newID(), Name: name, Email: normalize(email), PasswordHash: passwordHash}
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO auth.users (id, name, email, password_hash) VALUES ($1, $2, $3, $4)`,
		u.ID, u.Name, u.Email, u.PasswordHash)
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return nil, ErrEmailTaken
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (p *Postgres) FindByEmail(ctx context.Context, email string) (*User, error) {
	u, err := scanUser(p.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM auth.users WHERE email = $1`, normalize(email)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (p *Postgres) UpsertExternal(ctx context.Context, name, email string) (*User, error) {
	// ON CONFLICT DO UPDATE no-op agar RETURNING selalu mengembalikan baris.
	return scanUser(p.db.QueryRowContext(ctx,
		`INSERT INTO auth.users (id, name, email) VALUES ($1, $2, $3)
		 ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
		 RETURNING `+userColumns,
		newID(), name, normalize(email)))
}

// isInvalidUUID: id yang bukan UUID diperlakukan sebagai "tidak ditemukan", bukan galat server.
func isInvalidUUID(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "22P02"
}

func (p *Postgres) FindByID(ctx context.Context, id string) (*User, error) {
	u, err := scanUser(p.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM auth.users WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) || isInvalidUUID(err) {
		return nil, ErrNotFound
	}
	return u, err
}

func (p *Postgres) UpdateProfile(ctx context.Context, id string, upd ProfileUpdate) (*User, error) {
	// COALESCE($n, kolom): parameter NULL berarti kolom tidak diubah.
	var name, userName, avatar any
	if upd.Name != nil {
		name = *upd.Name
	}
	if upd.UserName != nil {
		userName = *upd.UserName
	}
	if upd.AvatarURL != nil {
		avatar = *upd.AvatarURL
	}
	u, err := scanUser(p.db.QueryRowContext(ctx,
		`UPDATE auth.users SET
			name         = COALESCE($2, name),
			user_name    = COALESCE($3, user_name),
			avatar_url   = COALESCE($4, avatar_url),
			phone_number = $5,
			bio          = $6
		 WHERE id = $1
		 RETURNING `+userColumns,
		id, name, userName, avatar, nullIfEmpty(upd.PhoneNumber), nullIfEmpty(upd.Bio)))
	var pqErr *pq.Error
	switch {
	case errors.Is(err, sql.ErrNoRows) || isInvalidUUID(err):
		return nil, ErrNotFound
	case errors.As(err, &pqErr) && pqErr.Code == "23505":
		return nil, ErrUserNameTaken
	}
	return u, err
}

func (p *Postgres) UpdatePasswordHash(ctx context.Context, id, passwordHash string) error {
	res, err := p.db.ExecContext(ctx, `UPDATE auth.users SET password_hash = $2 WHERE id = $1`, id, passwordHash)
	if isInvalidUUID(err) {
		return ErrNotFound
	}
	return affected(res, err)
}

func (p *Postgres) Delete(ctx context.Context, id string) error {
	res, err := p.db.ExecContext(ctx, `DELETE FROM auth.users WHERE id = $1`, id)
	if isInvalidUUID(err) {
		return ErrNotFound
	}
	return affected(res, err)
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
